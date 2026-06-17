//! Manage authentication, job signature verification, and the session
//! state machine. Does not manage jobs directly.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File, OpenOptions, remove_dir, remove_file};
use std::io::{self, Read as _, Seek as _, SeekFrom};
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use blake3::Hasher;
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use lru::LruCache;
use pwd::Passwd;
use rustix::io::close;
use rustix::process::{ioctl_tiocsctty, setsid};
use slog::{Logger, debug, error, info, o, warn};
use terminfo::Database as Terminfo;
use tokio::process::Command;
use tokio::spawn;
use tokio::sync::{Mutex, MutexGuard, mpsc, oneshot};
use tokio::task::spawn_blocking;
use x509_cert::Certificate;
use x509_cert::der::{DecodePem as _, Encode as _};

use sush_api::JobStartParams;
use sush_common::authn::{Credentials, Identity, Nonce};
use sush_common::interactive::WindowSize;
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobOutputHash, JobStartRequest, JobStatus, Session, SessionId, SignedJob, VerifiedJob,
};
use sush_common::keys::{KeyError, KeyId, Signature, SshPublicKey};

use crate::error::{ExecutionError, JobError};
use crate::interactive::SocketSender;
use crate::monitor::{ExecutionResult, JobEnded, JobMonitor, JobStarted, MonitorRequest};
use crate::pty::Pty;

/// Self-signed (root) X.509 certificates. Self-signed certificates may
/// not be imported (except in test code), and so must be included here.
pub const ROOT_CERTS: &[&[u8]] = &[
    // export PERMSLIP_URL="https://permslip.inickles.0xeng.dev"
    // export SUSH_PERMSLIP_KEY="UNTRUSTED Support Shell Prototype"
    include_bytes!("../certs/sandbox.pem"),
];

/// Maximum certificate chain length.
const MAX_CERT_CHAIN_LEN: usize = 10;

/// Maximum number of job signing certificates.
/// The ideal number of certs is 1, so this need not be large.
const MAX_CERTS: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// Maximum number of cached identities.
const MAX_CACHED_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Maximum number of active jobs in a session.
const MAX_ACTIVE_JOBS: usize = 1_000;

/// Maximum number of job status entries to hold as history.
const MAX_JOB_HISTORY: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

/// Maximum number of outstanding authentication nonces.
/// We do not really expect more than one simultaneous user,
/// nor do we expect hostile (DoS) requests, so a small value
/// here is adequate.
const MAX_OUTSTANDING_NONCES: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

type SessionGuard<'a> = MutexGuard<'a, Option<Session>>;

/// NB: All tables must have a fixed maximum size!
#[derive(Debug)]
#[allow(clippy::type_complexity)]
pub struct JobManager {
    log: Logger,
    nonces: Arc<Mutex<LruCache<Nonce, DateTime<Utc>>>>,
    identities: Arc<Mutex<LruCache<(KeyId, Nonce), (Identity, Credentials)>>>,
    certs: Arc<Mutex<LruCache<KeyId, Certificate>>>,
    session: Arc<Mutex<Option<Session>>>,
    active_jobs: Arc<Mutex<BTreeMap<JobId, JobStatus>>>,
    job_history: Arc<Mutex<LruCache<JobId, JobStatus>>>,
    output_dir: PathBuf,
    tx_monitor: mpsc::Sender<MonitorRequest>,
}

impl JobManager {
    pub async fn new(log: Logger, output_dir: &Path) -> Result<Self, JobError> {
        // Construct the job tables.
        let active_jobs = Arc::new(Mutex::new(BTreeMap::new()));
        let job_history = Arc::new(Mutex::new(LruCache::new(MAX_JOB_HISTORY)));

        // Start the monitor and listen for job-end events.
        let (tx_monitor, mut rx_monitor) =
            JobMonitor::start(log.new(o!("component" => "monitor")), output_dir.to_owned());
        spawn({
            let active_jobs = active_jobs.clone();
            let job_history = job_history.clone();
            let output_dir = output_dir.to_owned();
            let log = log.new(o!("component" => "monitor loop"));
            async move {
                while let Some(end) = rx_monitor.recv().await {
                    // A job has ended; asynchronously record that fact.
                    spawn({
                        let active_jobs = active_jobs.clone();
                        let job_history = job_history.clone();
                        let output_dir = output_dir.to_owned();
                        let log = log.clone();
                        async move {
                            // Compute output length and hashes before we
                            // take the job table locks.
                            let output = match spawn_blocking({
                                let output_dir = output_dir.to_owned();
                                let job_id = match &end {
                                    Ok(end) => end.job_id().to_owned(),
                                    Err(err) => err.job_id.to_owned(),
                                };
                                move || JobOutputState::new(&output_dir, &job_id)
                            })
                            .await
                            {
                                Ok(Ok(output)) => output,
                                Ok(Err(err)) => {
                                    error!(log, "failed to get job output state"; "error" => %err);
                                    JobOutputState::default()
                                }
                                Err(err) => {
                                    error!(log, "failed to spawn job output thread"; "error" => %err);
                                    JobOutputState::default()
                                }
                            };
                            match job_ended(
                                &mut *active_jobs.lock().await,
                                &mut *job_history.lock().await,
                                end,
                                output,
                            ) {
                                Ok(evicted) => {
                                    if let Some((evicted_id, _evicted_status)) = evicted {
                                        warn!(log, "evicted job record"; "job_id" => %evicted_id);
                                        spawn_blocking({
                                            let output_dir = output_dir.to_owned();
                                            move || remove_orphan_output(&output_dir, &evicted_id)
                                        });
                                    }
                                }
                                Err(err) => {
                                    error!(log, "failed to record job end"; "err" => %err);
                                }
                            }
                        }
                    });
                }
            }
        });

        // Create the new manager instance.
        let new = Self {
            log: log.new(o!("component" => "manager")),
            nonces: Arc::new(Mutex::new(LruCache::new(MAX_OUTSTANDING_NONCES))),
            identities: Arc::new(Mutex::new(LruCache::new(MAX_CACHED_IDENTITIES))),
            certs: Arc::new(Mutex::new(LruCache::new(MAX_CERTS))),
            session: Arc::new(Mutex::new(None)),
            active_jobs,
            job_history,
            output_dir: output_dir.to_owned(),
            tx_monitor,
        };

        // Import the root certificates.
        for root in ROOT_CERTS {
            new.import_cert_inner(Certificate::from_pem(root)?, true)
                .await?;
        }

        Ok(new)
    }

    // Certificate management.

    #[cfg(test)]
    async fn import_root(&self, root: Certificate) -> Result<KeyId, JobError> {
        self.import_cert_inner(root, true).await
    }

    pub async fn import_cert(
        &self,
        _authn: &Identity,
        cert: Certificate,
    ) -> Result<KeyId, JobError> {
        self.import_cert_inner(cert, false).await
    }

    async fn import_cert_inner(
        &self,
        cert: Certificate,
        root_allowed: bool,
    ) -> Result<KeyId, JobError> {
        // Verify the certificate signature.
        let signature = Signature::try_from(&cert)?;
        let tbs = cert.tbs_certificate.to_der()?;
        let subject = &cert.tbs_certificate.subject;
        let issuer = &cert.tbs_certificate.issuer;
        let root = subject == issuer;
        if root {
            if root_allowed {
                signature.verify_with_spki(&tbs, &cert.tbs_certificate.subject_public_key_info)?;
            } else {
                return Err(KeyError::SelfSigned.into());
            }
        } else {
            let issuer_key_id = KeyId::try_from(issuer)?;
            if let Some(issuer) = self.certs.lock().await.get(&issuer_key_id) {
                signature
                    .verify_with_spki(&tbs, &issuer.tbs_certificate.subject_public_key_info)?;
            } else {
                return Err(JobError::MissingCert(issuer_key_id));
            }
        }

        // Try to make room for the new cert, but do not evict roots.
        let key_id = KeyId::try_from(subject)?;
        let mut certs = self.certs.lock().await;
        if certs.len() >= MAX_CERTS.get() && !certs.contains(&key_id) {
            let mut i = 0;
            while let Some((lru_key_id, lru_cert)) =
                certs.peek_lru().map(|(k, v)| (k.to_owned(), v.to_owned()))
            {
                if lru_cert.tbs_certificate.subject == lru_cert.tbs_certificate.issuer {
                    certs.promote(&lru_key_id);
                    i += 1;
                } else {
                    certs.pop_lru();
                    break;
                }
                if i == MAX_CERTS.get() {
                    return Err(JobError::TooManyCerts(MAX_CERTS.get()));
                }
            }
        }

        // Import the certificate.
        certs.put(key_id.clone(), cert);
        info!(self.log, "imported certificate"; "key_id" => %key_id, "root" => root);
        Ok(key_id)
    }

    /// Return the cert chain for the given key in root-to-leaf order.
    pub async fn cert_chain(
        &self,
        _authn: &Identity,
        key_id: &KeyId,
    ) -> Result<Vec<Certificate>, JobError> {
        let mut certs = self.certs.lock().await;
        let mut chain = Vec::new();
        let mut key_id = key_id.to_owned();
        loop {
            if chain.len() >= MAX_CERT_CHAIN_LEN {
                return Err(JobError::CertChainTooLong);
            }
            let Some(cert) = certs.get(&key_id) else {
                return Err(JobError::MissingCert(key_id));
            };
            chain.push(cert.to_owned());
            if cert.tbs_certificate.subject == cert.tbs_certificate.issuer {
                break;
            }
            key_id = KeyId::try_from(&cert.tbs_certificate.issuer)?;
        }
        chain.reverse();
        Ok(chain)
    }

    // Identity management.

    /// Authenticate and cache authorization credentials.
    pub async fn iam(
        &self,
        authorization: Option<String>,
        public_key: Option<SshPublicKey>,
    ) -> Result<Identity, JobError> {
        // NB: Do not use the `?` operator in this function! We must ensure
        // that all authentication failures are logged and receive a proper
        // 401 Unauthorized response with a fresh nonce.
        macro_rules! unauthorized {
            ($error:expr) => {{
                warn!(self.log, "authentication failed"; "error" => %$error);
                let nonce = Nonce::generate();
                self.nonces.lock().await.put(nonce.clone(), Utc::now());
                return Err(JobError::unauthorized(nonce));
            }};
        }

        macro_rules! try_authn {
            // $expr -> Result
            ($expr:expr) => {
                match $expr {
                    Ok(value) => value,
                    Err(error) => unauthorized!(error),
                }
            };
            // $expr -> bool
            ($expr:expr, $error:expr) => {
                $expr || unauthorized!($error)
            };
        }

        // Parse the supplied credentials.
        let Some(authorization) = authorization else {
            unauthorized!("missing authorization")
        };
        let credentials: Credentials = try_authn!(authorization.parse());
        let Credentials {
            key_id,
            nonce,
            cnonce,
            signature,
        } = credentials.clone();

        // Check the identity cache.
        let now = Utc::now();
        {
            let mut identities = self.identities.lock().await;
            let cache_key = (key_id.clone(), nonce.clone());
            if let Some((identity, cached_credentials)) = identities.get(&cache_key).cloned() {
                if !identity.is_still_valid(&now) {
                    assert!(identities.pop(&cache_key).is_some());
                } else if cached_credentials.cnonce == cnonce
                    && cached_credentials.signature == signature
                {
                    assert_eq!(cached_credentials.nonce, nonce);
                    debug!(self.log, "credentials cache hit"; "key_id" => %key_id);
                    return Ok(identity);
                } else {
                    unauthorized!("invalid credentials for cached identity");
                }
            }
        }

        // Claim the nonce.
        let Some(generated) = self.nonces.lock().await.pop(&nonce) else {
            unauthorized!("nonce not found");
        };
        if !Nonce::is_still_valid(&generated, &now) {
            unauthorized!("nonce expired");
        };

        // Verify the supplied credentials.
        let Some(public_key) = public_key else {
            unauthorized!("missing public key");
        };
        if public_key.key_id().ok() != Some(key_id.clone()) {
            unauthorized!("invalid key ID");
        }
        let response = credentials.clone().into_challenge_response();
        let verified = try_authn!(response.verify_with_ssh_public_key(&public_key));
        let identity = try_authn!(Identity::new(public_key.to_owned(), verified, now));

        // Authenticated! Cache the identity & credentials.
        debug!(self.log, "authenticated credentials for identity"; "key_id" => %key_id);
        self.identities
            .lock()
            .await
            .put((key_id.to_owned(), nonce), (identity.clone(), credentials));
        Ok(identity)
    }

    pub async fn identities(&self, _authn: &Identity) -> Result<Vec<Identity>, JobError> {
        let now = Utc::now();
        Ok(self
            .identities
            .lock()
            .await
            .iter()
            .filter(|(_, (identity, _credentials))| identity.is_still_valid(&now))
            .map(|(_, (identity, _credentials))| identity.to_owned())
            .collect())
    }

    // Session management.

    pub async fn session(&self, _authn: &Identity) -> Result<Option<Session>, JobError> {
        todo!("get current session")
    }

    pub async fn session_start(&self, authn: &Identity) -> Result<Session, JobError> {
        let new_session_id = SessionId::new();
        let new_session = Session::new(new_session_id.clone());
        let mut session_guard = self.session.lock().await;
        if let Some(old_session) = session_guard.as_ref() {
            self.session_stop_inner(authn, old_session).await;
        }
        *session_guard = Some(new_session.clone());
        info!(self.log, "session started"; "session_id" => %new_session_id);
        Ok(new_session)
    }

    pub async fn session_stop(
        &self,
        authn: &Identity,
        session_id: &SessionId,
    ) -> Result<(), JobError> {
        let mut session_guard = self.session.lock().await;
        if let Some(session) = session_guard.as_ref()
            && session.session_id() == session_id
        {
            self.session_stop_inner(authn, session).await;
            *session_guard = None;
            Ok(())
        } else {
            Err(JobError::SessionNotFound(session_id.to_owned()))
        }
    }

    async fn session_stop_inner(&self, authn: &Identity, session: &Session) {
        let session_id = session.session_id();
        for job_id in {
            self.active_jobs
                .lock()
                .await
                .iter()
                .filter(|(_id, status)| status.session_id() == session_id)
                .map(|(id, _status)| id.to_owned())
                .collect::<Vec<JobId>>()
        } {
            if let Err(err) = self.monitor(MonitorRequest::Stop(job_id.to_owned())).await {
                error!(self.log, "runaway job"; "job_id" => %job_id, "session_id" => %session_id, "error" => %err);
            }
        }
        info!(self.log, "session stopped"; "session_id" => %session_id, "authn" => %authn.key_id);
    }

    // Job management.

    pub async fn job_history(
        &self,
        _authn: &Identity, // anyone may retrieve job history
        limit: u32,
        offset: u32,
    ) -> Result<Vec<JobStatus>, JobError> {
        let mut jobs = Vec::new();
        self.with_jobs(
            &mut self.session.lock().await,
            |active_jobs, job_history| {
                for (_id, status) in active_jobs.iter().chain(job_history.iter()) {
                    jobs.push(status.clone());
                }
                Ok(())
            },
        )
        .await?;
        let jobs = spawn_blocking(move || {
            jobs.sort_by_key(JobStatus::time_started);
            jobs
        })
        .await?;
        let iter = jobs.into_iter().rev().skip(offset as usize);
        let mut jobs: Vec<JobStatus> = if limit == 0 {
            iter.collect()
        } else {
            iter.take(limit as usize).collect()
        };
        spawn_blocking({
            let output_dir = self.output_dir.to_owned();
            move || {
                for job in jobs.iter_mut() {
                    if let JobStatus::Started {
                        job,
                        stdout_len,
                        stderr_len,
                        ..
                    } = job
                    {
                        *stdout_len = job_output_len(&output_dir, job.job_id(), Stdout)?;
                        *stderr_len = job_output_len(&output_dir, job.job_id(), Stderr)?;
                    }
                }
                Ok(jobs)
            }
        })
        .await?
    }

    pub async fn job_start(
        &self,
        authn: &Identity,
        job: SignedJob,
        params: JobStartParams,
    ) -> Result<Option<ExecutionResult>, JobError> {
        let wait = params.wait;
        let started = {
            let cert_key_id = job.key_id().to_owned();
            let chain = self.cert_chain(authn, &cert_key_id).await?;
            let job = if let Some(leaf) = chain.last() {
                job.verify_with_cert(leaf)?
            } else {
                return Err(JobError::MissingCert(cert_key_id));
            };

            let mut session_guard = self.session.lock().await;
            let Some(session) = session_guard.clone() else {
                return Err(JobError::NoSession);
            };

            let job_id = job.job_id().to_owned();
            self.with_jobs(&mut session_guard, |active_jobs, job_history| {
                if active_jobs.contains_key(&job_id) || job_history.contains(&job_id) {
                    return Err(JobError::InvalidJobId(job_id.to_owned()));
                }
                if active_jobs.len() >= MAX_ACTIVE_JOBS {
                    return Err(JobError::TooManyJobs(MAX_ACTIVE_JOBS));
                }
                Ok(())
            })
            .await?;

            if session.next_job_id() != job_id {
                return Err(JobError::InvalidJobId(job_id));
            }
            let started = job_start(
                &self.log,
                &self.output_dir,
                job.clone(),
                session.session_id(),
                &authn.key_id,
                params,
            )?;
            self.with_jobs(&mut session_guard, |active_jobs, _history| {
                active_jobs.insert(job_id, JobStatus::from(&started));
                Ok(())
            })
            .await?;

            session_guard
                .as_mut()
                .unwrap()
                .job_started(job.into_signed());
            started
        };

        let (tx, rx) = oneshot::channel();
        self.monitor(MonitorRequest::started(started, tx)).await?;
        if wait { Ok(Some(rx.await?)) } else { Ok(None) }
    }

    async fn check_job_owner(
        &self,
        session_guard: &mut SessionGuard<'_>,
        authn: &Identity,
        job_id: &JobId,
    ) -> Result<(), JobError> {
        let status = self.job_status_inner(session_guard, job_id).await?;
        if status.key_id() != &authn.key_id {
            Err(JobError::SessionWrongIdentity)
        } else {
            Ok(())
        }
    }

    pub async fn job_start_interactive_session(
        &self,
        authn: &Identity,
        job_id: &JobId,
    ) -> Result<SocketSender, JobError> {
        self.check_job_owner(&mut self.session.lock().await, authn, job_id)
            .await?;
        let (tx, rx) = oneshot::channel();
        self.monitor(MonitorRequest::interactive_session(job_id, tx))
            .await?;
        rx.await?
    }

    pub async fn job_status(
        &self,
        _authn: &Identity, // anyone may check job status
        job_id: &JobId,
    ) -> Result<JobStatus, JobError> {
        let mut status = self
            .job_status_inner(&mut self.session.lock().await, job_id)
            .await?;
        if let JobStatus::Started {
            stdout_len,
            stderr_len,
            ..
        } = &mut status
        {
            *stdout_len = job_output_len(&self.output_dir, job_id, Stdout)?;
            *stderr_len = job_output_len(&self.output_dir, job_id, Stderr)?;
        }
        Ok(status)
    }

    async fn job_status_inner(
        &self,
        session_guard: &mut SessionGuard<'_>,
        job_id: &JobId,
    ) -> Result<JobStatus, JobError> {
        self.with_jobs(session_guard, |active_jobs, job_history| {
            active_jobs
                .get(job_id)
                .cloned()
                .or_else(|| job_history.peek(job_id).cloned())
                .ok_or_else(|| JobError::JobNotFound(job_id.to_owned()))
        })
        .await
    }

    /// The `_session_guard` argument ensures that the session is locked
    /// before we take the job table locks.
    async fn with_jobs<T>(
        &self,
        _session_guard: &mut SessionGuard<'_>,
        f: impl FnOnce(
            &mut BTreeMap<JobId, JobStatus>,
            &mut LruCache<JobId, JobStatus>,
        ) -> Result<T, JobError>,
    ) -> Result<T, JobError> {
        f(
            &mut *self.active_jobs.lock().await,
            &mut *self.job_history.lock().await,
        )
    }

    pub async fn job_stop(
        &self,
        _authn: &Identity, // anyone may stop a job
        job_id: &JobId,
    ) -> Result<(), JobError> {
        let is_active = self
            .active_jobs
            .lock()
            .await
            .get(job_id)
            .is_some_and(JobStatus::is_active);
        if is_active {
            self.monitor(MonitorRequest::Stop(job_id.to_owned())).await
        } else {
            Err(JobError::JobNotFound(job_id.to_owned()))
        }
    }

    pub async fn job_output(
        &self,
        authn: &Identity,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        self.check_job_owner(&mut self.session.lock().await, authn, job_id)
            .await?;
        spawn_blocking({
            let output_dir = self.output_dir.to_owned();
            let job_id = job_id.to_owned();
            move || get_job_output(&output_dir, &job_id, stream, range)
        })
        .await?
    }

    /// Truncate output file and update corresponding job status length.
    /// Does *not* update the hash, as the mismatch indicates truncation
    /// has occurred.
    pub async fn job_output_delete(
        &self,
        authn: &Identity,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<u64, JobError> {
        // Check that truncation is allowed.
        {
            let mut session_guard = self.session.lock().await;
            self.check_job_owner(&mut session_guard, authn, job_id)
                .await?;
            if let JobStatus::Started { .. } =
                self.job_status_inner(&mut session_guard, job_id).await?
            {
                return Err(JobError::JobStillRunning(job_id.to_owned()));
            }
        }

        // Truncate.
        let n = spawn_blocking({
            let output_dir = self.output_dir.to_owned();
            let job_id = job_id.to_owned();
            move || delete_job_output(&output_dir, &job_id, stream, range)
        })
        .await??;

        // Update the jobs tables with the truncated status.
        self.with_jobs(
            &mut self.session.lock().await,
            |active_jobs, job_history| {
                if let Some(JobStatus::Started {
                    stdout_len,
                    stderr_len,
                    ..
                })
                | Some(JobStatus::Ended {
                    stdout_len,
                    stderr_len,
                    ..
                }) = active_jobs
                    .get_mut(job_id)
                    .or_else(|| job_history.peek_mut(job_id))
                {
                    match stream {
                        Stdout => *stdout_len = n,
                        Stderr => *stderr_len = n,
                    }
                }
                Ok(())
            },
        )
        .await?;
        Ok(n)
    }

    pub(crate) async fn job_end_status(
        &self,
        _authn: &Identity,
        end: JobEnded,
    ) -> Result<JobStatus, JobError> {
        let output_dir = self.output_dir.to_owned();
        let job_id = end.job_id().to_owned();
        Ok(end
            .into_status(spawn_blocking(move || JobOutputState::new(&output_dir, &job_id)).await??))
    }

    async fn monitor(&self, request: MonitorRequest) -> Result<(), JobError> {
        self.tx_monitor
            .send(request)
            .await
            .map_err(JobError::closed)
    }
}

#[derive(Debug, Default)]
pub(crate) struct JobOutputState {
    pub(crate) stdout_len: u64,
    pub(crate) stderr_len: u64,
    pub(crate) stdout_hash: JobOutputHash,
    pub(crate) stderr_hash: JobOutputHash,
}

impl JobOutputState {
    pub(crate) fn new(base_dir: &Path, job_id: &JobId) -> Result<Self, JobError> {
        Ok(Self {
            stdout_len: job_output_len(base_dir, job_id, Stdout)?,
            stderr_len: job_output_len(base_dir, job_id, Stderr)?,
            stdout_hash: job_output_hash(base_dir, job_id, Stdout)?,
            stderr_hash: job_output_hash(base_dir, job_id, Stderr)?,
        })
    }
}

fn job_output_dir(base_dir: &Path, job_id: &JobId) -> PathBuf {
    base_dir.join("jobs").join(job_id.to_string())
}

pub(crate) fn job_output_path(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
    job_output_dir(base_dir, job_id).join(stream.as_str())
}

fn job_output_len(
    base_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
) -> Result<u64, JobError> {
    let path = job_output_path(base_dir, job_id, stream);
    match path.metadata().map(|m| m.len()) {
        Ok(len) => Ok(len),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(JobError::file_io_for(&path)(err)),
    }
}

fn job_output_hash(
    base_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
) -> Result<JobOutputHash, JobError> {
    let mut hasher = Hasher::new();
    let path = job_output_path(base_dir, job_id, stream);
    match hasher.update_mmap_rayon(&path) {
        Ok(_) => (),
        Err(err) if err.kind() == io::ErrorKind::NotFound => (),
        Err(err) => return Err(JobError::file_io_for(&path)(err)),
    }
    Ok(hasher.finalize().into())
}

fn job_ended(
    active_jobs: &mut BTreeMap<JobId, JobStatus>,
    job_history: &mut LruCache<JobId, JobStatus>,
    result: ExecutionResult,
    output: JobOutputState,
) -> Result<Option<(JobId, JobStatus)>, JobError> {
    match result {
        Err(ExecutionError {
            job_id,
            time,
            error: _,
        }) => {
            if let JobStatus::Started {
                job,
                session_id,
                key_id,
                time_started,
                ..
            } = active_jobs
                .remove(&job_id)
                .ok_or_else(|| JobError::InvalidJobId(job_id.to_owned()))?
            {
                let status = JobStatus::Ended {
                    job,
                    session_id,
                    key_id,
                    time_started,
                    time_ended: time,
                    status: todo!("coerce error"),
                    stdout_len: output.stdout_len,
                    stderr_len: output.stderr_len,
                    stdout_hash: output.stdout_hash,
                    stderr_hash: output.stderr_hash,
                };
                Ok(job_history.push(job_id.to_owned(), status))
            } else {
                Err(JobError::InvalidJobId(job_id))
            }
        }
        Ok(ended) => {
            active_jobs.remove(ended.job_id());
            let job_id = ended.job_id().to_owned();
            let status = ended.into_status(output);
            Ok(job_history.push(job_id, status))
        }
    }
}

fn job_start(
    log: &Logger,
    output_dir: &Path,
    job: VerifiedJob,
    session_id: &SessionId,
    key_id: &KeyId,
    params: JobStartParams,
) -> Result<JobStarted, JobError> {
    // Set up the job.
    let JobStartParams {
        limits,
        term,
        rows,
        cols,
        wait: _,
    } = params;
    let JobStartRequest {
        job_id,
        command,
        interactive,
    } = job.clone().into_payload();
    if command.starts_with('-') {
        return Err(JobError::InvalidCommand(command));
    }

    // Set up output files.
    let job_dir = job_output_dir(output_dir, &job_id);
    DirBuilder::new()
        .recursive(true)
        .create(&job_dir)
        .map_err(|err| JobError::file_io(job_dir, err))?;
    let stdout_path = job_output_path(output_dir, &job_id, Stdout);
    let stderr_path = job_output_path(output_dir, &job_id, Stderr);
    let stdout_file =
        File::create_new(&stdout_path).map_err(|err| JobError::file_io(&stdout_path, err))?;
    let stderr_file =
        File::create_new(&stderr_path).map_err(|err| JobError::file_io(&stderr_path, err))?;

    // Set up the job child process.
    let mut child = Command::new("bash");
    child
        .arg("-c")
        .arg(&command)
        .env_clear()
        .env("SSH_CLIENT", "sush") // read bashrc
        .env("SUSH_JOB_ID", job_id.to_string())
        .env("SUSH_COMMAND", &command)
        .kill_on_drop(true);

    // Set basic user environment.
    if let Some(pwd) = Passwd::current_user() {
        child
            .current_dir(&pwd.dir)
            .env("HOME", &pwd.dir)
            .env("LOGNAME", &pwd.name)
            .env("USER", &pwd.name);
    }

    let pty = if interactive {
        // Create a pseudoterminal for interactive jobs and wire
        // the child up to it.
        let (pty, pts, pts_path) = Pty::open().map_err(|err| JobError::io("pty open", err))?;
        let pts_error = JobError::file_io_for(&pts_path);
        let pts_clone = || pts.try_clone().map_err(&pts_error);
        child
            .env("SUSH_TTY", &pts_path)
            .stdin(pts_clone()?)
            .stdout(pts_clone()?)
            .stderr(pts_clone()?);

        unsafe {
            let pty = pty.as_raw_fd();
            child.pre_exec(move || {
                close(pty); // not needed in the child
                setsid()?; // create new process session
                ioctl_tiocsctty(&pts)?; // set controlling terminal
                limits.apply() // set process limits
            });
        }

        // If it has a valid terminfo database, set `TERM` and the
        // initial pseudoterminal window size.
        if let Some(term) = term
            && Terminfo::from_name(&term).is_ok()
        {
            child.env("TERM", term);
            if let Some(rows) = rows
                && let Some(cols) = cols
            {
                pty.set_window_size(WindowSize { rows, cols })
                    .map_err(|err| JobError::io("pty window resize", err))?;
            }
        };

        Some(pty)
    } else {
        // For batch jobs, close stdin and send output directly to files.
        child
            .stdin(Stdio::null())
            .stdout(stdout_file)
            .stderr(stderr_file);
        unsafe {
            child.pre_exec(move || limits.apply());
        }
        None
    };

    // Go!
    let time_started = Utc::now();
    let child = child.spawn().map_err(|err| JobError::io("spawn", err))?;
    info!(log, "job started"; "job_id" => %job_id);
    Ok(JobStarted {
        job,
        session_id: session_id.to_owned(),
        key_id: key_id.to_owned(),
        time_started,
        child,
        interactive: pty,
    })
}

fn get_job_output(
    output_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
    range: Option<Range>,
) -> Result<Vec<u8>, JobError> {
    let len = job_output_len(output_dir, job_id, stream)?;
    let path = job_output_path(output_dir, job_id, stream);
    let io_error = JobError::file_io_for(&path);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(err) if len == 0 && err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(JobError::file_io_for(&path)(err)),
    };
    if let Some(Range { start, end }) = range {
        // HTTP Ranges include both their endpoints.
        let start = if let StartPosition::Index(start) = start
            && start < len
        {
            file.seek(SeekFrom::Start(start)).map_err(&io_error)?
        } else {
            return Err(JobError::InvalidRange(len));
        };
        let n = match end {
            EndPosition::Index(end) => end - start + 1,
            EndPosition::LastByte => len - start + 1,
        };
        if n > len.min(OUTPUT_THRESHOLD) {
            Err(JobError::InvalidRange(len))
        } else if n == 0 {
            Ok(vec![])
        } else {
            let mut buf = vec![0; n as usize];
            file.read_exact(&mut buf).map_err(&io_error)?;
            Ok(buf)
        }
    } else if len > OUTPUT_THRESHOLD {
        Err(JobError::OutputTooBig)
    } else {
        let mut buf = Vec::with_capacity(len as usize);
        file.read_to_end(&mut buf).map_err(&io_error)?;
        Ok(buf)
    }
}

fn delete_job_output(
    output_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
    range: Option<Range>,
) -> Result<u64, JobError> {
    let len = job_output_len(output_dir, job_id, stream)?;
    if let Some(Range {
        start: StartPosition::Index(n),
        end: EndPosition::LastByte,
    }) = range
        && n <= len
    {
        let path = job_output_path(output_dir, job_id, stream);
        let Ok(file) = OpenOptions::new().write(true).open(&path) else {
            return Ok(0);
        };
        file.set_len(n)
            .map_err(|err| JobError::file_io(&path, err))?;
        Ok(n)
    } else {
        Err(JobError::InvalidRange(len))
    }
}

fn remove_orphan_output(output_dir: &Path, job_id: &JobId) {
    let _ = remove_file(job_output_path(output_dir, job_id, Stdout));
    let _ = remove_file(job_output_path(output_dir, job_id, Stderr));
    let _ = remove_dir(job_output_dir(output_dir, job_id));
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use function_name::named;
    use pwd::Passwd;
    use rand_core::{OsRng, RngCore as _};
    use slog::{Drain as _, o};
    use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
    use tempfile::TempDir;
    use tokio::time::sleep;
    use x509_cert::name::Name;
    use x509_cert::time::Validity;

    use sush_common::authn::{Challenge, ChallengeResponse, Credentials};
    use sush_common::codephrases::generate_id;
    use sush_common::jobs::{JobLimits, ProcessError};
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};

    use super::*;

    // Signal numbers for killed jobs.
    const SIGKILL: i32 = 9;
    const SIGXCPU: i32 = 24;

    trait SignJobRequest {
        async fn sign_job_request<S: AsRef<str>>(
            &mut self,
            job_id: &JobId,
            command: S,
            interactive: bool,
        ) -> SignedJob;
    }

    impl SignJobRequest for EphemeralKey {
        async fn sign_job_request<S: AsRef<str>>(
            &mut self,
            job_id: &JobId,
            command: S,
            interactive: bool,
        ) -> SignedJob {
            self.sign(JobStartRequest::new(
                job_id.to_owned(),
                command,
                interactive,
            ))
            .await
            .unwrap()
        }
    }

    /// Inject some randomness into the subject DN to ensure unique key IDs.
    fn ephemeral_test_subject() -> Name {
        let mut buf = [0; 8];
        OsRng.fill_bytes(&mut buf);
        let id = generate_id();
        format!("CN=Ephemeral Test Key {id},O=Oxide Computer Company,C=US")
            .parse()
            .unwrap()
    }

    fn ephemeral_test_root() -> EphemeralKey {
        EphemeralKey::new_root(
            KeyType::P256,
            ephemeral_test_subject(),
            Validity::from_now(Duration::from_secs(60)).unwrap(),
        )
        .unwrap()
    }

    fn check_status_started(
        status: JobStatus,
        cert: &Certificate,
        expected_job_id: &JobId,
        expected_command: &str,
    ) {
        let JobStatus::Started {
            job, time_started, ..
        } = status
        else {
            panic!("expected job to be started");
        };
        assert_eq!(job.job_id, *expected_job_id);
        assert_eq!(job.command, expected_command);
        assert!(time_started < Utc::now());
        job.into_signed().verify_with_cert(cert).unwrap();
    }

    fn check_status_ended(
        status: JobStatus,
        expected_job_id: &JobId,
        expected_command: &str,
        expected_status: Result<i32, ProcessError>,
        expected_stdout_len: u64,
        expected_stderr_len: u64,
    ) {
        let JobStatus::Ended {
            job,
            time_started,
            time_ended,
            status,
            stdout_len,
            stderr_len,
            ..
        } = status
        else {
            panic!("expected job to be finished");
        };
        assert_eq!(job.job_id, *expected_job_id);
        assert_eq!(job.command, expected_command);
        assert!(time_started < time_ended);
        assert!(time_ended < Utc::now());
        assert_eq!(status, expected_status);
        assert_eq!(stdout_len, expected_stdout_len);
        assert_eq!(stderr_len, expected_stderr_len);
    }

    async fn manager_and_test_root(test_name: &'static str) -> (JobManager, EphemeralKey, TempDir) {
        let decorator = PlainSyncDecorator::new(TestStdoutWriter);
        let drain = FullFormat::new(decorator).build().fuse();
        let dir = TempDir::with_prefix("sush-").unwrap();
        let log = Logger::root(drain, o!("test" => test_name));
        let mgr = JobManager::new(log, dir.path()).await.unwrap();
        let root = ephemeral_test_root();
        let key_id = mgr.import_root(root.cert().to_owned()).await.unwrap();
        assert_eq!(&key_id, root.key_id());
        (mgr, root, dir)
    }

    async fn fake_identity(key: &mut EphemeralKey) -> Identity {
        let nonce = Nonce::generate();
        let challenge = Challenge::new(nonce.clone());
        let response = ChallengeResponse::new(challenge);
        let signed = key.sign(response).await.unwrap();
        let verified = signed.verify_with_cert(key.cert()).unwrap();
        Identity::new(key.ssh_public_key(), verified, Utc::now()).unwrap()
    }

    async fn job_start(
        authn: &Identity,
        mgr: &JobManager,
        job: SignedJob,
    ) -> Result<JobStatus, JobError> {
        let job_id = job.job_id().to_owned();
        Ok(mgr
            .job_start(authn, job, JobStartParams::wait())
            .await
            .expect("should be able to start job")
            .expect("should be waiting for job")
            .expect("job should end successfully")
            .into_status(JobOutputState::new(&mgr.output_dir, &job_id)?))
    }

    async fn job_error(authn: &Identity, mgr: &JobManager, job: SignedJob) -> JobError {
        mgr.job_start(authn, job, JobStartParams::wait())
            .await
            .expect_err("job should end with an error")
    }

    #[named]
    #[tokio::test]
    async fn jobs() {
        let (mgr, mut root, _dir) = manager_and_test_root(function_name!()).await;
        let authn = fake_identity(&mut root).await;
        let session = mgr.session_start(&authn).await.unwrap();
        let session_id = session.session_id();
        let job_id = session_id.first_job_id();
        let job = root.sign_job_request(&job_id, "true", false).await;
        assert!(matches!(
            mgr.job_status(&authn, &job_id).await.unwrap_err(),
            JobError::JobNotFound(id) if id == job_id
        ));
        let status = job_start(&authn, &mgr, job.clone()).await.unwrap();
        check_status_ended(status, &job_id, "true", Ok(0), 0, 0);

        assert!(
            matches!(
                job_error(&authn, &mgr, job.clone()).await,
                JobError::InvalidJobId(ref id) if *id == job_id
            ),
            "should not be allowed to reuse a job ID"
        );

        let job_id = session_id.next_job_id(&job);
        let job = root.sign_job_request(&job_id, "false", false).await;
        let status = job_start(&authn, &mgr, job.clone()).await.unwrap();
        check_status_ended(status, &job_id, "false", Ok(1), 0, 0);

        let job_id = session_id.next_job_id(&job);
        let job_id_string = job_id.to_string();
        let job_id_bytes = job_id_string.as_bytes();
        let job = root
            .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", false)
            .await;
        let status = job_start(&authn, &mgr, job.clone()).await.unwrap();
        check_status_ended(
            status,
            &job_id,
            "echo -n $SUSH_JOB_ID",
            Ok(0),
            job_id_bytes.len() as u64,
            0,
        );
        assert_eq!(
            mgr.job_output(&authn, &job_id, Stdout, None).await.unwrap(),
            job_id_bytes
        );
        assert!(
            mgr.job_output(&authn, &job_id, Stderr, None)
                .await
                .unwrap()
                .is_empty()
        );

        let home = Passwd::current_user().unwrap().dir;
        let output = format!("{home}\n");
        let job_id = session_id.next_job_id(&job);
        let job = root.sign_job_request(&job_id, "pwd", false).await;
        let status = job_start(&authn, &mgr, job.clone()).await.unwrap();
        check_status_ended(status, &job_id, "pwd", Ok(0), output.len() as u64, 0);
        assert_eq!(
            mgr.job_output(&authn, &job_id, Stdout, None).await.unwrap(),
            output.as_bytes(),
        );
        assert!(
            mgr.job_output(&authn, &job_id, Stderr, None)
                .await
                .unwrap()
                .is_empty()
        );

        let job_id = session_id.next_job_id(&job);
        let job = root.sign_job_request(&job_id, "foo", false).await;
        let new_session = mgr.session_start(&authn).await.unwrap();
        assert_ne!(new_session.session_id(), session_id);
        assert!(
            matches!(
                job_error(&authn, &mgr, job).await,
                JobError::InvalidJobId(ref id) if *id == job_id
            ),
            "session has ended, should not be able to start job"
        );

        let job_id = session_id.first_job_id();
        let job = root.sign_job_request(&job_id, "bar", false).await;
        assert!(
            matches!(
                job_error(&authn, &mgr, job.clone()).await,
                JobError::InvalidJobId(ref id) if *id == job_id
            ),
            "should not be able to use old session job ID in new session"
        );

        let job_id = new_session.session_id().first_job_id();
        let job = root.sign_job_request(&job_id, "true", false).await;
        let status = job_start(&authn, &mgr, job).await.unwrap();
        check_status_ended(status, &job_id, "true", Ok(0), 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn abort() {
        let (mgr, mut root, _dir) = manager_and_test_root(function_name!()).await;
        let authn = fake_identity(&mut root).await;
        let session = mgr.session_start(&authn).await.unwrap();
        let session_id = session.session_id();
        let job_id = session_id.first_job_id();

        // Start a (potentially) long-running job.
        let command = "sleep 10";
        let job = root.sign_job_request(&job_id, command, false).await;
        assert!(
            mgr.job_start(&authn, job, JobStartParams::default())
                .await
                .expect("should be able to start job")
                .is_none(),
            "should not be waiting for job"
        );

        // Check that the job is alive.
        let status = mgr.job_status(&authn, &job_id).await.unwrap();
        check_status_started(status, root.cert(), &job_id, command);

        // Kill the job and wait for it to die.
        mgr.job_stop(&authn, &job_id).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        // Check that it's dead and that it didn't live for long.
        let status = mgr.job_status(&authn, &job_id).await.unwrap();
        assert!(status.time_elapsed().to_std().unwrap() < Duration::from_secs(1));
        check_status_ended(
            status,
            &job_id,
            command,
            Err(ProcessError::Killed(SIGKILL)),
            0,
            0,
        );
    }

    #[named]
    #[tokio::test]
    async fn cert_chain() {
        let validity = Validity::from_now(Duration::from_secs(60)).unwrap();
        let mut root =
            EphemeralKey::new_root(KeyType::P256, ephemeral_test_subject(), validity).unwrap();
        let root_key_id = root.key_id().to_owned();
        let root_cert = root.cert().to_owned();
        let issuer = root.subject();
        let signature_algorithm = root.signature_algorithm();
        let subject = ephemeral_test_subject();
        let mut child = EphemeralKey::new_child(
            KeyType::Ed25519,
            subject,
            issuer,
            validity,
            &mut root,
            signature_algorithm,
        )
        .await
        .unwrap();
        assert_ne!(child.key_id(), &root_key_id);
        let child_key_id = child.key_id().to_owned();

        let authn = fake_identity(&mut root).await;
        let dir = TempDir::with_prefix("sush-").unwrap();
        let log = Logger::root(slog::Discard, slog::o!("test" => function_name!()));
        let mgr = JobManager::new(log, dir.path()).await.unwrap();
        assert!(
            matches!(
                mgr.import_cert(&authn, root_cert.clone())
                    .await
                    .unwrap_err(),
                JobError::Key(KeyError::SelfSigned),
            ),
            "should not accept root cert without override"
        );
        assert!(
            matches!(
                mgr.import_cert(&authn, child.cert().clone()).await.unwrap_err(),
                JobError::MissingCert(key_id) if key_id == root_key_id,
            ),
            "should not accept child cert without root"
        );
        assert_eq!(
            mgr.import_root(root_cert.clone()).await.unwrap(),
            root_key_id
        );
        assert_eq!(
            mgr.cert_chain(&authn, &root_key_id).await.unwrap(),
            vec![root_cert.clone()]
        );
        assert_eq!(
            mgr.import_cert(&authn, child.cert().clone()).await.unwrap(),
            child_key_id
        );
        assert_eq!(
            mgr.cert_chain(&authn, &child_key_id).await.unwrap(),
            vec![root_cert.clone(), child.cert().clone()]
        );

        let session = mgr.session_start(&authn).await.unwrap();
        let session_id = session.session_id();
        let job_id = session_id.first_job_id();
        let job = child.sign_job_request(&job_id, "true", false).await;
        let status = job_start(&authn, &mgr, job).await.unwrap();
        check_status_ended(status, &job_id, "true", Ok(0), 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn too_much_cpu() {
        let (mgr, mut root, _dir) = manager_and_test_root(function_name!()).await;
        let authn = fake_identity(&mut root).await;
        let session = mgr.session_start(&authn).await.unwrap();
        let session_id = session.session_id();
        let job_id = session_id.first_job_id();
        let command = "openssl speed sha1";
        let job = root.sign_job_request(&job_id, command, false).await;
        let end = mgr
            .job_start(
                &authn,
                job.clone(),
                JobStartParams {
                    limits: JobLimits {
                        max_cpu: 1,
                        max_fsize: 100,
                        ..Default::default()
                    },
                    wait: true,
                    ..Default::default()
                },
            )
            .await
            .expect("should be able to start job")
            .expect("should be waiting for job")
            .expect("job should end successfully");
        let status = end.into_status(JobOutputState::new(&mgr.output_dir, job.job_id()).unwrap());
        assert!(status.time_elapsed().to_std().unwrap() < Duration::from_secs(2));

        // The output of `openssl speed` changed between v3.0 and v3.5.
        let stderr = mgr.job_output(&authn, &job_id, Stderr, None).await.unwrap();
        let stderr = String::from_utf8_lossy(&stderr);
        match status {
            JobStatus::Ended { stderr_len: 37, .. } => {
                check_status_ended(
                    status,
                    &job_id,
                    command,
                    Err(ProcessError::Killed(SIGXCPU)),
                    0,
                    37,
                );
                assert_eq!(stderr, "Doing sha1 for 3s on 16 size blocks: ");
            }
            JobStatus::Ended { stderr_len: 41, .. } => {
                check_status_ended(
                    status,
                    &job_id,
                    command,
                    Err(ProcessError::Killed(SIGXCPU)),
                    0,
                    41,
                );
                assert_eq!(stderr, "Doing sha1 ops for 3s on 16 size blocks: ");
            }
            _ => todo!("what does `{command}` produce on your system?"),
        }
    }

    #[named]
    #[tokio::test]
    async fn output_ranges() {
        let (mgr, mut root, _dir) = manager_and_test_root(function_name!()).await;
        let authn = fake_identity(&mut root).await;
        let session = mgr.session_start(&authn).await.unwrap();
        let session_id = session.session_id();
        let job_id = session_id.first_job_id();

        // Read some random bytes.
        let n = 1000;
        let command = &format!("head -c {n} /dev/urandom");
        let job = root.sign_job_request(&job_id, command, false).await;
        let status = job_start(&authn, &mgr, job).await.unwrap();
        check_status_ended(status, &job_id, command, Ok(0), n, 0);

        // No range, i.e., full output.
        let r = mgr.job_output(&authn, &job_id, Stdout, None).await.unwrap();

        // One byte too big.
        assert!(matches!(
            mgr.job_output(
                &authn,
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n),
                }),
            )
            .await
            .unwrap_err(),
            JobError::InvalidRange(m) if m == n,
        ));

        // Whole range.
        assert_eq!(
            mgr.job_output(
                &authn,
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n - 1),
                }),
            )
            .await
            .unwrap(),
            r
        );

        // Two half-ranges.
        let mut o = mgr
            .job_output(
                &authn,
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n / 2 - 1),
                }),
            )
            .await
            .unwrap();
        o.extend(
            mgr.job_output(
                &authn,
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(n / 2),
                    end: EndPosition::Index(n - 1),
                }),
            )
            .await
            .unwrap(),
        );
        assert_eq!(o, r);

        // Various ranges, from one byte to half.
        for l in 1..n / 2 {
            let mut i = 0;
            let mut o = vec![];
            while i + l < n {
                o.extend(
                    mgr.job_output(
                        &authn,
                        &job_id,
                        Stdout,
                        Some(Range {
                            start: StartPosition::Index(i),
                            end: EndPosition::Index(i + l - 1),
                        }),
                    )
                    .await
                    .unwrap(),
                );
                i += l;
            }
            o.extend(
                mgr.job_output(
                    &authn,
                    &job_id,
                    Stdout,
                    Some(Range {
                        start: StartPosition::Index(i),
                        end: EndPosition::Index(n - 1),
                    }),
                )
                .await
                .unwrap(),
            );
            assert_eq!(o, r);
        }
    }

    #[named]
    #[tokio::test]
    async fn iam() {
        let (mgr, mut root, _dir) = manager_and_test_root(function_name!()).await;
        let JobError::Unauthorized(nonce) = mgr.iam(None, None).await.unwrap_err() else {
            panic!("should not be authorized yet");
        };

        // Construct credentials.
        let challenge = Challenge::new(nonce.clone());
        let response = ChallengeResponse::new(challenge);
        let signed = root.sign(response).await.unwrap();
        let verified = signed.verify_with_cert(root.cert()).unwrap();
        let mut credentials = Credentials::new(verified);
        let public_key = root.ssh_public_key();
        let key_id = public_key.key_id().unwrap();
        credentials.key_id = key_id.clone(); // override cert key ID

        // Register our identity.
        let identity = mgr
            .iam(Some(credentials.to_string()), Some(public_key.clone()))
            .await
            .unwrap();
        let Identity {
            key_id: iam_key_id,
            public_key: iam_public_key,
            nonce: iam_nonce,
            time_authenticated: iam_authenticated,
            time_revoked: iam_revoked,
        } = identity.clone();
        assert_eq!(iam_key_id, key_id);
        assert_eq!(iam_public_key, public_key);
        assert_eq!(iam_nonce, credentials.nonce);
        assert!(iam_authenticated <= Utc::now());
        assert!(iam_revoked.is_none());

        // Authenticate successfully.
        assert_eq!(
            mgr.iam(Some(credentials.to_string()), None)
                .await
                .unwrap()
                .key_id,
            key_id,
        );
    }
}
