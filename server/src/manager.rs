//! Manage a set of jobs.
//!
//! Jobs are spawned onto new tokio tasks and passed to the monitor to wait
//! for completion. Standard output and standard error are saved in files.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, MutexGuard};

use blake3::Hasher;
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use lru::LruCache;
use pwd::Passwd;
use rustix::io::close;
use rustix::process::{ioctl_tiocsctty, setsid};
use slog::{Logger, debug, error, info, o};
use terminfo::Database as Terminfo;
use tokio::process::Command;
use tokio::spawn;
use tokio::sync::{mpsc, oneshot};
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
use crate::monitor::{ExecutionResult, JobMonitor, JobStarted, MonitorRequest};
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

/// Maximum number of identities.
const MAX_IDENTITIES: NonZeroUsize = NonZeroUsize::new(1_000).unwrap();

/// Maximum number of job entries to hold in memory.
const MAX_JOBS: NonZeroUsize = NonZeroUsize::new(10_000).unwrap();

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
pub struct JobManager {
    log: Logger,
    nonces: Arc<Mutex<LruCache<Nonce, DateTime<Utc>>>>,
    identities: Arc<Mutex<LruCache<KeyId, (Identity, Credentials)>>>,
    certs: Arc<Mutex<LruCache<KeyId, Certificate>>>,
    session: Arc<Mutex<Option<Session>>>,
    jobs: Arc<Mutex<LruCache<JobId, JobStatus>>>,
    output_dir: PathBuf,
    tx_monitor: mpsc::Sender<MonitorRequest>,
}

impl JobManager {
    pub async fn new(log: Logger, output_dir: &Path) -> Result<Self, JobError> {
        // The jobs table is shared between the manager and the monitor.
        let jobs = Arc::new(Mutex::new(LruCache::new(MAX_JOBS)));

        // Start the monitor and listen for job-end events.
        let (tx_monitor, mut rx_monitor) =
            JobMonitor::start(log.new(o!("component" => "monitor")), output_dir.to_owned());
        spawn({
            let jobs = jobs.clone();
            let output_dir = output_dir.to_owned();
            let log = log.new(o!("component" => "monitor loop"));
            async move {
                while let Some(end) = rx_monitor.recv().await {
                    if let Err(err) = job_ended(&mut jobs.lock().unwrap(), &output_dir, end) {
                        error!(log, "failed to record job end"; "err" => %err);
                    }
                }
                Ok::<_, JobError>(())
            }
        });

        // Create the new manager instance.
        let new = Self {
            log: log.new(o!("component" => "manager")),
            nonces: Arc::new(Mutex::new(LruCache::new(MAX_OUTSTANDING_NONCES))),
            identities: Arc::new(Mutex::new(LruCache::new(MAX_IDENTITIES))),
            certs: Arc::new(Mutex::new(LruCache::new(MAX_CERTS))),
            session: Arc::new(Mutex::new(None)),
            jobs,
            output_dir: output_dir.to_owned(),
            tx_monitor,
        };

        // Import the root certificates.
        for root in ROOT_CERTS {
            new.import_cert_inner(Certificate::from_pem(root)?, true)?;
        }

        Ok(new)
    }

    // Certificate management.

    /// Tests must import a root to use ephemeral signers,
    /// but this is not allowed in production.
    #[cfg(feature = "import_root_for_test_only")] // disabled by default
    pub fn import_root(&self, root: Certificate) -> Result<KeyId, JobError> {
        self.import_cert_inner(root, true)
    }

    pub fn import_cert(&self, _authn: &Identity, cert: Certificate) -> Result<KeyId, JobError> {
        self.import_cert_inner(cert, false)
    }

    fn import_cert_inner(&self, cert: Certificate, root_allowed: bool) -> Result<KeyId, JobError> {
        let mut certs = self.certs.lock().unwrap();

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
            if let Some(issuer) = certs.get(&issuer_key_id) {
                signature
                    .verify_with_spki(&tbs, &issuer.tbs_certificate.subject_public_key_info)?;
            } else {
                return Err(JobError::MissingCert(issuer_key_id));
            }
        }

        // Import the certificate.
        let key_id = KeyId::try_from(subject)?;
        certs.put(key_id.clone(), cert);
        info!(self.log, "imported certificate"; "key_id" => %key_id, "root" => root);
        Ok(key_id)
    }

    /// Return the cert chain for the given key in root-to-leaf order.
    pub fn cert_chain(
        &self,
        _authn: &Identity,
        key_id: &KeyId,
    ) -> Result<Vec<Certificate>, JobError> {
        let mut certs = self.certs.lock().unwrap();
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
                error!(self.log, "authentication failed"; "error" => %$error);
                let nonce = Nonce::generate();
                self.nonces.lock().unwrap().put(nonce.clone(), Utc::now());
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

        // Check the cache.
        let now = Utc::now();
        if let Some((identity, cached_credentials)) =
            self.identities.lock().unwrap().get(&key_id).cloned()
            && try_authn!(identity.time_revoked.is_none(), "identity revoked")
            && identity.is_still_valid(&now)
            && identity.nonce == nonce
            && cached_credentials.nonce == nonce
            && cached_credentials.cnonce == cnonce
            && cached_credentials.signature == signature
        {
            debug!(self.log, "credentials cache hit"; "key_id" => %key_id);
            return Ok(identity.to_owned());
        }

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

        // Claim the nonce.
        let Some(generated) = self.nonces.lock().unwrap().pop(&nonce) else {
            unauthorized!("nonce not found");
        };
        if !Nonce::is_still_valid(&generated, &now) {
            unauthorized!("nonce expired");
        };

        // Authenticated! Cache the credentials.
        debug!(self.log, "authenticated credentials for new identity"; "key_id" => %key_id);
        self.identities
            .lock()
            .unwrap()
            .put(key_id.to_owned(), (identity.clone(), credentials));
        Ok(identity)
    }

    pub async fn identities(&self, _authn: &Identity) -> Result<Vec<Identity>, JobError> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .map(|(_id, (identity, _credentials))| identity.to_owned())
            .collect())
    }

    pub async fn revoke_identity(&self, _authn: &Identity, key_id: KeyId) -> Result<(), JobError> {
        if let Some((identity, _credentials)) = self.identities.lock().unwrap().get_mut(&key_id) {
            identity.time_revoked = Some(Utc::now());
        } else {
            return Err(JobError::PublicKeyNotFound(key_id));
        }
        // for job_id in todo!("get interactive sessions") {
        //     self.monitor(MonitorRequest::Stop(job_id)).await?;
        // }
        Ok(())
    }

    // Session management.

    pub async fn session_start(&self, authn: &Identity) -> Result<SessionId, JobError> {
        let new_session_id = SessionId::new();
        let new_session = Session::new(new_session_id.clone(), Some(authn.key_id.clone()));

        // Don't hold the session lock while we stop any old session.
        if let Some(old_session) = { self.session.lock().unwrap().replace(new_session) } {
            self.session_stop_inner(old_session).await?;
        }

        info!(self.log, "session started"; "session_id" => %new_session_id);
        Ok(new_session_id)
    }

    pub async fn session_stop(
        &self,
        _authn: &Identity,
        session_id: &SessionId,
    ) -> Result<(), JobError> {
        // Anyone is allowed to stop a session.
        let session = {
            let mut session_guard = self.session.lock().unwrap();
            if session_guard.as_ref().map(|s| s.session_id()) == Some(session_id) {
                session_guard.take()
            } else {
                None
            }
        };
        if let Some(session) = session {
            self.session_stop_inner(session).await
        } else {
            Err(JobError::SessionNotFound(session_id.to_owned()))
        }
    }

    async fn session_stop_inner(&self, session: Session) -> Result<(), JobError> {
        // TODO: send session stop event
        info!(self.log, "session stopped"; "session_id" => %session.session_id());
        Ok(())
    }

    // Job management.

    pub async fn job_history(&self, _authn: &Identity) -> Result<Vec<JobStatus>, JobError> {
        Ok(self
            .jobs
            .lock()
            .unwrap()
            .iter()
            .map(|(_id, status)| status.to_owned())
            .collect())
    }

    pub async fn job_start(
        &self,
        authn: &Identity,
        job: SignedJob,
        params: JobStartParams,
    ) -> Result<Option<ExecutionResult>, JobError> {
        let wait = params.wait;
        let started = {
            let mut session_guard = self.session.lock().unwrap();
            let Some(session) = session_guard.clone() else {
                return Err(JobError::NoSession);
            };

            let job_id = job.job_id().to_owned();
            self.with_jobs(&mut session_guard, |jobs| {
                if jobs.contains(&job_id) {
                    return Err(JobError::InvalidJobId(job_id.to_owned()));
                }
                Ok(())
            })?;

            let cert_key_id = job.key_id().to_owned();
            let cert = self
                .certs
                .lock()
                .unwrap()
                .get(&cert_key_id)
                .cloned()
                .ok_or_else(|| JobError::MissingCert(cert_key_id))?;

            let job = job.verify_with_cert(&cert)?;
            if session.key_id() != Some(&authn.key_id) {
                return Err(JobError::SessionWrongIdentity);
            }
            if session.next_job_id() != job_id {
                return Err(JobError::InvalidJobId(job_id));
            }
            let started = job_start(
                &self.log,
                &self.output_dir,
                job.clone(),
                session.session_id(),
                params,
            )?;
            self.with_jobs(&mut session_guard, |jobs| {
                jobs.put(job_id, JobStatus::from(&started));
                Ok(())
            })?;

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

    /// For jobs in the current session, only the owner is allowed access.
    /// For jobs from previous sessions, anyone may access them; otherwise
    /// they would be orphaned.
    fn check_job_owner(&self, authn: &Identity, job_id: &JobId) -> Result<(), JobError> {
        let mut session_guard = self.session.lock().unwrap();
        let Some(job_session_id) = self
            .job_status_inner(&mut session_guard, job_id)?
            .session_id()
        else {
            return Err(JobError::JobNotFound(job_id.to_owned()));
        };
        if let Some(session) = session_guard.as_ref()
            && job_session_id == *session.session_id()
            && session.key_id() != Some(&authn.key_id)
        {
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
        self.check_job_owner(authn, job_id)?;
        let (tx, rx) = oneshot::channel();
        self.monitor(MonitorRequest::interactive_session(job_id, tx))
            .await?;
        rx.await?
    }

    pub fn job_status(&self, _authn: &Identity, job_id: &JobId) -> Result<JobStatus, JobError> {
        // Anyone is allowed to read job status.
        self.job_status_inner(&mut self.session.lock().unwrap(), job_id)
    }

    fn job_status_inner(
        &self,
        session_guard: &mut SessionGuard,
        job_id: &JobId,
    ) -> Result<JobStatus, JobError> {
        self.with_jobs(session_guard, |jobs| {
            Ok(jobs
                .get(job_id)
                .cloned()
                .unwrap_or_else(|| JobStatus::Unknown {
                    job_id: job_id.to_owned(),
                }))
        })
    }

    /// The `_session_guard` argument ensures that the session is locked
    /// before we take the job table lock.
    fn with_jobs<T>(
        &self,
        _session_guard: &mut SessionGuard,
        f: impl FnOnce(&mut LruCache<JobId, JobStatus>) -> Result<T, JobError>,
    ) -> Result<T, JobError> {
        f(&mut self.jobs.lock().unwrap())
    }

    pub async fn job_stop(&self, authn: &Identity, job_id: &JobId) -> Result<(), JobError> {
        self.check_job_owner(authn, job_id)?;
        self.monitor(MonitorRequest::Stop(job_id.to_owned())).await
    }

    pub async fn job_output(
        &self,
        authn: &Identity,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        self.check_job_owner(authn, job_id)?;
        get_job_output(&self.output_dir, job_id, stream, range)
    }

    pub async fn job_output_delete(
        &self,
        authn: &Identity,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<u64, JobError> {
        self.check_job_owner(authn, job_id)?;
        delete_job_output(&self.output_dir, job_id, stream, range)
    }

    async fn monitor(&self, request: MonitorRequest) -> Result<(), JobError> {
        self.tx_monitor
            .send(request)
            .await
            .map_err(JobError::closed)
    }
}

pub fn job_output_dir(base_dir: &Path, job_id: &JobId) -> PathBuf {
    base_dir.join("jobs").join(job_id.to_string())
}

pub fn job_output_path(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
    job_output_dir(base_dir, job_id).join(stream.as_str())
}

pub fn job_output_len(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> u64 {
    job_output_path(base_dir, job_id, stream)
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0)
}

pub fn job_output_hash(
    base_dir: &Path,
    job_id: &JobId,
    stream: JobOutputStream,
) -> Result<JobOutputHash, JobError> {
    let mut hasher = Hasher::new();
    let path = job_output_path(base_dir, job_id, stream);
    hasher
        .update_mmap_rayon(&path)
        .map_err(|err| JobError::file_io(path, err))?;
    Ok(hasher.finalize().into())
}

fn job_ended(
    jobs: &mut LruCache<JobId, JobStatus>,
    output_dir: &Path,
    result: ExecutionResult,
) -> Result<(), JobError> {
    match result {
        Err(ExecutionError {
            job_id,
            time,
            error: _,
        }) => {
            if let JobStatus::Started {
                job,
                session_id,
                time_started,
                ..
            } = jobs
                .get(&job_id)
                .cloned()
                .ok_or_else(|| JobError::InvalidJobId(job_id.to_owned()))?
            {
                jobs.put(
                    job_id.to_owned(),
                    JobStatus::Ended {
                        job,
                        session_id,
                        time_started,
                        time_ended: time,
                        status: None,
                        stdout_len: job_output_len(output_dir, &job_id, Stdout),
                        stderr_len: job_output_len(output_dir, &job_id, Stderr),
                        stdout_hash: job_output_hash(output_dir, &job_id, Stdout)?,
                        stderr_hash: job_output_hash(output_dir, &job_id, Stderr)?,
                    },
                );
                Ok(())
            } else {
                Err(JobError::InvalidJobId(job_id))
            }
        }
        Ok(ended) => {
            jobs.put(ended.job_id().to_owned(), ended.into());
            Ok(())
        }
    }
}

fn job_start(
    log: &Logger,
    output_dir: &Path,
    job: VerifiedJob,
    session_id: &SessionId,
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
    let len = job_output_len(output_dir, job_id, stream);
    let path = job_output_path(output_dir, job_id, stream);
    let io_error = JobError::file_io_for(&path);
    let mut file = File::open(&path).map_err(|_| JobError::InvalidJobId(job_id.to_owned()))?;
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
    let len = job_output_len(output_dir, job_id, stream);
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

// See tests in `tests/src/manager_tests.rs`
