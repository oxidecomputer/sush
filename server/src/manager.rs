//! Manage a set of jobs.
//!
//! Jobs are spawned onto new tokio tasks and passed to the monitor to wait
//! for completion. Standard output and standard error are saved in files.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::num::{NonZeroU32, NonZeroUsize};
use std::ops::Bound;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

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

/// Maximum number of outstanding authentication nonces.
const MAX_OUTSTANDING_NONCES: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

#[derive(Debug)]
pub struct JobManager {
    log: Logger,
    nonces: Arc<Mutex<LruCache<Nonce, DateTime<Utc>>>>,
    identities: Arc<Mutex<BTreeMap<KeyId, Identity>>>,
    certs: Arc<Mutex<BTreeMap<KeyId, Certificate>>>,
    session: Arc<Mutex<Option<Session>>>,
    jobs: Arc<Mutex<BTreeMap<JobId, JobStatus>>>,
    output_dir: PathBuf,
    tx_monitor: mpsc::Sender<MonitorRequest>,
}

impl JobManager {
    pub async fn new(log: Logger, output_dir: &Path) -> Result<Self, JobError> {
        let jobs = Arc::new(Mutex::new(BTreeMap::new()));

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
            identities: Arc::new(Mutex::new(BTreeMap::new())),
            certs: Arc::new(Mutex::new(BTreeMap::new())),
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

    #[cfg(test)]
    fn import_root(&self, root: Certificate) -> Result<KeyId, JobError> {
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
        certs.insert(key_id.clone(), cert);
        info!(self.log, "imported certificate"; "key_id" => %key_id, "root" => root);
        Ok(key_id)
    }

    /// Return the cert chain for the given key in root-to-leaf order.
    pub fn cert_chain(
        &self,
        _authn: &Identity,
        key_id: &KeyId,
    ) -> Result<Vec<Certificate>, JobError> {
        let certs = self.certs.lock().unwrap();
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

    pub async fn iam(
        &self,
        authorization: Option<String>,
        public_key: Option<SshPublicKey>,
    ) -> Result<Identity, JobError> {
        let mut nonces = self.nonces.lock().unwrap();
        let mut identities = self.identities.lock().unwrap();

        // The client should (probably) not get detailed information back about
        // authentication failures, but debugging is much easier if we log full
        // errors here on the server.
        macro_rules! try_authn {
            ($expr:expr) => {
                match $expr {
                    Ok(value) => Ok(value),
                    Err(error) => {
                        error!(self.log, "authentication failed"; "error" => %error);
                        Err(error)
                    }
                }
            };
            ($expr:expr, $error:expr) => {
                $expr || {
                    error!(self.log, "authentication failed"; "error" => $error);
                    false
                }
            }
        }

        if let Some(authorization) = authorization
            && let now = Utc::now()
            && let Ok(credentials) = try_authn!(authorization.parse())
            && let Credentials {
                key_id,
                nonce,
                cnonce,
                signature,
            } = &credentials
            && let Some(identity) = match identities.get(key_id) {
                Some(Identity {
                    time_revoked: Some(time_revoked),
                    ..
                }) => {
                    return try_authn!(Err(JobError::PublicKeyRevoked {
                        key_id: key_id.to_owned(),
                        time_revoked: time_revoked.to_owned(),
                    }));
                }
                Some(
                    identity @ Identity {
                        key_id: identity_key_id,
                        cnonce: c,
                        signature: s,
                        time_revoked: None,
                        ..
                    },
                ) if try_authn!(identity.is_still_valid(&now), "credentials expired")
                    && try_authn!(c == cnonce, "invalid cnonce")
                    && try_authn!(s == signature, "invalid signature") =>
                {
                    assert_eq!(identity_key_id, key_id);
                    Some(identity.to_owned())
                }
                _ if try_authn!(
                    nonces
                        .pop(nonce)
                        .map(|t| Nonce::is_still_valid(&t, &now))
                        .unwrap_or(false),
                    "nonce expired"
                ) && try_authn!(
                    public_key.as_ref().and_then(|k| k.key_id().ok()) == Some(key_id.clone()),
                    "invalid public key"
                ) =>
                {
                    let public_key = public_key.expect("checked in guard");
                    let response = credentials.clone().into_challenge_response();
                    let verified = try_authn!(response.verify_with_ssh_public_key(&public_key))?;
                    Some(try_authn!(Identity::new(
                        public_key.to_owned(),
                        verified,
                        now
                    ))?)
                }
                _ => None,
            }
        {
            identities.insert(key_id.to_owned(), identity.to_owned());
            debug!(self.log, "authenticated credentials"; "key_id" => %key_id);
            Ok(identity)
        } else {
            let nonce = Nonce::generate();
            nonces.put(nonce.clone(), Utc::now());
            Err(JobError::unauthorized(nonce))
        }
    }

    pub async fn identities(
        &self,
        _authn: &Identity,
        start: Option<KeyId>,
        limit: NonZeroU32,
    ) -> Result<Vec<Identity>, JobError> {
        let identities = self.identities.lock().unwrap();
        let iter = match start {
            Some(start_key) => identities.range((Bound::Excluded(start_key), Bound::Unbounded)),
            None => identities.range(..),
        };
        Ok(iter
            .take(limit.get() as usize)
            .map(|(_id, identity)| identity.to_owned())
            .collect())
    }

    pub async fn revoke_identity(&self, _authn: &Identity, key_id: KeyId) -> Result<(), JobError> {
        if let Some(identity) = self.identities.lock().unwrap().get_mut(&key_id) {
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
        if let Some(session) = { self.session.lock().unwrap().take() }
            && session.session_id() == session_id
        {
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

    pub async fn job_history(
        &self,
        _authn: &Identity,
        _start: Option<JobId>,
        _limit: NonZeroU32,
    ) -> Result<Vec<JobStatus>, JobError> {
        // TODO: fetch job history
        Ok(vec![])
    }

    pub async fn job_start(
        &self,
        authn: &Identity,
        job: SignedJob,
        params: JobStartParams,
    ) -> Result<Option<ExecutionResult>, JobError> {
        let wait = params.wait;
        let started = {
            let job_id = job.job_id().to_owned();
            if self.jobs.lock().unwrap().contains_key(&job_id) {
                return Err(JobError::InvalidJobId(job_id));
            }

            let cert_key_id = job.key_id().to_owned();
            let cert = self
                .certs
                .lock()
                .unwrap()
                .get(&cert_key_id)
                .cloned()
                .ok_or_else(|| JobError::MissingCert(cert_key_id))?;

            let job = job.verify_with_cert(&cert)?;
            let mut session_guard = self.session.lock().unwrap();
            let Some(session) = session_guard.as_mut() else {
                return Err(JobError::NoSession);
            };
            if session.key_id() != Some(&authn.key_id) {
                return Err(JobError::SessionWrongIdentity);
            }
            if session.next_job_id()? != job_id {
                return Err(JobError::InvalidJobId(job_id));
            }
            let started = job_start(
                &self.log,
                &self.output_dir,
                job.clone(),
                session.session_id(),
                params,
            )?;
            self.jobs
                .lock()
                .unwrap()
                .insert(job_id, JobStatus::from(&started));
            session.job_started(job.into_signed());
            started
        };

        let (tx, rx) = oneshot::channel();
        self.monitor(MonitorRequest::started(started, tx)).await?;
        if wait { Ok(Some(rx.await?)) } else { Ok(None) }
    }

    fn check_job_owner(&self, authn: &Identity, job_id: &JobId) -> Result<(), JobError> {
        let Some(ref session) = *self.session.lock().unwrap() else {
            return Err(JobError::NoSession);
        };
        let Some(job_session_id) = self.job_status(authn, job_id)?.session_id() else {
            return Err(JobError::JobNotFound(job_id.to_owned()));
        };
        if job_session_id != *session.session_id() {
            return Err(JobError::JobNotFound(job_id.to_owned()));
        }
        if session.key_id() != Some(&authn.key_id) {
            return Err(JobError::SessionWrongIdentity);
        }
        Ok(())
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
        Ok(self
            .jobs
            .lock()
            .unwrap()
            .get(job_id)
            .cloned()
            .unwrap_or_else(|| JobStatus::Unknown {
                job_id: job_id.to_owned(),
            }))
    }

    pub async fn job_stop(&self, authn: &Identity, job_id: &JobId) -> Result<(), JobError> {
        self.check_job_owner(authn, job_id)?;
        self.monitor(MonitorRequest::Stop(job_id.to_owned())).await
    }

    pub async fn job_output(
        &self,
        _authn: &Identity,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        // Anyone is allowed to read job output.
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
    jobs: &mut BTreeMap<JobId, JobStatus>,
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
                assert!(
                    jobs.insert(
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
                        }
                    )
                    .is_some()
                );
                Ok(())
            } else {
                Err(JobError::InvalidJobId(job_id))
            }
        }
        Ok(ended) => {
            assert!(
                jobs.insert(ended.job_id().to_owned(), ended.into())
                    .is_some()
            );
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
    use sush_common::jobs::JobLimits;
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};

    use super::*;

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
            job,
            session_id: _,
            time_started,
            stdout_len: _,
            stderr_len: _,
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
        expected_status: Option<i32>,
        expected_stdout_len: u64,
        expected_stderr_len: u64,
    ) {
        let JobStatus::Ended {
            job,
            session_id: _,
            time_started,
            time_ended,
            status,
            stdout_len,
            stderr_len,
            stdout_hash: _,
            stderr_hash: _,
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
        let key_id = mgr.import_root(root.cert().to_owned()).unwrap();
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

    async fn job_status(authn: &Identity, mgr: &JobManager, job: SignedJob) -> JobStatus {
        mgr.job_start(authn, job, JobStartParams::wait())
            .await
            .expect("should be able to start job")
            .expect("should be waiting for job")
            .expect("job should end successfully")
            .into()
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
        let session_id = mgr.session_start(&authn).await.unwrap();
        let job_id = session_id.first_job_id();
        let job = root.sign_job_request(&job_id, "true", false).await;
        assert!(matches!(
            mgr.job_status(&authn, &job_id).unwrap(),
            JobStatus::Unknown { job_id: id } if id == job_id
        ));
        let status = job_status(&authn, &mgr, job.clone()).await;
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);

        assert!(
            matches!(
                job_error(&authn, &mgr, job.clone()).await,
                JobError::InvalidJobId(ref id) if *id == job_id
            ),
            "should not be allowed to reuse a job ID"
        );

        let job_id = session_id.next_job_id(&job).unwrap();
        let job = root.sign_job_request(&job_id, "false", false).await;
        let status = job_status(&authn, &mgr, job.clone()).await;
        check_status_ended(status, &job_id, "false", Some(1), 0, 0);

        let job_id = session_id.next_job_id(&job).unwrap();
        let job_id_string = job_id.to_string();
        let job_id_bytes = job_id_string.as_bytes();
        let job = root
            .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", false)
            .await;
        let status = job_status(&authn, &mgr, job.clone()).await;
        check_status_ended(
            status,
            &job_id,
            "echo -n $SUSH_JOB_ID",
            Some(0),
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
        let job_id = session_id.next_job_id(&job).unwrap();
        let job = root.sign_job_request(&job_id, "pwd", false).await;
        let status = job_status(&authn, &mgr, job.clone()).await;
        check_status_ended(status, &job_id, "pwd", Some(0), output.len() as u64, 0);
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

        let job_id = session_id.next_job_id(&job).unwrap();
        let job = root.sign_job_request(&job_id, "foo", false).await;
        let new_session_id = mgr.session_start(&authn).await.unwrap();
        assert_ne!(new_session_id, session_id);
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

        let job_id = new_session_id.first_job_id();
        let job = root.sign_job_request(&job_id, "true", false).await;
        let status = job_status(&authn, &mgr, job).await;
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn abort() {
        let (mgr, mut root, _dir) = manager_and_test_root(function_name!()).await;
        let authn = fake_identity(&mut root).await;
        let session_id = mgr.session_start(&authn).await.unwrap();
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
        let status = mgr.job_status(&authn, &job_id).unwrap();
        check_status_started(status, root.cert(), &job_id, command);

        // Kill the job and wait for it to die.
        mgr.job_stop(&authn, &job_id).await.unwrap();
        sleep(Duration::from_millis(10)).await;

        // Check that it's dead and that it didn't live for long.
        let status = mgr.job_status(&authn, &job_id).unwrap();
        assert!(status.time_elapsed().unwrap().to_std().unwrap() < Duration::from_secs(1));
        check_status_ended(status, &job_id, command, None, 0, 0);
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
                mgr.import_cert(&authn, root_cert.clone()).unwrap_err(),
                JobError::Key(KeyError::SelfSigned),
            ),
            "should not accept root cert without override"
        );
        assert!(
            matches!(
                mgr.import_cert(&authn, child.cert().clone()).unwrap_err(),
                JobError::MissingCert(key_id) if key_id == root_key_id,
            ),
            "should not accept child cert without root"
        );
        assert_eq!(mgr.import_root(root_cert.clone()).unwrap(), root_key_id);
        assert_eq!(
            mgr.cert_chain(&authn, &root_key_id).unwrap(),
            vec![root_cert.clone()]
        );
        assert_eq!(
            mgr.import_cert(&authn, child.cert().clone()).unwrap(),
            child_key_id
        );
        assert_eq!(
            mgr.cert_chain(&authn, &child_key_id).unwrap(),
            vec![root_cert.clone(), child.cert().clone()]
        );

        let session_id = mgr.session_start(&authn).await.unwrap();
        let job_id = session_id.first_job_id();
        let job = child.sign_job_request(&job_id, "true", false).await;
        let status = job_status(&authn, &mgr, job).await;
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn too_much_cpu() {
        let (mgr, mut root, _dir) = manager_and_test_root(function_name!()).await;
        let authn = fake_identity(&mut root).await;
        let session_id = mgr.session_start(&authn).await.unwrap();
        let job_id = session_id.first_job_id();
        let command = "openssl speed sha1";
        let job = root.sign_job_request(&job_id, command, false).await;
        let status = JobStatus::from(
            mgr.job_start(
                &authn,
                job,
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
            .expect("job should end successfully"),
        );
        assert!(status.time_elapsed().unwrap().to_std().unwrap() < Duration::from_secs(2));

        // The output of `openssl speed` changed between v3.0 and v3.5.
        let stderr = mgr.job_output(&authn, &job_id, Stderr, None).await.unwrap();
        let stderr = String::from_utf8_lossy(&stderr);
        match status {
            JobStatus::Ended { stderr_len: 37, .. } => {
                check_status_ended(status, &job_id, command, None, 0, 37);
                assert_eq!(stderr, "Doing sha1 for 3s on 16 size blocks: ");
            }
            JobStatus::Ended { stderr_len: 41, .. } => {
                check_status_ended(status, &job_id, command, None, 0, 41);
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
        let session_id = mgr.session_start(&authn).await.unwrap();
        let job_id = session_id.first_job_id();

        // Read some random bytes.
        let n = 1000;
        let command = &format!("head -c {n} /dev/urandom");
        let job = root.sign_job_request(&job_id, command, false).await;
        let status = job_status(&authn, &mgr, job).await;
        check_status_ended(status, &job_id, command, Some(0), n, 0);

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
            cnonce: iam_cnonce,
            signature: _,
            time_authenticated: iam_authenticated,
            time_revoked: iam_revoked,
        } = identity.clone();
        assert_eq!(iam_key_id, key_id);
        assert_eq!(iam_public_key, public_key);
        assert_eq!(iam_nonce, credentials.nonce);
        assert_eq!(iam_cnonce, credentials.cnonce);
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

        // Revoke and check for failure.
        mgr.revoke_identity(&identity, key_id.clone())
            .await
            .unwrap();
        assert!(
            matches!(
                mgr.iam(Some(credentials.to_string()), None)
                    .await
                    .unwrap_err(),
                JobError::PublicKeyRevoked {
                    key_id: revoked_key_id,
                    time_revoked,
                } if revoked_key_id == key_id && time_revoked < Utc::now()
            ),
            "should no longer be authorized"
        );

        // Even fresh credentials should now fail.
        let JobError::Unauthorized(new_nonce) = mgr.iam(None, None).await.unwrap_err() else {
            panic!("should not be authorized");
        };
        let challenge = Challenge::new(new_nonce);
        let response = ChallengeResponse::new(challenge);
        let signed = root.sign(response).await.unwrap();
        let verified = signed.verify_with_cert(root.cert()).unwrap();
        let mut credentials = Credentials::new(verified);
        credentials.key_id = key_id.clone(); // override cert key ID
        mgr.iam(Some(credentials.to_string()), Some(public_key.clone()))
            .await
            .unwrap_err();
    }
}
