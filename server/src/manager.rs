//! Manage a set of jobs.
//!
//! The manager runs as an agent loop with exclusive access to the
//! database. It services requests and sends responses via oneshot
//! channels (included in the requests). Jobs are spawned onto new
//! tokio tasks, which the manager loop watches for completion.
//! Standard output and standard error are saved in files.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom};
use std::num::NonZeroU32;
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use blake3::Hasher;
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use dropshot::{ClientErrorStatusCode, HttpError};
use futures::future::FutureExt as _;
use http_range_header::{EndPosition, StartPosition, SyntacticallyCorrectRange as Range};
use pwd::Passwd;
use rusqlite::{Connection, OptionalExtension as _, Row, prepare_cached_and_bind};
use rustix::io::close;
use rustix::process::{ioctl_tiocsctty, setsid};
use slog::{Logger, error, info, o, warn};
use terminfo::Database as Terminfo;
use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle, JoinSet, spawn};
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, DecodePem as _, Encode as _};

use sush_api::JobStartParams;
use sush_common::authn::{Challenge, Credentials, Identity, Nonce};
use sush_common::codephrases::generate_id;
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobOutputHash, JobStartRequest, JobStatus, JobsReserved, SignedJob, VerifiedJob,
};
use sush_common::keys::{KeyError, KeyId, Signature, SshPublicKey};
use sush_common::session::{SessionError, WindowSize};

use crate::pty::Pty;
use crate::session::{Session, SocketSender};

/// Self-signed (root) X.509 certificates. Self-signed certificates may
/// not be imported (except in test code), and so must be included here.
pub const ROOT_CERTS: &[&[u8]] = &[
    // export PERMSLIP_URL="https://permslip.inickles.0xeng.dev"
    // export SUSH_PERMSLIP_KEY="UNTRUSTED Support Shell Prototype"
    include_bytes!("../certs/sandbox.pem"),
];

/// Output files or ranges larger than this will not be served all at once.
const OUTPUT_THRESHOLD: u64 = ByteSize::mb(128).as_u64();

/// An asynchronous kill signal, delivered by the abort request.
type KillShot = oneshot::Sender<()>;

/// A pinned interactive session.
type PinnedSession = Pin<Box<dyn Future<Output = Result<ExitStatus, JobError>> + Send>>;

#[derive(Debug, Error)]
pub enum JobError {
    #[error("Can't send job request: receiver dropped")]
    ChannelClosed,
    #[error("DER encoding error: {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error("File I/O error accessing `{path}`: {error}")]
    FileIo {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("Identity mismatch, expected `{interactive}`, found `{authn}`")]
    IdentityMismatch { interactive: KeyId, authn: KeyId },
    #[error("Invalid command `{0}`")]
    InvalidCommand(String),
    #[error("Invalid or duplicate job ID")]
    InvalidJobId(JobId),
    #[error("Invalid range for output of length {0}")]
    InvalidRange(u64),
    #[error("I/O error during {what}: {error}")]
    Io { what: String, error: std::io::Error },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Can't find certificate for key `{0}`")]
    MissingCert(KeyId),
    #[error("No such nonce `{0}`")]
    NoSuchNonce(Nonce),
    #[error("Job output hash mismatch, file may be corrupt")]
    OutputHashMismatch(JobId, JobOutputHash),
    #[error("Output not yet available")]
    OutputPending,
    #[error("Output too big, please use range requests")]
    OutputTooBig,
    #[error("Public key for `{0}` does not match stored key")]
    PublicKeyMismatch(KeyId),
    #[error("Public key `{0}` not found")]
    PublicKeyNotFound(KeyId),
    #[error("Public key `{key_id}` was revoked at {time_revoked}")]
    PublicKeyRevoked {
        key_id: KeyId,
        time_revoked: DateTime<Utc>,
    },
    #[error("Can't receive response: sender dropped")]
    Recv(#[from] oneshot::error::RecvError),
    #[error("Interactive session error: {0}")]
    Session(#[from] SessionError),
    #[error(transparent)]
    Slice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Task(#[from] JoinError),
    #[error("Unauthorized request")]
    Unauthorized(Nonce),
    #[error("Unable to wait for job end")]
    Wait,
}

impl JobError {
    /// Report I/O errors with the corresponding path or stream name.
    pub fn io(what: impl AsRef<str>, error: std::io::Error) -> Self {
        Self::Io {
            what: what.as_ref().to_owned(),
            error,
        }
    }

    /// Report I/O errors with the corresponding path or stream name.
    pub fn file_io(path: impl AsRef<Path>, error: std::io::Error) -> Self {
        Self::FileIo {
            path: path.as_ref().to_owned(),
            error,
        }
    }

    /// Close over a path.
    pub fn file_io_for(path: impl AsRef<Path>) -> impl Fn(std::io::Error) -> Self {
        move |err| Self::file_io(path.as_ref(), err)
    }
}

impl From<JobError> for HttpError {
    fn from(error: JobError) -> Self {
        use JobError::*;
        let message = error.to_string();
        match error {
            Key(_)
            | ChannelClosed
            | Der(_)
            | Execution(_)
            | FileIo { .. }
            | IdentityMismatch { .. }
            | Io { .. }
            | NoSuchNonce(_)
            | OutputHashMismatch(_, _)
            | PublicKeyNotFound(_)
            | PublicKeyMismatch(_)
            | PublicKeyRevoked { .. }
            | Recv(_)
            | Sqlite(_)
            | Task(_)
            | Slice(_)
            | Wait => HttpError::for_internal_error(message),
            InvalidRange(length) => {
                let mut error = HttpError::for_client_error(
                    None,
                    ClientErrorStatusCode::RANGE_NOT_SATISFIABLE,
                    message,
                );
                error
                    .add_header("content-range", format!("bytes */{length}"))
                    .expect("should be able to add content-range header");
                error
            }
            OutputTooBig => {
                HttpError::for_client_error(None, ClientErrorStatusCode::PAYLOAD_TOO_LARGE, message)
            }
            Session(error) => HttpError::for_client_error(
                None,
                ClientErrorStatusCode::NOT_FOUND,
                error.to_string(),
            ),
            Unauthorized(nonce) => {
                let mut err = HttpError::for_client_error(
                    None,
                    ClientErrorStatusCode::UNAUTHORIZED,
                    String::from("Authentication required"),
                );
                let challenge = Challenge::new(nonce);
                err.add_header("www-authenticate", challenge)
                    .expect("should be able to add www-authenticate header");
                err
            }
            InvalidCommand(_) | InvalidJobId(_) | Json(_) | MissingCert(_) | OutputPending => {
                HttpError::for_client_error(None, ClientErrorStatusCode::BAD_REQUEST, message)
            }
        }
    }
}

#[derive(Clone, Debug, Error)]
#[error("{error}")]
pub struct ExecutionError {
    job_id: JobId,
    time: DateTime<Utc>,
    error: Arc<JobError>,
}

impl ExecutionError {
    fn new(job_id: JobId, error: JobError) -> Self {
        let time = Utc::now();
        Self {
            job_id,
            time,
            error: Arc::new(error),
        }
    }

    #[cfg(test)]
    fn error(&self) -> &JobError {
        &self.error
    }
}

#[derive(Debug)]
struct JobStart {
    job: SignedJob,
    params: JobStartParams,
    authn: Option<Identity>,
    output_dir: PathBuf,
}

impl JobStart {
    fn new(
        job: SignedJob,
        params: JobStartParams,
        authn: Option<Identity>,
        output_dir: PathBuf,
    ) -> Self {
        Self {
            job,
            params,
            authn,
            output_dir,
        }
    }

    fn start(self, time_reserved: DateTime<Utc>) -> Result<JobStarted, JobError> {
        let Self {
            job,
            params:
                JobStartParams {
                    limits,
                    term,
                    rows,
                    cols,
                    wait: _,
                },
            authn: _,
            output_dir,
        } = self;
        let JobStartRequest {
            job_id,
            command,
            interactive,
        } = job.into_payload();
        if command.starts_with('-') {
            return Err(JobError::InvalidCommand(command));
        }

        // Set up output files.
        let job_dir = job_output_dir(&output_dir, &job_id);
        DirBuilder::new()
            .recursive(true)
            .create(&job_dir)
            .map_err(|err| JobError::file_io(job_dir, err))?;
        let stdout_path = job_output_path(&output_dir, &job_id, Stdout);
        let stderr_path = job_output_path(&output_dir, &job_id, Stderr);
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

        let pty = if let Some(key_id) = interactive {
            // Create a pseudoterminal for interactive jobs and wire
            // the child up to it.
            let (pty, pts, pts_path) = Pty::open().map_err(|err| JobError::io("pty open", err))?;
            let pts_error = JobError::file_io_for(&pts_path);
            let pts_clone = || pts.try_clone().map_err(&pts_error);
            child
                .env("SUSH_IDENTITY", key_id.to_string())
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
        Ok(JobStarted {
            time_reserved,
            time_started: Utc::now(),
            child: child.spawn().map_err(|err| JobError::io("spawn", err))?,
            pty,
        })
    }

    fn job_id(&self) -> &JobId {
        self.job.job_id()
    }
}

/// Event representing the start of a job.
#[derive(Debug)]
struct JobStarted {
    time_reserved: DateTime<Utc>,
    time_started: DateTime<Utc>,
    child: Child,
    pty: Option<Pty>,
}

/// Event representing the end of a job. If the job ended due to
/// a signal or an abort, `status` will be `None`.
#[derive(Clone, Debug)]
pub struct JobEnd {
    job: VerifiedJob,
    time_reserved: DateTime<Utc>,
    time_started: DateTime<Utc>,
    time_ended: DateTime<Utc>,
    status: ExitStatus,
    stdout_len: u64,
    stderr_len: u64,
    stdout_hash: JobOutputHash,
    stderr_hash: JobOutputHash,
}

impl From<JobEnd> for JobStatus {
    fn from(end: JobEnd) -> Self {
        let JobEnd {
            job,
            time_reserved,
            time_started,
            time_ended,
            status,
            stdout_len,
            stderr_len,
            stdout_hash,
            stderr_hash,
        } = end;
        Self::Ended {
            job,
            time_reserved,
            time_started,
            time_ended,
            status: status.code(),
            stdout_len,
            stderr_len,
            stdout_hash,
            stderr_hash,
        }
    }
}

enum JobRequest {
    // Certificate requests.
    ImportCert {
        cert: Box<Certificate>,
        response: oneshot::Sender<Result<KeyId, JobError>>,

        /// **For tests only:** Override the usual refusal to import
        /// a self-signed (root) certficate via a request.
        #[cfg(test)]
        root: bool,
    },
    CertChain {
        key_id: KeyId,
        response: oneshot::Sender<Result<Vec<Certificate>, JobError>>,
    },

    // Authentication requests.
    Iam {
        authorization: Option<String>,
        public_key: Option<SshPublicKey>,
        response: oneshot::Sender<Result<Identity, JobError>>,
    },
    Identities {
        start: Option<KeyId>,
        limit: NonZeroU32,
        response: oneshot::Sender<Result<Vec<Identity>, JobError>>,
    },
    RevokeIdentity {
        key_id: KeyId,
        response: oneshot::Sender<Result<(), JobError>>,
    },

    // Job reservation requests.
    Reserve {
        number: u8,
        response: oneshot::Sender<Result<JobsReserved, JobError>>,
    },
    GetReserved {
        response: oneshot::Sender<Result<BTreeMap<JobId, DateTime<Utc>>, JobError>>,
    },
    RevokeReserved {
        job_ids: Vec<JobId>,
        response: oneshot::Sender<Result<Vec<JobId>, JobError>>,
    },

    // Job management requests.
    Start {
        request: Box<JobStart>,
        response: oneshot::Sender<Result<JobEnd, ExecutionError>>,
    },
    Session {
        job_id: JobId,
        response: oneshot::Sender<Result<SocketSender, JobError>>,
    },
    Status {
        job_id: JobId,
        response: oneshot::Sender<Result<JobStatus, JobError>>,
    },
    Output {
        job_id: JobId,
        stream: JobOutputStream,
        range: Option<Range>,
        response: oneshot::Sender<Result<Vec<u8>, JobError>>,
    },
    Abort {
        job_id: JobId,
        response: oneshot::Sender<Result<(), JobError>>,
    },

    // History and post-hoc modification requests.
    History {
        start: Option<JobId>,
        limit: NonZeroU32,
        response: oneshot::Sender<Result<Vec<JobStatus>, JobError>>,
    },
    DeleteOutput {
        job_id: JobId,
        stream: JobOutputStream,
        range: Option<Range>,
        response: oneshot::Sender<Result<u64, JobError>>,
    },
}

#[derive(Debug)]
pub struct JobManager {
    channel: mpsc::Sender<JobRequest>,
    task: JoinHandle<Result<(), JobError>>,
    output_dir: PathBuf,
}

impl JobManager {
    /// Spawn a task that processes job requests and monitors jobs for completion.
    pub async fn new(log: Logger, mut db: Connection, output_dir: &Path) -> Result<Self, JobError> {
        // Import the root certificates.
        for root in ROOT_CERTS {
            let cert = Certificate::from_pem(root).or_else(|_| Certificate::from_der(root))?;
            let key_id = import_cert(&db, &cert, true)?;
            info!(log, "imported root certificate"; "key_id" => %key_id);
        }

        // Accept and process job requests and end events.
        let (tx_requests, mut rx_requests) = mpsc::channel::<JobRequest>(8);
        let task = spawn({
            let output_dir = output_dir.to_owned();
            async move {
                let mut tasks = JoinSet::<Result<JobEnd, ExecutionError>>::new();
                let mut killers = BTreeMap::<JobId, KillShot>::new();
                let mut sessions = BTreeMap::<JobId, SocketSender>::new();
                loop {
                    select! {
                        Some(request) = rx_requests.recv() => {
                            client_request(
                                &log,
                                &mut db,
                                &output_dir,
                                request,
                                &mut tasks,
                                &mut killers,
                                &mut sessions,
                            )?
                        }
                        Some(end) = tasks.join_next() => {
                            job_ended(&log, &db, &output_dir, end, &mut killers, &mut sessions)?
                        }
                        else => {
                            info!(log, "job manager shutting down");
                            return Ok(());
                        }
                    }
                }
            }
        });
        Ok(Self {
            channel: tx_requests,
            output_dir: output_dir.to_owned(),
            task,
        })
    }

    pub async fn wait(self) -> Result<(), JobError> {
        self.task.await?
    }

    async fn request(&self, request: JobRequest) -> Result<(), JobError> {
        self.channel
            .send(request)
            .await
            .map_err(|_| JobError::ChannelClosed)
    }

    pub async fn import_cert_bytes(&self, bytes: &[u8]) -> Result<KeyId, JobError> {
        self.import_cert(
            &Certificate::from_der(bytes)?,
            #[cfg(test)]
            false,
        )
        .await
    }

    async fn import_cert(
        &self,
        cert: &Certificate,
        #[cfg(test)] root: bool,
    ) -> Result<KeyId, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::ImportCert {
            cert: Box::new(cert.to_owned()),
            #[cfg(test)]
            root,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn cert_chain(&self, key_id: KeyId) -> Result<Vec<Certificate>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::CertChain {
            key_id,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn iam(
        &self,
        authorization: Option<String>,
        public_key: Option<SshPublicKey>,
    ) -> Result<Identity, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Iam {
            authorization,
            public_key,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn identities(
        &self,
        start: Option<KeyId>,
        limit: NonZeroU32,
        _authn: &Identity,
    ) -> Result<Vec<Identity>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Identities {
            start,
            limit,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn revoke_identity(&self, key_id: KeyId, _authn: &Identity) -> Result<(), JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::RevokeIdentity {
            key_id,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn reserve_jobs(&self, number: u8) -> Result<JobsReserved, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Reserve {
            number,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn reserve_one(&self) -> Result<(JobId, DateTime<Utc>), JobError> {
        let JobsReserved {
            mut job_ids,
            time_reserved,
        } = self.reserve_jobs(1).await?;
        let n = job_ids.len();
        assert_eq!(n, 1, "requested one job, got {n}");
        Ok((job_ids.pop().unwrap(), time_reserved))
    }

    pub async fn get_reserved(&self) -> Result<BTreeMap<JobId, DateTime<Utc>>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::GetReserved { response: tx })
            .await?;
        rx.await?
    }

    pub async fn revoke_reserved(&self, job_ids: Vec<JobId>) -> Result<Vec<JobId>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::RevokeReserved {
            job_ids,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_start(
        &self,
        job: SignedJob,
        params: JobStartParams,
        authn: Option<Identity>,
    ) -> Result<oneshot::Receiver<Result<JobEnd, ExecutionError>>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Start {
            request: Box::new(JobStart::new(
                job,
                params,
                authn,
                self.output_dir.to_owned(),
            )),
            response: tx,
        })
        .await?;
        Ok(rx)
    }

    pub async fn job_session(
        &self,
        job_id: &JobId,
        _authn: &Identity,
    ) -> Result<SocketSender, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Session {
            job_id: job_id.to_owned(),
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_status(&self, job_id: &JobId) -> Result<JobStatus, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Status {
            job_id: job_id.to_owned(),
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_abort(&self, job_id: &JobId) -> Result<(), JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Abort {
            job_id: job_id.to_owned(),
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_output(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<Vec<u8>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::Output {
            job_id: job_id.to_owned(),
            stream,
            range,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_output_delete(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
        range: Option<Range>,
    ) -> Result<u64, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::DeleteOutput {
            job_id: job_id.to_owned(),
            stream,
            range,
            response: tx,
        })
        .await?;
        rx.await?
    }

    pub async fn job_history(
        &self,
        start: Option<JobId>,
        limit: NonZeroU32,
    ) -> Result<Vec<JobStatus>, JobError> {
        let (tx, rx) = oneshot::channel();
        self.request(JobRequest::History {
            start,
            limit,
            response: tx,
        })
        .await?;
        rx.await?
    }
}

fn job_output_dir(base_dir: &Path, job_id: &JobId) -> PathBuf {
    base_dir.join("jobs").join(job_id.to_string())
}

fn job_output_path(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
    job_output_dir(base_dir, job_id).join(stream.as_str())
}

fn job_output_len(base_dir: &Path, job_id: &JobId, stream: JobOutputStream) -> u64 {
    job_output_path(base_dir, job_id, stream)
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0)
}

fn job_output_hash(
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
    log: &Logger,
    db: &Connection,
    output_dir: &Path,
    end: Result<Result<JobEnd, ExecutionError>, JoinError>,
    killers: &mut BTreeMap<JobId, KillShot>,
    sessions: &mut BTreeMap<JobId, SocketSender>,
) -> Result<(), JobError> {
    match end {
        Err(error) if error.is_cancelled() => {
            info!(log, "job aborted"; "error" => %error);
        }
        Err(error) => {
            error!(log, "job failed"; "error" => %error);
        }
        Ok(Err(ExecutionError {
            job_id,
            time,
            error,
        })) => {
            error!(log, "job execution failed"; "error" => %error, "job_id" => %job_id, "time" => %time);
            assert!(killers.remove(&job_id).is_some());
            assert!(sessions.remove(&job_id).is_some());
            job_aborted(db, output_dir, &job_id, time)?;
        }
        Ok(Ok(JobEnd {
            job,
            time_reserved: _,
            time_started: _,
            time_ended,
            status,
            stdout_len: _,
            stderr_len: _,
            stdout_hash,
            stderr_hash,
        })) => {
            let job_id = job.job_id();
            let _ = killers.remove(job_id);
            let _ = sessions.remove(job_id);
            let status = status.code();
            prepare_cached_and_bind!(
                db,
                "UPDATE jobs \
                 SET time_ended = $time_ended, \
                     status = $status, \
                     stdout_hash = $stdout_hash, \
                     stderr_hash = $stderr_hash \
                 WHERE job_id = $job_id AND \
                       time_started IS NOT NULL AND \
                       time_ended IS NULL"
            )
            .raw_execute()?;
        }
    }
    Ok(())
}

fn job_aborted(
    db: &Connection,
    output_dir: &Path,
    job_id: &JobId,
    time_ended: DateTime<Utc>,
) -> Result<(), JobError> {
    let stdout_hash = job_output_hash(output_dir, job_id, Stdout)?;
    let stderr_hash = job_output_hash(output_dir, job_id, Stderr)?;
    prepare_cached_and_bind!(
        db,
        "UPDATE jobs \
         SET time_ended = $time_ended, \
             stdout_hash = $stdout_hash, \
             stderr_hash = $stderr_hash \
         WHERE job_id = $job_id AND \
               time_started IS NOT NULL AND \
               time_ended IS NULL"
    )
    .raw_execute()?;
    Ok(())
}

fn client_request(
    log: &Logger,
    db: &mut Connection,
    output_dir: &Path,
    request: JobRequest,
    tasks: &mut JoinSet<Result<JobEnd, ExecutionError>>,
    killers: &mut BTreeMap<JobId, KillShot>,
    sessions: &mut BTreeMap<JobId, SocketSender>,
) -> Result<(), JobError> {
    match request {
        JobRequest::ImportCert {
            cert,
            #[cfg(test)]
            root,
            response,
        } => {
            #[cfg(not(test))]
            let root = false;
            let _ = response.send(import_cert(db, &cert, root));
        }

        JobRequest::CertChain { key_id, response } => {
            let _ = response.send(get_cert_chain(db, key_id));
        }

        JobRequest::Iam {
            authorization,
            public_key,
            response,
        } => {
            let _ = response.send(iam(log, db, authorization, public_key));
        }

        JobRequest::Identities {
            start,
            limit,
            response,
        } => {
            let _ = response.send(get_identities(db, start, limit));
        }

        JobRequest::RevokeIdentity { key_id, response } => {
            for job_id in get_sessions(db, &key_id)? {
                let _ = abort_job(log, &job_id, killers);
            }
            let _ = response.send(revoke_identity(log, db, &key_id));
        }

        JobRequest::Reserve { number, response } => {
            let _ = response.send(reserve_jobs(db, number));
        }

        JobRequest::GetReserved { response } => {
            let _ = response.send(get_reserved_jobs(db));
        }

        JobRequest::RevokeReserved { job_ids, response } => {
            let _ = response.send(revoke_reserved_jobs(db, &job_ids));
        }

        JobRequest::Start {
            request: start,
            response,
        } => {
            let job_id = start.job_id().to_owned();
            let log = log.new(o!("job_id" => job_id.to_string()));
            match start_job(&log, db, output_dir, *start, response, tasks, sessions) {
                Ok(kill) => assert!(killers.insert(job_id, kill).is_none()),
                Err(error) => {
                    error!(log, "job execution error"; "error" => %error);
                }
            }
        }

        JobRequest::Session { job_id, response } => {
            let _ = response.send(if let Some(session) = sessions.get_mut(&job_id) {
                info!(log, "accepted interactive session"; "job_id" => %job_id);
                Ok(session.clone())
            } else {
                warn!(log, "can't start session, job ended"; "job_id" => %job_id);
                Err(JobError::Session(SessionError::JobEnded))
            });
        }

        JobRequest::Abort { job_id, response } => {
            let _ = response.send(abort_job(log, &job_id, killers));
        }

        JobRequest::Status { job_id, response } => {
            let _ = response.send(get_job_status(db, output_dir, &job_id));
        }

        JobRequest::Output {
            job_id,
            stream,
            range,
            response,
        } => {
            let _ = response.send(get_job_output(output_dir, &job_id, stream, range));
        }

        JobRequest::History {
            start,
            limit,
            response,
        } => {
            let _ = response.send(get_job_history(db, output_dir, start, limit));
        }

        JobRequest::DeleteOutput {
            job_id,
            stream,
            range,
            response,
        } => {
            let _ = response.send(delete_job_output(output_dir, &job_id, stream, range));
        }
    }
    Ok(())
}

/// Verify and start a job, spawn a task to wait for it and report its end,
/// and return a oneshot channel to kill it.
fn start_job(
    log: &Logger,
    db: &mut Connection,
    output_dir: &Path,
    start: JobStart,
    response: oneshot::Sender<Result<JobEnd, ExecutionError>>,
    tasks: &mut JoinSet<Result<JobEnd, ExecutionError>>,
    sessions: &mut BTreeMap<JobId, SocketSender>,
) -> Result<KillShot, ExecutionError> {
    let job = start.job.clone();
    let job_id = job.job_id().to_owned();
    macro_rules! exe {
        ($expr:expr) => {
            match $expr {
                Ok(x) => x,
                Err(e) => {
                    let e = ExecutionError::new(job_id, e.into());
                    let _ = response.send(Err(e.clone()));
                    return Err(e.into());
                }
            }
        };
    }

    // Verify the job request.
    let txn = exe!(db.transaction());
    let time_reserved = exe!(verify_reservation(&txn, &job_id));
    let cert = exe!(get_cert(&txn, job.key_id()));
    let job = exe!(job.verify_with_cert(&cert));
    if let Some(key_id) = job.interactive() {
        let Some(ref authn) = start.authn else {
            exe!(txn.rollback());
            exe!(unauthorized(db))
        };
        if authn.key_id != *key_id {
            exe!(Err(JobError::IdentityMismatch {
                interactive: key_id.to_owned(),
                authn: authn.key_id.to_owned(),
            }))
        }
    }

    // Start the job.
    let JobStarted {
        time_reserved,
        time_started,
        child,
        pty,
    } = exe!(start.start(time_reserved));
    exe!(job_started(&txn, &job, time_started));
    exe!(txn.commit());

    // If the command is interactive, start a new session for it.
    // Otherwise, run it as a batch (non-interactive) job.
    let output_dir = output_dir.to_owned();
    let (session, shutdown): (PinnedSession, KillShot) = if let Some(pty) = pty {
        let key_id = exe!(get_interactive(db, &job_id));
        let log = log.new(o!("interactive" => key_id.to_string()));
        let output_dir = output_dir.to_owned();
        let path = job_output_path(&output_dir, &job_id, Stdout);
        let io_error = JobError::file_io_for(path.clone());
        let output_file = exe!(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(&io_error)
        );
        let (session, shutdown) = Session::start(log, child, pty, output_file.into());
        assert!(sessions.insert(job_id.clone(), session.clients()).is_none());
        let future = async { session.wait().await.map_err(|err| err.into()) };
        (future.boxed(), shutdown)
    } else {
        batch_job(child)
    };

    tasks.spawn(async move {
        let status = exe!(session.await);
        let stdout_len = job_output_len(&output_dir, &job_id, Stdout);
        let stderr_len = job_output_len(&output_dir, &job_id, Stderr);
        let stdout_hash = exe!(job_output_hash(&output_dir, &job_id, Stdout));
        let stderr_hash = exe!(job_output_hash(&output_dir, &job_id, Stderr));
        let time_ended = Utc::now();
        let end = JobEnd {
            job,
            time_reserved,
            time_started,
            time_ended,
            status,
            stdout_len,
            stderr_len,
            stdout_hash,
            stderr_hash,
        };
        let _ = response.send(Ok(end.clone()));
        Ok(end)
    });

    Ok(shutdown)
}

fn batch_job(mut child: Child) -> (PinnedSession, KillShot) {
    let (kill, die) = oneshot::channel();
    let future = async move {
        select! {
            status = child.wait() => status.map_err(|err| JobError::io("wait", err)),
            _ = die => {
                child.start_kill().map_err(|err| JobError::io("kill", err))?;
                child.wait().await.map_err(|err| JobError::io("wait", err))
            }
        }
    };
    (future.boxed(), kill)
}

fn abort_job(
    log: &Logger,
    job_id: &JobId,
    killers: &mut BTreeMap<JobId, KillShot>,
) -> Result<(), JobError> {
    if let Some(kill) = killers.remove(job_id)
        && let Ok(()) = kill.send(())
    {
        Ok(())
    } else {
        error!(log, "can't kill job"; "job_id" => %job_id);
        Err(SessionError::Shutdown.into())
    }
}

fn get_cert(db: &Connection, key_id: &KeyId) -> Result<Certificate, JobError> {
    let mut stmt = db.prepare_cached(
        "SELECT cert FROM certs WHERE key_id = ?1",
        // `--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?)
    )?;
    if let Some(cert) = stmt
        .query_one([key_id], |row| -> Result<Vec<u8>, _> { row.get(0) })
        .optional()?
    {
        Ok(Certificate::from_der(&cert)?)
    } else {
        Err(JobError::MissingCert(key_id.to_owned()))
    }
}

fn get_cert_chain(db: &Connection, mut key_id: KeyId) -> Result<Vec<Certificate>, JobError> {
    let mut chain = Vec::new();
    loop {
        let cert = get_cert(db, &key_id)?;
        let self_signed = cert.tbs_certificate.subject == cert.tbs_certificate.issuer;
        key_id = KeyId::try_from(&cert.tbs_certificate.issuer)?;
        chain.push(cert);
        if self_signed {
            break;
        }
    }
    chain.reverse();
    Ok(chain)
}

fn import_cert(db: &Connection, cert: &Certificate, root: bool) -> Result<KeyId, JobError> {
    let subject = &cert.tbs_certificate.subject;
    let issuer = &cert.tbs_certificate.issuer;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let signature = Signature::try_from(cert)?;
    if subject == issuer {
        if !root {
            return Err(JobError::Key(KeyError::SelfSigned));
        }
        signature.verify_with_spki(&cert.tbs_certificate.to_der()?, spki)?;
    } else {
        let issuer_cert = get_cert(db, &KeyId::try_from(issuer)?)?;
        let issuer_pki = &issuer_cert.tbs_certificate.subject_public_key_info;
        signature.verify_with_spki(&cert.tbs_certificate.to_der()?, issuer_pki)?;
    }

    let key_id = KeyId::try_from(subject)?;
    db.execute(
        "INSERT INTO certs(key_id, cert) VALUES(?1, ?2) \
         ON CONFLICT(key_id) DO UPDATE SET cert = ?2",
        (&key_id, cert.to_der()?),
    )?;
    Ok(key_id)
}

fn iam(
    log: &Logger,
    db: &mut Connection,
    authorization: Option<String>,
    key: Option<SshPublicKey>,
) -> Result<Identity, JobError> {
    // The client should (probably) not get detailed information back about
    // authentication failures, but debugging is much easier if we log full
    // errors here on the server.
    macro_rules! try_authn {
        ($expr:expr) => {
            match $expr {
                Ok(value) => Ok(value),
                Err(error) => {
                    error!(log, "authentication failed"; "error" => %error);
                    Err(error)
                }
            }
        }
    }

    let txn = db.transaction()?;
    if let Some(authorization) = authorization
        && let Ok(credentials) = try_authn!(authorization.parse())
        && let Credentials { key_id, nonce, .. } = &credentials
        && let Ok(key) = try_authn!(get_public_key(&txn, &key, key_id.clone(), nonce.clone()))
        && let response = credentials.into_challenge_response()
        && let Ok(verified) = try_authn!(response.verify_with_ssh_public_key(&key))
        && let Ok(identity) = try_authn!(Identity::new(key, verified))
    {
        let Identity {
            key_id,
            public_key,
            nonce,
            time_authenticated,
            time_revoked,
        } = &identity;
        assert!(
            time_revoked.is_none(),
            "should not authenticate a revoked identity"
        );
        prepare_cached_and_bind!(
            txn,
            "INSERT OR REPLACE INTO authn (key_id, public_key, nonce, time_authenticated) \
             VALUES ($key_id, $public_key, $nonce, $time_authenticated)"
        )
        .raw_execute()?;
        txn.commit()?;
        info!(log, "authenticated credentials"; "nonce" => %nonce, "key_id" => %key_id);
        Ok(identity)
    } else {
        txn.rollback()?;
        unauthorized(db)
    }
}

fn unauthorized<T>(db: &Connection) -> Result<T, JobError> {
    let nonce = Nonce::generate();
    prepare_cached_and_bind!(db, "INSERT INTO challenges VALUES ($nonce)").raw_execute()?;
    Err(JobError::Unauthorized(nonce))
}

fn claim_nonce(db: &Connection, nonce: Nonce) -> Result<(), JobError> {
    let mut stmt = prepare_cached_and_bind!(db, "DELETE FROM challenges WHERE nonce = $nonce");
    if stmt.raw_execute()? == 1 {
        Ok(())
    } else {
        Err(JobError::NoSuchNonce(nonce.to_owned()))
    }
}

fn get_public_key(
    db: &Connection,
    public_key: &Option<SshPublicKey>,
    key_id: KeyId,
    nonce: Nonce,
) -> Result<SshPublicKey, JobError> {
    if let Some((stored_key, stored_nonce, time_revoked)) = db
        .prepare_cached(
            "SELECT public_key, nonce, time_revoked FROM authn WHERE key_id = ?1",
            // `--SEARCH authn USING INDEX sqlite_autoindex_authn_1 (key_id=?)
        )?
        .query_one(
            [&key_id],
            |row| -> Result<(SshPublicKey, Nonce, Option<DateTime<Utc>>), _> {
                Ok((
                    row.get("public_key")?,
                    row.get("nonce")?,
                    row.get("time_revoked")?,
                ))
            },
        )
        .optional()?
    {
        assert_eq!(
            stored_key
                .key_id()
                .expect("stored keys should have a valid ID"),
            key_id,
            "stored key ID does not match public key, database may be corrupt"
        );

        if let Some(time_revoked) = time_revoked {
            return Err(JobError::PublicKeyRevoked {
                key_id,
                time_revoked,
            });
        }

        if let Some(public_key) = public_key
            && *public_key != stored_key
        {
            return Err(JobError::PublicKeyMismatch(key_id.to_owned()));
        }

        if nonce != stored_nonce {
            claim_nonce(db, nonce)?;
        }

        Ok(stored_key)
    } else if let Some(public_key) = public_key
        && public_key.key_id().map(|id| id == key_id).unwrap_or(false)
    {
        claim_nonce(db, nonce)?;
        Ok(public_key.to_owned())
    } else {
        Err(JobError::PublicKeyNotFound(key_id.to_owned()))
    }
}

fn get_interactive(db: &Connection, job_id: &JobId) -> Result<KeyId, JobError> {
    if let Some(interactive) = db
        .prepare_cached(
            "SELECT interactive FROM jobs WHERE job_id = ?1 AND time_started IS NOT NULL",
        )?
        .query_one([job_id], |row| -> Result<KeyId, _> { row.get(0) })
        .optional()?
    {
        Ok(interactive)
    } else {
        Err(JobError::InvalidJobId(job_id.to_owned()))
    }
}

fn get_sessions(db: &Connection, key_id: &KeyId) -> Result<Vec<JobId>, JobError> {
    let mut stmt = prepare_cached_and_bind!(
        db,
        "SELECT job_id FROM jobs \
         WHERE interactive = $key_id AND \
               time_started IS NOT NULL AND \
               time_ended IS NULL"
    );
    // `--SCAN jobs USING COVERING INDEX current_sessions
    let mut rows = stmt.raw_query();
    let mut sessions = Vec::new();
    while let Some(row) = rows.next()? {
        sessions.push(row.get("job_id")?);
    }
    Ok(sessions)
}

fn get_identities(
    db: &Connection,
    start: Option<KeyId>,
    limit: NonZeroU32,
) -> Result<Vec<Identity>, JobError> {
    let mut stmt = if let Some(start) = start {
        prepare_cached_and_bind!(
            db,
            "SELECT * FROM authn WHERE key_id > $start ORDER BY key_id LIMIT $limit"
        )
        // `--SEARCH authn USING INDEX sqlite_autoindex_authn_1 (key_id<?)
    } else {
        prepare_cached_and_bind!(db, "SELECT * FROM authn ORDER BY key_id LIMIT $limit")
        // `--SCAN authn USING INDEX sqlite_autoindex_authn_1
    };
    let mut rows = stmt.raw_query();
    let mut identities = Vec::new();
    while let Some(row) = rows.next()? {
        identities.push(Identity {
            key_id: row.get("key_id")?,
            public_key: row.get("public_key")?,
            nonce: row.get("nonce")?,
            time_authenticated: row.get("time_authenticated")?,
            time_revoked: row.get("time_revoked")?,
        });
    }
    Ok(identities)
}

fn revoke_identity(log: &Logger, db: &Connection, key_id: &KeyId) -> Result<(), JobError> {
    let time_revoked = Utc::now();
    let mut stmt = prepare_cached_and_bind!(
        db,
        "UPDATE authn SET time_revoked = $time_revoked WHERE key_id = $key_id"
    );
    // `--SEARCH authn USING INDEX sqlite_autoindex_authn_1 (key_id=?)
    if stmt.raw_execute()? == 1 {
        info!(log, "revoked identity"; "key_id" => %key_id);
        Ok(())
    } else {
        Err(JobError::PublicKeyNotFound(key_id.to_owned()))
    }
}

fn reserve_jobs(db: &mut Connection, number: u8) -> Result<JobsReserved, JobError> {
    let time_reserved = Utc::now();
    let txn = db.transaction()?;
    let mut job_ids = Vec::new();
    {
        let mut stmt =
            txn.prepare_cached("INSERT INTO jobs(job_id, time_reserved) VALUES(?1, ?2)")?;
        for _ in 0..number {
            let job_id = JobId::from(&generate_id());
            stmt.execute((&job_id, time_reserved))?;
            job_ids.push(job_id);
        }
    }
    txn.commit()?;
    Ok(JobsReserved {
        job_ids,
        time_reserved,
    })
}

fn get_reserved_jobs(db: &Connection) -> Result<BTreeMap<JobId, DateTime<Utc>>, JobError> {
    let mut reserved = BTreeMap::new();
    let mut stmt = db.prepare_cached(
        "SELECT job_id, time_reserved FROM jobs WHERE time_started IS NULL",
        // `--SCAN jobs USING COVERING INDEX jobs_reserved_only
    )?;
    for row in stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))? {
        let (job_id, time_reserved) = row?;
        assert!(reserved.insert(job_id, time_reserved).is_none());
    }
    Ok(reserved)
}

fn revoke_reserved_jobs(db: &mut Connection, job_ids: &[JobId]) -> Result<Vec<JobId>, JobError> {
    let txn = db.transaction()?;
    let job_ids = if !job_ids.is_empty() {
        job_ids.to_vec()
    } else {
        get_reserved_jobs(&txn)?.keys().cloned().collect()
    };
    let mut revoked = Vec::new();
    {
        let mut stmt = txn.prepare_cached(
            "DELETE FROM jobs WHERE job_id = ?1 AND time_started IS NULL",
            // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        )?;
        for job_id in job_ids {
            if stmt.execute([&job_id])? == 1 {
                revoked.push(job_id);
            }
        }
    }
    txn.commit()?;
    Ok(revoked)
}

fn verify_reservation(db: &Connection, job_id: &JobId) -> Result<DateTime<Utc>, JobError> {
    let mut stmt = db.prepare_cached(
        "SELECT time_reserved FROM jobs WHERE job_id = ?1 AND time_started IS NULL",
        // `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
    )?;
    if let Some(time_reserved) = stmt
        .query_one([job_id], |row| -> Result<DateTime<Utc>, _> { row.get(0) })
        .optional()?
    {
        Ok(time_reserved)
    } else {
        Err(JobError::InvalidJobId(job_id.to_owned()))
    }
}

fn job_started(
    db: &Connection,
    job: &VerifiedJob,
    time_started: DateTime<Utc>,
) -> Result<(), JobError> {
    let job_id = job.job_id();
    let key_id = job.key_id();
    let command = job.command();
    let interactive = &job.interactive;
    let signature = job.signature();
    let mut stmt = prepare_cached_and_bind!(
        db,
        "UPDATE jobs \
         SET key_id = $key_id, command = $command, interactive = $interactive, signature = $signature, time_started = $time_started \
         WHERE job_id = $job_id AND time_started IS NULL"
    );
    if stmt.raw_execute()? == 1 {
        Ok(())
    } else {
        Err(JobError::InvalidJobId(job.job_id().to_owned()))
    }
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

fn get_job_status(
    db: &Connection,
    output_dir: &Path,
    job_id: &JobId,
) -> Result<JobStatus, JobError> {
    let mut stmt = prepare_cached_and_bind!(
        db,
        "SELECT * FROM jobs NATURAL LEFT JOIN certs WHERE job_id = $job_id"
    );
    // |--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
    // `--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?) LEFT-JOIN
    let mut rows = stmt.raw_query();
    if let Ok(Some(row)) = rows.next() {
        let status = make_job_row_to_status(output_dir)(row)?;
        assert!(
            rows.next()?.is_none(),
            "query on primary key should return at most one row"
        );
        Ok(status)
    } else {
        Err(JobError::InvalidJobId(job_id.to_owned()))
    }
}

fn get_job_history(
    db: &Connection,
    output_dir: &Path,
    start: Option<JobId>,
    limit: NonZeroU32,
) -> Result<Vec<JobStatus>, JobError> {
    let mut stmt = if let Some(start) = start {
        prepare_cached_and_bind!(
            db,
            "SELECT * FROM jobs NATURAL LEFT JOIN certs \
             WHERE time_started < (SELECT time_started FROM jobs WHERE job_id=$start) \
             ORDER by time_started DESC, time_reserved DESC \
             LIMIT $limit"
        )
        // |--SEARCH jobs USING INDEX jobs_time_started (time_started<?)
        // |--SCALAR SUBQUERY 1
        // |  `--SEARCH jobs USING INDEX sqlite_autoindex_jobs_1 (job_id=?)
        // |--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?) LEFT-JOIN
        // `--USE TEMP B-TREE FOR LAST TERM OF ORDER BY
    } else {
        prepare_cached_and_bind!(
            db,
            "SELECT * FROM jobs NATURAL LEFT JOIN certs \
             ORDER BY time_started DESC \
             LIMIT $limit"
        )
        // |--SCAN jobs USING INDEX jobs_time_started
        // `--SEARCH certs USING INDEX sqlite_autoindex_certs_1 (key_id=?) LEFT-JOIN
    };
    let job_row_to_status = make_job_row_to_status(output_dir);
    let mut rows = stmt.raw_query();
    let mut entries = Vec::new();
    while let Some(row) = rows.next()? {
        entries.push(job_row_to_status(row)?);
    }
    Ok(entries)
}

/// Return a closure over `output_dir` that constructs a [`JobStatus`]
/// from a row in the `jobs` table.
fn make_job_row_to_status(output_dir: &Path) -> impl Fn(&Row<'_>) -> Result<JobStatus, JobError> {
    move |row| {
        let job_id: JobId = row.get("job_id")?;
        let get_verified_job = || -> Result<VerifiedJob, JobError> {
            let cert = Certificate::from_der(&row.get::<_, Vec<u8>>("cert")?)?;
            Ok(SignedJob::new(
                JobStartRequest {
                    job_id: job_id.clone(),
                    command: row.get("command")?,
                    interactive: row.get("interactive")?,
                },
                row.get("key_id")?,
                row.get("signature")?,
            )
            .verify_with_cert(&cert)?)
        };

        if let Ok(time_ended) = row.get("time_ended") {
            Ok(JobStatus::Ended {
                job: get_verified_job()?,
                time_reserved: row.get("time_reserved")?,
                time_started: row.get("time_started")?,
                time_ended,
                status: row.get("status")?,
                stdout_len: job_output_len(output_dir, &job_id, Stdout),
                stderr_len: job_output_len(output_dir, &job_id, Stderr),
                stdout_hash: row.get("stdout_hash")?,
                stderr_hash: row.get("stderr_hash")?,
            })
        } else if let Ok(time_started) = row.get("time_started") {
            Ok(JobStatus::Started {
                job: get_verified_job()?,
                time_reserved: row.get("time_reserved")?,
                time_started,
                stdout_len: job_output_len(output_dir, &job_id, Stdout),
                stderr_len: job_output_len(output_dir, &job_id, Stderr),
            })
        } else if let Ok(time_reserved) = row.get("time_reserved") {
            Ok(JobStatus::Reserved {
                job_id: job_id.clone(),
                time_reserved,
            })
        } else {
            panic!("time_reserved should be NOT NULL")
        }
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use function_name::named;
    use pwd::Passwd;
    use rand_core::{OsRng, RngCore as _};
    use rusqlite::limits::Limit;
    use slog::{Drain as _, o};
    use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
    use tempfile::TempDir;
    use x509_cert::name::Name;
    use x509_cert::time::Validity;

    use sush_common::authn::ChallengeResponse;
    use sush_common::jobs::JobLimits;
    use sush_common::keys::{EphemeralKey, KeyType, Signer as _};

    #[allow(unused_imports)]
    use crate::database::{open_database, open_database_in_memory};

    use super::*;

    trait SignJobRequest {
        async fn sign_job_request<S: AsRef<str>>(
            &mut self,
            job_id: &JobId,
            command: S,
            interactive: Option<KeyId>,
        ) -> SignedJob;
    }

    impl SignJobRequest for EphemeralKey {
        async fn sign_job_request<S: AsRef<str>>(
            &mut self,
            job_id: &JobId,
            command: S,
            interactive: Option<KeyId>,
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
            time_reserved,
            time_started,
            stdout_len: _,
            stderr_len: _,
        } = status
        else {
            panic!("expected job to be started");
        };
        assert_eq!(job.job_id, *expected_job_id);
        assert_eq!(job.command, expected_command);
        assert!(time_reserved < time_started);
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
            time_reserved,
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
        assert!(time_reserved < time_started);
        assert!(time_started < time_ended);
        assert!(time_ended < Utc::now());
        assert_eq!(status, expected_status);
        assert_eq!(stdout_len, expected_stdout_len);
        assert_eq!(stderr_len, expected_stderr_len);
    }

    async fn manager_and_test_root(
        db: Option<&str>,
        test_name: &'static str,
    ) -> (JobManager, EphemeralKey, TempDir) {
        let db = if let Some(db) = db {
            open_database(db).unwrap()
        } else {
            open_database_in_memory().unwrap()
        };
        db.set_limit(Limit::SQLITE_LIMIT_LENGTH, 10_000).unwrap();
        let decorator = PlainSyncDecorator::new(TestStdoutWriter);
        let drain = FullFormat::new(decorator).build().fuse();
        let dir = TempDir::with_prefix("sush-").unwrap();
        let log = Logger::root(drain, o!("test" => test_name));
        let mgr = JobManager::new(log, db, dir.path()).await.unwrap();
        let root = ephemeral_test_root();
        let key_id = mgr.import_cert(root.cert(), true).await.unwrap();
        assert_eq!(&key_id, root.key_id());
        (mgr, root, dir)
    }

    #[named]
    #[tokio::test]
    async fn jobs() {
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let JobsReserved {
            mut job_ids,
            time_reserved,
        } = mgr.reserve_jobs(5).await.unwrap();
        assert_eq!(job_ids.len(), 5);
        assert!(time_reserved < Utc::now());

        let reserved = mgr.get_reserved().await.unwrap();
        for job_id in &job_ids {
            assert_eq!(reserved[job_id], time_reserved);
        }

        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, "true", None).await;
        assert!(matches!(
            mgr.job_status(&job_id).await.unwrap(),
            JobStatus::Reserved { job_id: id, time_reserved }
            if id == job_id && time_reserved < Utc::now(),
        ));

        let rx = mgr
            .job_start(job.clone(), Default::default(), None)
            .await
            .unwrap();
        let status = rx.await.unwrap().unwrap().into();
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);

        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();
        assert!(
            matches!(
                rx.await.unwrap().unwrap_err().error(),
                JobError::InvalidJobId(id) if *id == job_id
            ),
            "should not be allowed to reuse a job ID"
        );

        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, "false", None).await;
        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();
        let status = rx.await.unwrap().unwrap().into();
        check_status_ended(status, &job_id, "false", Some(1), 0, 0);

        let job_id = job_ids.pop().unwrap();
        let job_id_string = job_id.to_string();
        let job_id_bytes = job_id_string.as_bytes();
        let job = root
            .sign_job_request(&job_id, "echo -n $SUSH_JOB_ID", None)
            .await;
        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(
            status,
            &job_id,
            "echo -n $SUSH_JOB_ID",
            Some(0),
            job_id_bytes.len() as u64,
            0,
        );
        assert_eq!(
            mgr.job_output(&job_id, Stdout, None).await.unwrap(),
            job_id_bytes
        );
        assert!(
            mgr.job_output(&job_id, Stderr, None)
                .await
                .unwrap()
                .is_empty()
        );

        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, "pwd", None).await;
        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();
        rx.await.unwrap().unwrap();
        let home = Passwd::current_user().unwrap().dir;
        let pwd = format!("{home}\n");
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(status, &job_id, "pwd", Some(0), pwd.len() as u64, 0);
        assert_eq!(
            mgr.job_output(&job_id, Stdout, None).await.unwrap(),
            pwd.as_bytes(),
        );
        assert!(
            mgr.job_output(&job_id, Stderr, None)
                .await
                .unwrap()
                .is_empty()
        );

        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
    }

    #[named]
    #[tokio::test]
    async fn revoke() {
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, time_reserved) = mgr.reserve_one().await.unwrap();
        let job_ids = vec![job_id.clone()];
        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());

        let job = root.sign_job_request(&job_id, "false", None).await;
        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();
        assert!(
            matches!(
                rx.await.unwrap().unwrap_err().error(),
                JobError::InvalidJobId(id) if *id == job_id
            ),
            "should not be allowed to start a revoked job"
        );
        assert!(
            matches!(
                mgr.job_status(&job_id).await.unwrap_err(),
                JobError::InvalidJobId(id) if id == job_id
            ),
            "revoked jobs should not have a status"
        );

        let (new_job_id, new_time_reserved) = mgr.reserve_one().await.unwrap();
        assert_ne!(new_job_id, job_id);
        assert!(new_time_reserved > time_reserved);

        let job_ids = vec![job_id.clone(), new_job_id.clone()];
        assert_eq!(
            mgr.revoke_reserved(job_ids.clone()).await.unwrap(),
            vec![new_job_id],
            "old job was previously revoked"
        );
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());

        let JobsReserved {
            job_ids,
            time_reserved: _,
        } = mgr.reserve_jobs(100).await.unwrap();
        assert_eq!(mgr.revoke_reserved(job_ids.clone()).await.unwrap(), job_ids);
        assert!(mgr.revoke_reserved(job_ids).await.unwrap().is_empty());
    }

    #[named]
    #[tokio::test]
    async fn abort() {
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();

        let command = "sleep 10";
        let job = root.sign_job_request(&job_id, command, None).await;
        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();

        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_started(status, root.cert(), &job_id, command);

        mgr.job_abort(&job_id).await.unwrap();
        assert_eq!(rx.await.unwrap().unwrap().job.job_id(), &job_id);

        let status = mgr.job_status(&job_id).await.unwrap();
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

        let db = open_database_in_memory().unwrap();
        let dir = TempDir::with_prefix("sush-").unwrap();
        let log = Logger::root(slog::Discard, slog::o!("test" => function_name!()));
        let mgr = JobManager::new(log, db, dir.path()).await.unwrap();
        assert!(
            matches!(
                mgr.import_cert(&root_cert, false).await.unwrap_err(),
                JobError::Key(KeyError::SelfSigned),
            ),
            "should not accept root cert without override"
        );
        assert!(
            matches!(
                mgr.import_cert(child.cert(), false).await.unwrap_err(),
                JobError::MissingCert(key_id) if key_id == root_key_id,
            ),
            "should not accept child cert without root"
        );
        assert_eq!(
            mgr.import_cert(&root_cert, true).await.unwrap(),
            root_key_id
        );
        assert_eq!(
            mgr.cert_chain(root_key_id).await.unwrap(),
            vec![root_cert.clone()]
        );
        assert_eq!(
            mgr.import_cert(child.cert(), false).await.unwrap(),
            child_key_id,
        );
        assert_eq!(
            mgr.cert_chain(child_key_id).await.unwrap(),
            vec![root_cert.clone(), child.cert().clone()]
        );

        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();
        let job = child.sign_job_request(&job_id, "true", None).await;
        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        check_status_ended(status, &job_id, "true", Some(0), 0, 0);
    }

    #[named]
    #[tokio::test]
    async fn too_much_cpu() {
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let (job_id, _time_reserved) = mgr.reserve_one().await.unwrap();
        let command = "openssl speed sha1";
        let job = root.sign_job_request(&job_id, command, None).await;
        let rx = mgr
            .job_start(
                job,
                JobStartParams {
                    limits: JobLimits {
                        max_cpu: 1,
                        max_fsize: 100,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                None,
            )
            .await
            .unwrap();
        rx.await.unwrap().unwrap();
        let status = mgr.job_status(&job_id).await.unwrap();
        assert!(status.time_elapsed().unwrap().to_std().unwrap() < Duration::from_secs(2));

        // The output of `openssl speed` changed between v3.0 and v3.5.
        let stderr = mgr.job_output(&job_id, Stderr, None).await.unwrap();
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
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
        let JobsReserved {
            mut job_ids,
            time_reserved: _,
        } = mgr.reserve_jobs(1).await.unwrap();

        // Read some random bytes.
        let n = 1000;
        let command = &format!("head -c {n} /dev/urandom");
        let job_id = job_ids.pop().unwrap();
        let job = root.sign_job_request(&job_id, command, None).await;
        let rx = mgr.job_start(job, Default::default(), None).await.unwrap();
        let status = rx.await.unwrap().unwrap().into();
        check_status_ended(status, &job_id, command, Some(0), n, 0);

        // No range, i.e., full output.
        let r = mgr.job_output(&job_id, Stdout, None).await.unwrap();

        // One byte too big.
        assert!(matches!(
            mgr.job_output(
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n),
                })
            )
            .await
            .unwrap_err(),
            JobError::InvalidRange(m) if m == n,
        ));

        // Whole range.
        assert_eq!(
            mgr.job_output(
                &job_id,
                Stdout,
                Some(Range {
                    start: StartPosition::Index(0),
                    end: EndPosition::Index(n - 1),
                })
            )
            .await
            .unwrap(),
            r
        );

        // Two half-ranges.
        let mut o = mgr
            .job_output(
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
        let (mgr, mut root, _dir) = manager_and_test_root(None, function_name!()).await;
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
        assert_eq!(iam_nonce, nonce);
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

        // Revoke and check failure.
        mgr.revoke_identity(key_id.clone(), &identity)
            .await
            .unwrap();
        let JobError::Unauthorized(new_nonce) = mgr
            .iam(Some(credentials.to_string()), None)
            .await
            .unwrap_err()
        else {
            panic!("should no longer be authorized");
        };
        assert_ne!(new_nonce, nonce);

        // Even fresh credentials fail.
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
