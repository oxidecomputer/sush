//! Job server errors.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dropshot::{ClientErrorStatusCode, HttpError};
use thiserror::Error;

use sush_common::authn::{Challenge, Nonce};
use sush_common::interactive::InteractiveSessionError;
use sush_common::jobs::{JobId, JobOutputHash, SessionId};
use sush_common::keys::{KeyError, KeyId};

/// What went wrong processing a client job request.
#[derive(Debug, Error)]
pub enum JobError {
    #[error("Certificate chain is too long")]
    CertChainTooLong,
    #[error("Internal communications channel was unexpectedly closed")]
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
    #[error("Identity not found")]
    IdentityNotFound(KeyId),
    #[error("Interactive session error: {0}")]
    InteractiveSession(#[from] InteractiveSessionError),
    #[error("Invalid command `{0}`, must not start with `-`")]
    InvalidCommand(String),
    #[error("Invalid or duplicate job ID")]
    InvalidJobId(JobId),
    #[error("Invalid range for output of length {0}")]
    InvalidRange(u64),
    #[error("I/O error during {what}: {error}")]
    Io { what: String, error: std::io::Error },
    #[error("Job `{0}` not found")]
    JobNotFound(JobId),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Can't kill job `{0}`")]
    Shutdown(JobId),
    #[error("Can't find certificate for key `{0}`")]
    MissingCert(KeyId),
    #[error("Only one session may be running at a time")]
    MultipleSessions,
    #[error("No current session")]
    NoSession,
    #[error("Session `{0}` is no longer current")]
    SessionNotCurrent(SessionId),
    #[error("Session `{0}` not found")]
    SessionNotFound(SessionId),
    #[error("Incorrect identity for session, try `iam`")]
    SessionWrongIdentity,
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
    Recv(#[from] tokio::sync::oneshot::error::RecvError),
    #[error(transparent)]
    Slice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("Too many certificates ({0})")]
    TooManyCerts(usize),
    #[error("Too many jobs in a session ({0}), try waiting for some to finish")]
    TooManyJobs(usize),
    #[error("Too many identities revoked ({0})")]
    TooManyRevocations(usize),
    #[error("Unauthorized request")]
    Unauthorized(Nonce),
    #[error("Unable to wait for job end")]
    Wait,
}

impl JobError {
    pub fn closed<E>(_err: E) -> Self {
        Self::ChannelClosed
    }

    pub fn unauthorized(nonce: Nonce) -> Self {
        Self::Unauthorized(nonce)
    }

    /// Report I/O errors with the corresponding stream name.
    pub fn io(what: impl AsRef<str>, error: std::io::Error) -> Self {
        Self::Io {
            what: what.as_ref().to_owned(),
            error,
        }
    }

    /// Report file I/O errors with the corresponding path.
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
            | Io { .. }
            | OutputHashMismatch(_, _)
            | PublicKeyNotFound(_)
            | PublicKeyMismatch(_)
            | Recv(_)
            | Shutdown(_)
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
                    .add_header("Content-Range", format!("bytes */{length}"))
                    .expect("should be able to add Content-Range header");
                error
            }
            OutputTooBig => {
                HttpError::for_client_error(None, ClientErrorStatusCode::PAYLOAD_TOO_LARGE, message)
            }
            InteractiveSession(error) => HttpError::for_client_error(
                None,
                ClientErrorStatusCode::NOT_FOUND,
                error.to_string(),
            ),
            Unauthorized(nonce) => {
                let mut err = HttpError::for_client_error(
                    None,
                    ClientErrorStatusCode::UNAUTHORIZED,
                    String::from("Authentication required, try `iam`"),
                );
                let challenge = Challenge::new(nonce);
                err.add_header("WWW-Authenticate", challenge)
                    .expect("should be able to add WWW-Authenticate header");
                err
            }
            SessionWrongIdentity | PublicKeyRevoked { .. } => {
                HttpError::for_client_error(None, ClientErrorStatusCode::FORBIDDEN, message)
            }
            JobNotFound(_) | NoSession | SessionNotFound(_) | SessionNotCurrent(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::NOT_FOUND, message)
            }
            IdentityNotFound(_)
            | InvalidCommand(_)
            | InvalidJobId(_)
            | Json(_)
            | CertChainTooLong
            | MissingCert(_)
            | MultipleSessions
            | OutputPending
            | TooManyCerts(_)
            | TooManyJobs(_)
            | TooManyRevocations(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::BAD_REQUEST, message)
            }
        }
    }
}

/// What went wrong acutally running a job.
#[derive(Clone, Debug, Error)]
#[error("{error}")]
pub struct ExecutionError {
    pub job_id: JobId,
    pub time: DateTime<Utc>,
    pub error: Arc<JobError>,
}

impl ExecutionError {
    pub fn new(job_id: JobId, error: JobError) -> Self {
        let time = Utc::now();
        Self {
            job_id,
            time,
            error: Arc::new(error),
        }
    }
}
