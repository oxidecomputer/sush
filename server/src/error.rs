//! Job server errors.

use std::path::{Path, PathBuf};

use dropshot::{ClientErrorStatusCode, HttpError};
use thiserror::Error;

use sush_common::authn::{Challenge, Nonce};
use sush_common::interactive::InteractiveJobError;
use sush_common::jobs::{ExecutionError, JobId, JobOutputHash, SessionId};
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
    #[error("Duplicate job ID `{0}`")]
    DuplicateJobId(JobId),
    #[error("Execution error: {0}")]
    Execution(#[from] ExecutionError),
    #[error("File I/O error accessing `{path}`: {error}")]
    FileIo {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("Identity not found")]
    IdentityNotFound(KeyId),
    #[error("Interactive session error: {0}")]
    InteractiveJob(#[from] InteractiveJobError),
    #[error("Invalid command `{0}`, must not start with `-`")]
    InvalidCommand(String),
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
    #[error("Can't find certificate for key `{0}`")]
    MissingCert(KeyId),
    #[error("Only one session may be running at a time")]
    MultipleSessions,
    #[error("No current session")]
    NoSession,
    #[error("Session `{0}` is no longer current")]
    SessionNotCurrent(SessionId),
    #[error("Job output hash mismatch, file may be corrupt")]
    OutputHashMismatch(JobId, JobOutputHash),
    #[error("Output too big, please use range requests")]
    OutputTooBig,
    #[error("Public key for `{0}` does not match stored key")]
    PublicKeyMismatch(KeyId),
    #[error("Public key `{0}` not found")]
    PublicKeyNotFound(KeyId),
    #[error(transparent)]
    Slice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("Wait timed out")]
    Timeout,
    #[error("Too many certificates ({0})")]
    TooManyCerts(usize),
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
            InteractiveJob(error) => HttpError::for_client_error(
                None,
                ClientErrorStatusCode::NOT_FOUND,
                error.to_string(),
            ),
            Timeout => HttpError::for_client_error(
                None,
                ClientErrorStatusCode::REQUEST_TIMEOUT,
                String::from("Wait timed out"),
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
            IdentityNotFound(_) | JobNotFound(_) | NoSession | SessionNotCurrent(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::NOT_FOUND, message)
            }
            CertChainTooLong | DuplicateJobId(_) | InvalidCommand(_) | Json(_) | MissingCert(_)
            | MultipleSessions | TooManyCerts(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::BAD_REQUEST, message)
            }
        }
    }
}
