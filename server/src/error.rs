//! Job server errors.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dropshot::{ClientErrorStatusCode, HttpError};
use thiserror::Error;

use sush_common::authn::{Challenge, Nonce};
use sush_common::jobs::{JobId, JobOutputHash};
use sush_common::keys::{KeyError, KeyId};
use sush_common::session::SessionError;

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
    #[error("Identity mismatch, expected `{interactive}`, found `{authn}`")]
    IdentityMismatch { interactive: KeyId, authn: KeyId },
    #[error("Invalid command `{0}`, must not start with `-`")]
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
    #[error("Can't kill job `{0}`")]
    Shutdown(JobId),
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
    Recv(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("Interactive session error: {0}")]
    Session(#[from] SessionError),
    #[error(transparent)]
    Slice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Task(#[from] tokio::task::JoinError),
    #[error("Unauthorized request")]
    Unauthorized(Nonce),
    #[error("Unable to wait for job end")]
    Wait,
}

impl JobError {
    pub fn closed<E>(_err: E) -> Self {
        Self::ChannelClosed
    }

    pub fn unauthorized() -> Self {
        Self::Unauthorized(Nonce::generate())
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
            | IdentityMismatch { .. }
            | Io { .. }
            | NoSuchNonce(_)
            | OutputHashMismatch(_, _)
            | PublicKeyNotFound(_)
            | PublicKeyMismatch(_)
            | PublicKeyRevoked { .. }
            | Recv(_)
            | Shutdown(_)
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
            InvalidCommand(_) | InvalidJobId(_) | Json(_) | CertChainTooLong | MissingCert(_)
            | OutputPending => {
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
