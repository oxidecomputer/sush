// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job server errors.

use std::ffi::c_int;
use std::fmt::Display;
use std::io;
use std::path::{Path, PathBuf};

use dropshot::{ClientErrorStatusCode, HttpError};
use thiserror::Error;

use sush_api::ErrorCode;
use sush_common::authn::{Challenge, Nonce};
use sush_common::interactive::InteractiveJobError;
use sush_common::jobs::{ExecutionError, JobId, JobOutputHash, SessionId};
use sush_common::keys::{KeyError, KeyId};

/// Prefix an I/O error with `what` we were doing.
pub fn io_context(what: impl Display, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{what}: {error}"))
}

/// Check the result of a C function that returns an error number rather
/// than setting the global `errno`, as libcontract and posix_spawn(3C) do.
pub fn check_errno(what: impl Display, errno: c_int) -> io::Result<()> {
    if errno == 0 {
        Ok(())
    } else {
        Err(io_context(what, io::Error::from_raw_os_error(errno)))
    }
}

/// What went wrong processing a client job request.
#[derive(Debug, Error)]
pub enum JobError {
    #[error("Attach access to this session's jobs has not been granted")]
    AttachDenied,
    #[error("Internal communications channel was unexpectedly closed")]
    ChannelClosed,
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
    #[error("Command must not start with `-`")]
    InvalidCommand,
    #[error("Interactive jobs must target exactly one sled")]
    InteractiveTarget,
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
    #[error("Only one session may be running at a time")]
    MultipleSessions,
    #[error("No sled this job targets is reachable")]
    NoReachableTarget,
    #[error("No current session, try `session start`")]
    NoSession,
    #[error("Job `{0}` is not the session's next job")]
    NotNextJob(JobId),
    #[error("Only the session starter may manage the session")]
    NotSessionStarter,
    #[error("Session `{0}` is no longer current, try `session attach` or `session start`")]
    SessionNotCurrent(SessionId),
    #[error("Job output hash mismatch, file may be corrupt")]
    OutputHashMismatch(JobId, JobOutputHash),
    #[error("Job output file missing or unavailable")]
    OutputFileMissing(JobId),
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
    #[error("Too many simultaneous output requests ({0})")]
    TooManyOutputRequests(usize),
    #[error("Unauthorized request")]
    Unauthorized(Nonce),
    #[error("Which sled is in cubby {0} has not yet been reported")]
    UnknownCubby(u8),
    #[error("Unable to wait for job end")]
    Wait,
    #[error("The provided session ID is invalid")]
    InvalidSessionId,
    #[error("Job signature verification failed: {0}")]
    UnverifiedJob(KeyError),
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
            TooManyOutputRequests(_) => HttpError::for_client_error(
                None,
                ClientErrorStatusCode::TOO_MANY_REQUESTS,
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
            AttachDenied | NotSessionStarter => {
                HttpError::for_client_error(None, ClientErrorStatusCode::FORBIDDEN, message)
            }
            IdentityNotFound(_) | JobNotFound(_) | OutputFileMissing(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::NOT_FOUND, message)
            }
            NoSession => HttpError::for_client_error(
                Some(ErrorCode::NoSession.to_string()),
                ClientErrorStatusCode::NOT_FOUND,
                message,
            ),
            SessionNotCurrent(_) => HttpError::for_client_error(
                Some(ErrorCode::SessionNotCurrent.to_string()),
                ClientErrorStatusCode::GONE,
                message,
            ),
            DuplicateJobId(_) | InteractiveTarget | InvalidCommand | Json(_) | MultipleSessions
            | InvalidSessionId | NoReachableTarget | UnknownCubby(_) | UnverifiedJob(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::BAD_REQUEST, message)
            }
            NotNextJob(_) => {
                HttpError::for_client_error(None, ClientErrorStatusCode::CONFLICT, message)
            }
        }
    }
}
