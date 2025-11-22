//! Signed job requests.

use std::ops::Deref;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::certs::{KeyId, Signed, ToBeSigned, Verified};

#[derive(Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd)]
pub struct JobId(Uuid);

impl JobId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for JobId {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for JobId {
    type Target = Uuid;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for JobId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::from_str(s)?))
    }
}

impl_to_from_sql_and_serde!(JobId);

/// The response to a job reservation request.
#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct JobsReserved {
    /// Fresh, globally unique job IDs.
    pub job_ids: Vec<JobId>,

    /// The server's idea of the time at which the job IDs were reserved.
    pub time_reserved: DateTime<Utc>,
}

/// A request to run the given `command` in the slot reserved by `job_id`.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct JobStartRequest {
    pub job_id: JobId,
    pub command: String,
}

impl JobStartRequest {
    pub fn new<S: AsRef<str>>(job_id: JobId, command: S) -> Self {
        Self {
            job_id,
            command: command.as_ref().to_string(),
        }
    }

    pub fn job_id(&self) -> JobId {
        self.job_id
    }

    pub fn command(&self) -> &str {
        &self.command
    }
}

impl ToBeSigned for JobStartRequest {
    /// Generate a SHA-256 hash over the fields of `self`.
    fn to_be_signed(&self, key_id: &KeyId) -> Vec<u8> {
        let mut hasher = Sha256::default();
        let mut hash = |data: &[u8]| {
            hasher.update((data.len() as u64).to_be_bytes());
            hasher.update(data);
        };
        hash(b"JobStartRequest");
        hash(self.job_id.as_bytes());
        hash(self.command.as_bytes());
        hash(key_id.as_slice());
        hasher.finalize().to_vec()
    }
}

pub type SignedJob = Signed<JobStartRequest>;
pub type VerifiedJob = Verified<JobStartRequest>;

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub enum JobStatus {
    NotFound,
    Reserved {
        job_id: JobId,
        time_reserved: DateTime<Utc>,
    },
    Started {
        job: SignedJob,
        time_reserved: DateTime<Utc>,
        time_started: DateTime<Utc>,
    },
    Ended {
        job: SignedJob,
        time_reserved: DateTime<Utc>,
        time_started: DateTime<Utc>,
        time_ended: DateTime<Utc>,
        status: Option<i32>,
        stdout_len: i32,
        stderr_len: i32,
    },
}
