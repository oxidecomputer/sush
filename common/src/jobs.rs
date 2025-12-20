//! Signed job requests.

use std::convert::Infallible;
use std::fmt;
use std::io::Error as IoError;
use std::ops::Deref;
use std::str::FromStr;

use bytesize::GB;
use chrono::{DateTime, TimeDelta, Utc};
use rlimit::Resource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::certs::{KeyId, Signed, ToBeSigned, Verified};

#[derive(Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd)]
pub struct JobId(String);

impl Deref for JobId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for JobId {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl<S: AsRef<str>> From<S> for JobId {
    fn from(s: S) -> Self {
        Self(s.as_ref().to_string())
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

    pub fn job_id(&self) -> &JobId {
        &self.job_id
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
        hash(self.job_id.as_ref());
        hash(self.command.as_bytes());
        hash(key_id.as_bytes());
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

impl JobStatus {
    pub fn time_elapsed(&self) -> Option<TimeDelta> {
        match self {
            Self::NotFound | Self::Reserved { .. } => None,
            Self::Started { time_started, .. } => Some(Utc::now() - time_started),
            Self::Ended {
                time_started,
                time_ended,
                ..
            } => Some(*time_ended - time_started),
        }
    }
}

/// Limits on job processes.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct JobLimits {
    /// Maximum CPU use in seconds.
    pub max_cpu: u64,

    /// Maximum size of address space in bytes.
    pub max_mem: u64,

    /// Maximum file size in bytes.
    pub max_fsize: u64,
}

impl JobLimits {
    pub fn apply(&self) -> Result<(), IoError> {
        let Self {
            max_cpu,
            max_mem,
            max_fsize,
        } = *self;
        self.set_limit(Resource::CPU, max_cpu)?;
        self.set_limit(Resource::AS, max_mem)?;
        self.set_limit(Resource::FSIZE, max_fsize)?;
        Ok(())
    }

    fn set_limit(&self, resource: Resource, value: u64) -> Result<(), IoError> {
        let (_soft, hard) = resource.get()?;
        resource.set(value.min(hard), hard)
    }
}

/// Default limits should be increased as needed.
/// But note that if `fsize` > `SQLITE_LIMIT_LENGTH`,
/// job output may be truncated.
impl Default for JobLimits {
    fn default() -> Self {
        JobLimits {
            max_cpu: 60,
            max_mem: GB,
            max_fsize: GB,
        }
    }
}
