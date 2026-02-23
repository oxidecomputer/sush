//! Signed job requests.

use std::convert::Infallible;
use std::fmt;
use std::io::Error as IoError;
use std::ops::{Deref, Not};
use std::str::FromStr;

use blake3::Hash;
use bytesize::GB;
use chrono::{DateTime, TimeDelta, Utc};
use rlimit::Resource;
use rusqlite::Result as SqlResult;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use schemars::schema::{Schema, SchemaObject};
use schemars::{JsonSchema, SchemaGenerator};
use serde::de::{Deserializer, Error as DeserializeError, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::certs::{KeyId, Signed, ToBeSigned, Verified};

#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
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

impl From<&Self> for JobId {
    fn from(other: &Self) -> Self {
        other.to_owned()
    }
}

impl<S: AsRef<str>> From<S> for JobId {
    fn from(s: S) -> Self {
        Self(s.as_ref().to_string())
    }
}

impl FromSql for JobId {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Ok(Self::from(value.as_str()?))
    }
}

impl ToSql for JobId {
    fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.clone()))
    }
}

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
    #[serde(default, skip_serializing_if = "Not::not")]
    pub interactive: bool,
}

impl JobStartRequest {
    pub fn new<S: AsRef<str>>(job_id: JobId, command: S, interactive: bool) -> Self {
        Self {
            job_id,
            command: command.as_ref().to_string(),
            interactive,
        }
    }

    pub fn job_id(&self) -> &JobId {
        &self.job_id
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn is_interactive(&self) -> bool {
        self.interactive
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

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub enum JobStatus {
    Reserved {
        job_id: JobId,
        time_reserved: DateTime<Utc>,
    },
    Started {
        job: VerifiedJob,
        time_reserved: DateTime<Utc>,
        time_started: DateTime<Utc>,
        stdout_len: u64,
        stderr_len: u64,
    },
    Ended {
        job: VerifiedJob,
        time_reserved: DateTime<Utc>,
        time_started: DateTime<Utc>,
        time_ended: DateTime<Utc>,
        status: Option<i32>,
        stdout_len: u64,
        stderr_len: u64,
        stdout_hash: JobOutputHash,
        stderr_hash: JobOutputHash,
    },
}

impl JobStatus {
    pub fn time_elapsed(&self) -> Option<TimeDelta> {
        match self {
            Self::Reserved { .. } => None,
            Self::Started { time_started, .. } => Some(Utc::now() - time_started),
            Self::Ended {
                time_started,
                time_ended,
                ..
            } => Some(*time_ended - time_started),
        }
    }

    pub fn job_id(&self) -> &JobId {
        match self {
            Self::Reserved { job_id, .. } => job_id,
            Self::Started { job, .. } | Self::Ended { job, .. } => job.job_id(),
        }
    }
}

/// BLAKE3 hash of job output, used as a checksum.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct JobOutputHash(
    #[serde(serialize_with = "hash_ser", deserialize_with = "hash_de")]
    #[schemars(schema_with = "hash_schema")]
    Hash,
);

impl Deref for JobOutputHash {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Hash> for JobOutputHash {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl fmt::Display for JobOutputHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromSql for JobOutputHash {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Ok(Self::from(
            Hash::from_hex(value.as_str()?).map_err(|e| FromSqlError::Other(Box::new(e)))?,
        ))
    }
}

impl ToSql for JobOutputHash {
    fn to_sql(&self) -> SqlResult<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.to_string()))
    }
}

fn hash_ser<S>(hash: &Hash, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    ser.serialize_str(&hash.to_string())
}

fn hash_de<'de, D>(de: D) -> Result<Hash, D::Error>
where
    D: Deserializer<'de>,
{
    struct HashVisitor;

    impl<'de> Visitor<'de> for HashVisitor {
        type Value = Hash;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a hex encoded 32 byte BLAKE3 hash")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: DeserializeError,
        {
            Hash::from_hex(v).map_err(DeserializeError::custom)
        }
    }

    de.deserialize_str(HashVisitor)
}

fn hash_schema(g: &mut SchemaGenerator) -> Schema {
    let mut schema: SchemaObject = <String>::json_schema(g).into();
    schema.format = Some("hex encoded hash (32 bytes)".to_owned());
    schema.into()
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
impl Default for JobLimits {
    fn default() -> Self {
        JobLimits {
            max_cpu: 60,
            max_mem: GB,
            max_fsize: 10 * GB,
        }
    }
}

/// Either the standard output or standard error of a job.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobOutputStream {
    Stdout,
    Stderr,
}

impl JobOutputStream {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl fmt::Display for JobOutputStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Error)]
#[error("invalid output stream, must be one of `stdout` or `stderr`")]
pub struct InvalidOutputStream;

impl FromStr for JobOutputStream {
    type Err = InvalidOutputStream;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stdout" => Ok(Self::Stdout),
            "stderr" => Ok(Self::Stderr),
            _ => Err(InvalidOutputStream),
        }
    }
}
