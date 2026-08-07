//! Signed job requests.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Error as IoError;
use std::ops::Deref;
use std::str::FromStr;

use blake3::{Hash, Hasher, hash};
use borsh::{BorshDeserialize, BorshSerialize};
use bytesize::GB;
use chrono::{DateTime, TimeDelta, Utc};
use crypto_bigint::U256;
use rlimit::Resource;
use schemars::schema::{Schema, SchemaObject};
use schemars::{JsonSchema, SchemaGenerator};
use serde::de::{Deserializer, Error as DeserializeError, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use sled_hardware_types::{BaseboardId, BaseboardIdParseError};
use thiserror::Error;

use crate::borsh::{
    borsh_de_datetime, borsh_de_hash, borsh_de_job_id, borsh_ser_datetime, borsh_ser_hash,
};
use crate::codephrases::{
    InvalidCodephrase, WORD_SEPARATOR, decode_phrase, generate_id, id_phrase,
};
use crate::interactive::InteractiveJobError;
use crate::keys::{Signed, ToBeSigned, Verified};

/// A globally unique identifier for a job within a session.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(try_from = "String")]
pub struct JobId(#[borsh(deserialize_with = "borsh_de_job_id")] String);

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

impl From<&Self> for JobId {
    fn from(other: &Self) -> Self {
        other.to_owned()
    }
}

impl From<U256> for JobId {
    fn from(value: U256) -> Self {
        Self(id_phrase(value).join(WORD_SEPARATOR))
    }
}

impl FromStr for JobId {
    type Err = InvalidCodephrase;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let p = id_phrase(decode_phrase(s)?).join(WORD_SEPARATOR);
        if p == *s {
            Ok(Self(p))
        } else {
            Err(InvalidCodephrase)
        }
    }
}

impl TryFrom<String> for JobId {
    type Error = InvalidCodephrase;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        JobId::from_str(&s)
    }
}

impl slog::Value for JobId {
    fn serialize(
        &self,
        _rec: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str(key, self)
    }
}

/// A globally unique identifier for a session.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct SessionId(String);

#[allow(clippy::new_without_default)]
impl SessionId {
    pub fn new() -> Self {
        Self(generate_id())
    }

    pub fn first_job_id(&self) -> JobId {
        U256::from_be_slice(hash(self.0.as_bytes()).as_bytes()).into()
    }

    pub fn next_job_id(&self, last_job: &LastJob) -> JobId {
        U256::from_be_slice(
            match last_job {
                LastJob::None => hash(&[b"None", self.0.as_bytes()].concat()),
                LastJob::Some(job) => hash(&[b"Some", job.to_be_signed().as_slice()].concat()),
                LastJob::Burned(job_id) => hash(&[b"Burned", job_id.as_bytes()].concat()),
            }
            .as_bytes(),
        )
        .into()
    }
}

impl Deref for SessionId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&Self> for SessionId {
    fn from(other: &Self) -> Self {
        other.to_owned()
    }
}

impl<S: AsRef<str>> From<S> for SessionId {
    fn from(s: S) -> Self {
        Self(s.as_ref().to_string())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub enum LastJob {
    #[default]
    None,
    Some(SignedJob),
    Burned(JobId),
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct Session {
    session_id: SessionId,
    last_job: LastJob,
}

impl Session {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            last_job: LastJob::None,
        }
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn into_session_id(self) -> SessionId {
        self.session_id
    }

    pub fn last_job(&self) -> LastJob {
        self.last_job.clone()
    }

    pub fn job_started(&mut self, job: SignedJob) {
        self.last_job = LastJob::Some(job)
    }

    pub fn skip_job(&mut self, job_id: JobId) {
        if job_id == self.next_job_id() {
            self.last_job = LastJob::Burned(job_id)
        }
    }

    pub fn next_job_id(&self) -> JobId {
        self.session_id.next_job_id(&self.last_job)
    }
}

/// A request to run the given `command` as `job_id`.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
)]
pub struct JobStartRequest {
    pub job_id: JobId,
    pub command: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub interactive: bool,
}

fn is_false(x: &bool) -> bool {
    !x
}

impl JobStartRequest {
    const TYPE_NAME: &[u8] = b"sush_common::jobs::JobStartRequest";

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

    pub fn interactive(&self) -> bool {
        self.interactive
    }
}

impl ToBeSigned for JobStartRequest {
    /// BLAKE3 hash over the fields of `self`.
    fn to_be_signed(&self) -> Vec<u8> {
        let mut hasher = Hasher::new();
        let mut hash_with_len = |data: &[u8]| {
            hasher.update(&(data.len() as u64).to_be_bytes());
            hasher.update(data);
        };

        let JobStartRequest {
            job_id,
            command,
            interactive,
        } = self;
        hash_with_len(Self::TYPE_NAME);
        hash_with_len(job_id.as_bytes());
        hash_with_len(command.as_bytes());
        hash_with_len(if *interactive { &[1] } else { &[0] });
        hasher.finalize().as_bytes().to_vec()
    }
}

pub type SignedJob = Signed<JobStartRequest>;
pub type VerifiedJob = Verified<JobStartRequest>;

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub enum JobStatus {
    Cancelled {
        job_id: JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        time_cancelled: DateTime<Utc>,
    },
    Queued {
        job_id: JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        time_queued: DateTime<Utc>,
    },
    Error {
        job_id: JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        time_error: DateTime<Utc>,
        error: ProcessError,
    },
    Started {
        job_id: JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        time_started: DateTime<Utc>,
    },
    Stopped {
        job_id: JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        time_started: DateTime<Utc>,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        time_stopped: DateTime<Utc>,
        result: Result<i32, ProcessError>,
        output: JobOutputState,
    },
}

pub type JobStatusMap = BTreeMap<BaseboardId, JobStatus>;
pub type JsonJobStatusMap = HashMap<String, JobStatus>;

/// This helper fallibly decodes a job status map from a JSON (string-keyed) map.
pub fn job_status_try_from_json_map(
    json_map: JsonJobStatusMap,
) -> Result<JobStatusMap, BaseboardIdParseError> {
    let mut new = JobStatusMap::new();
    for (k, v) in json_map.into_iter() {
        new.insert(BaseboardId::from_str(&k)?, v);
    }
    Ok(new)
}

/// And this one infallibly encodes a job status map into a JSON-compatible map.
pub fn job_status_to_json_map(status_map: JobStatusMap) -> JsonJobStatusMap {
    let mut new = HashMap::new();
    for (k, v) in status_map.into_iter() {
        new.insert(k.to_string(), v);
    }
    new
}

/// What went wrong running a job's process or interactive session.
///
/// We currently squash inner errors into strings to avoid excessive
/// derivation requirements, but may come to regret that decision.
#[derive(
    BorshSerialize,
    BorshDeserialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    Error,
    JsonSchema,
    PartialEq,
    Serialize,
)]
pub enum ProcessError {
    #[error("The fate of the process is unknown")]
    Unknown,
    #[error("Process killed with signal {0}")]
    Killed(i32),
    #[error("Interactive session error: {0}")]
    Interactive(String),
    #[error("Command must not start with `-`")]
    InvalidCommand,
    #[error("Job validation error: {0}")]
    InvalidJob(String),
    #[error("I/O error {what}: {error}")]
    Io { what: String, error: String },
    #[error("{stream} exceeded the output limit of {limit} bytes")]
    OutputLimitExceeded { stream: JobOutputStream, limit: u64 },
    #[error("Unable to join job process: {0}")]
    Join(String),
}

impl ProcessError {
    pub fn io(what: impl AsRef<str>, error: IoError) -> Self {
        Self::Io {
            what: what.as_ref().to_owned(),
            error: error.to_string(),
        }
    }
}

/// What went wrong running a job, and when (informative).
#[derive(Clone, Debug, Error)]
#[error("{error}")]
pub struct ExecutionError {
    pub job_id: JobId,
    pub time: DateTime<Utc>,
    pub error: ProcessError,
}

impl ExecutionError {
    pub fn interactive(job_id: JobId, error: InteractiveJobError) -> Self {
        let time = Utc::now();
        Self {
            job_id,
            time,
            error: ProcessError::Interactive(error.to_string()),
        }
    }

    pub fn io(job_id: JobId, what: impl AsRef<str>, error: IoError) -> Self {
        let time = Utc::now();
        Self {
            job_id,
            time,
            error: ProcessError::Io {
                what: what.as_ref().to_owned(),
                error: error.to_string(),
            },
        }
    }

    pub fn error(&self) -> ProcessError {
        self.error.clone()
    }
}

impl JobStatus {
    /// The most recent timestamp recorded for this status.
    pub fn time(&self) -> DateTime<Utc> {
        match self {
            Self::Cancelled { time_cancelled, .. } => *time_cancelled,
            Self::Queued { time_queued, .. } => *time_queued,
            Self::Error { time_error, .. } => *time_error,
            Self::Started { time_started, .. } => *time_started,
            Self::Stopped { time_stopped, .. } => *time_stopped,
        }
    }

    pub fn time_elapsed(&self) -> TimeDelta {
        match self {
            Self::Cancelled { .. } | Self::Error { .. } => TimeDelta::zero(),
            Self::Queued { time_queued, .. } => Utc::now() - time_queued,
            Self::Started { time_started, .. } => Utc::now() - time_started,
            Self::Stopped {
                time_started,
                time_stopped,
                ..
            } => *time_stopped - time_started,
        }
    }

    pub fn job_id(&self) -> &JobId {
        match self {
            Self::Cancelled { job_id, .. }
            | Self::Queued { job_id, .. }
            | Self::Error { job_id, .. }
            | Self::Started { job_id, .. }
            | Self::Stopped { job_id, .. } => job_id,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Started { .. })
    }
}

#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    Default,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
)]
pub struct JobOutputState {
    pub stdout_len: u64,
    pub stderr_len: u64,
    pub stdout_hash: JobOutputHash,
    pub stderr_hash: JobOutputHash,
}

/// BLAKE3 hash of job output, used as a checksum.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
)]
pub struct JobOutputHash(
    #[serde(serialize_with = "hash_ser", deserialize_with = "hash_de")]
    #[schemars(schema_with = "hash_schema")]
    #[borsh(serialize_with = "borsh_ser_hash", deserialize_with = "borsh_de_hash")]
    Hash,
);

impl Default for JobOutputHash {
    fn default() -> Self {
        Self::from(hash(&[]))
    }
}

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
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    Serialize,
    PartialEq,
)]
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
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
)]
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
