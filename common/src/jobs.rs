// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
use rlimit::Resource;
use schemars::schema::{Schema, SchemaObject};
use schemars::{JsonSchema, SchemaGenerator};
use serde::de::{Deserializer, Error as DeserializeError, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use sled_hardware_types::{BaseboardId, BaseboardIdParseError};
use thiserror::Error;

use crate::borsh::{
    borsh_de_datetime, borsh_de_hash, borsh_de_target, borsh_ser_datetime, borsh_ser_hash,
    borsh_ser_target,
};
use crate::interactive::InteractiveJobError;
use crate::keys::{KeyId, Signed, ToBeSigned, Verified};
use crate::targets::{Cubbies, Target};

codephrase_newtype! {
    /// A globally unique identifier for a job within a session.
    #[derive(
        BorshDeserialize,
        BorshSerialize,
        Copy,
        Clone,
        Deserialize,
        Eq,
        Hash,
        JsonSchema,
        Ord,
        PartialEq,
        PartialOrd,
        Serialize,
    )]
    pub struct JobId = Truncated;
}

impl slog::Value for JobId {
    fn serialize(
        &self,
        _rec: &slog::Record,
        key: slog::Key,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        serializer.emit_str(key, &self.0.to_string())
    }
}

impl From<&JobId> for JobId {
    fn from(value: &JobId) -> Self {
        *value
    }
}

codephrase_newtype! {
    /// A globally unique identifier for a session.
    #[derive(
        BorshDeserialize,
        BorshSerialize,
        Copy,
        Clone,
        Deserialize,
        Eq,
        Hash,
        JsonSchema,
        Ord,
        PartialEq,
        PartialOrd,
        Serialize,
    )]
    pub struct SessionId = Truncated;
}

impl SessionId {
    pub fn first_job_id(&self) -> JobId {
        JobId::from_hash(hash(&self.0.to_be_bytes()))
    }

    pub fn next_job_id(&self, last_job: &LastJob) -> JobId {
        JobId::from_hash(match last_job {
            LastJob::None => hash(&[b"None", self.0.to_be_bytes().as_slice()].concat()),
            LastJob::Some(job) => hash(&[b"Some", job.to_be_signed().as_slice()].concat()),
            LastJob::Burned(job_id) => hash(&[b"Burned", job_id.to_be_bytes().as_slice()].concat()),
        })
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
    /// The key that started the session, where known. Client-side
    /// trackers leave it `None`. Servers record the verified starter.
    started_by: Option<KeyId>,
}

impl Session {
    pub fn new(session_id: SessionId) -> Self {
        Self {
            session_id,
            last_job: LastJob::None,
            started_by: None,
        }
    }

    pub fn started(session_id: SessionId, actor: KeyId) -> Self {
        Self {
            session_id,
            last_job: LastJob::None,
            started_by: Some(actor),
        }
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn started_by(&self) -> Option<&KeyId> {
        self.started_by.as_ref()
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
    /// The sleds this job runs on.
    #[borsh(
        serialize_with = "borsh_ser_target",
        deserialize_with = "borsh_de_target"
    )]
    #[serde(default, skip_serializing_if = "Target::is_all")]
    pub target: Target,
}

fn is_false(x: &bool) -> bool {
    !x
}

impl JobStartRequest {
    const TYPE_NAME: &[u8] = b"sush_common::jobs::JobStartRequest";

    pub fn new<S: AsRef<str>>(
        job_id: JobId,
        command: S,
        interactive: bool,
        target: Target,
    ) -> Self {
        Self {
            job_id,
            command: command.as_ref().to_string(),
            interactive,
            target,
        }
    }

    /// Interactive jobs run only on their single named baseboard.
    pub fn runs_on(&self, baseboard: &BaseboardId, cubbies: &Cubbies) -> bool {
        if self.interactive {
            self.target.single_baseboard() == Some(baseboard)
        } else {
            self.target.includes(baseboard, cubbies)
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

    pub fn target(&self) -> &Target {
        &self.target
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
            target,
        } = self;
        hash_with_len(Self::TYPE_NAME);
        hash_with_len(&job_id.to_be_bytes());
        hash_with_len(command.as_bytes());
        hash_with_len(if *interactive { &[1] } else { &[0] });
        hash_with_len(target.to_string().as_bytes());
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
        /// The key that requested the cancellation.
        actor: KeyId,
    },
    Queued {
        job_id: JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        time_queued: DateTime<Utc>,
        /// The key that submitted the job.
        actor: KeyId,
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
    /// Whether this status can ever change again.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Cancelled { .. } | Self::Error { .. } | Self::Stopped { .. }
        )
    }

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
    /// Clamp each limit to the default ceiling. Limits arrive as
    /// unsigned request parameters, which may narrow the server's
    /// limits but never widen them.
    pub fn clamp(self) -> Self {
        let ceiling = Self::default();
        Self {
            max_cpu: self.max_cpu.min(ceiling.max_cpu),
            max_mem: self.max_mem.min(ceiling.max_mem),
            max_fsize: self.max_fsize.min(ceiling.max_fsize),
        }
    }

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

/// The default limits are also the ceilings: see [`JobLimits::clamp`].
impl Default for JobLimits {
    fn default() -> Self {
        JobLimits {
            max_cpu: 3600,
            max_mem: 8 * GB,
            max_fsize: 10 * GB,
        }
    }
}

/// Attach access to a session's interactive jobs. The session starter
/// always has read-write access. Guests have what they were granted.
/// Read-write means co-driving a shell the job signature authorized,
/// so who deserves it is deployment policy. Recorded output is not
/// gated: it is the customer's data, readable by any authenticated key.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    Eq,
    JsonSchema,
    PartialEq,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    #[default]
    ReadOnly,
    ReadWrite,
}

impl Access {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::ReadWrite => "read-write",
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::targets::SledId;

    /// Interactive jobs run only on their single named baseboard.
    #[test]
    fn interactive_targets() {
        let sled = |serial: &str| BaseboardId {
            part_number: "913".to_string(),
            serial_number: serial.to_string(),
        };
        let me = sled("me");
        let cubbies = Cubbies::from([(14, me.clone())]);
        let job = |interactive, target| {
            JobStartRequest::new(JobId::random(), "true", interactive, target)
        };
        let just_me = Target::Sleds(vec![SledId::Baseboard(me.clone())]);
        assert!(job(true, just_me.clone()).runs_on(&me, &cubbies));
        assert!(job(false, just_me).runs_on(&me, &cubbies));
        assert!(!job(true, Target::All).runs_on(&me, &cubbies));
        assert!(job(false, Target::All).runs_on(&me, &cubbies));
        let my_cubby = Target::Sleds(vec![SledId::Cubby(14)]);
        assert!(!job(true, my_cubby.clone()).runs_on(&me, &cubbies));
        assert!(job(false, my_cubby).runs_on(&me, &cubbies));
    }

    /// Requested limits may narrow the default ceiling, never widen it.
    #[test]
    fn limits_clamp() {
        let narrowed = JobLimits {
            max_cpu: 1,
            max_mem: GB,
            max_fsize: GB,
        };
        assert_eq!(narrowed.clone().clamp(), narrowed);
        let widened = JobLimits {
            max_cpu: u64::MAX,
            max_mem: u64::MAX,
            max_fsize: u64::MAX,
        };
        assert_eq!(widened.clamp(), JobLimits::default());
    }
}
