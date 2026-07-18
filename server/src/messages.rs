//! Messages gossiped via rumors.

use chrono::{DateTime, Utc};
use rumors::{
    Version,
    borsh::{BorshDeserialize, BorshSerialize},
};
use sled_hardware_types::BaseboardId;
use sush_api::JobStartParams;
use uuid::Uuid;

use sush_common::borsh::{
    borsh_de_baseboard_id, borsh_de_datetime, borsh_ser_baseboard_id, borsh_ser_datetime,
};
use sush_common::jobs::{JobId, ProcessError, SessionId, VerifiedJob};

#[derive(BorshDeserialize, BorshSerialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct RequestId(pub Uuid);

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Message {
    Request(Request),
    Event(
        #[borsh(
            serialize_with = "borsh_ser_baseboard_id",
            deserialize_with = "borsh_de_baseboard_id"
        )]
        BaseboardId,
        Event,
    ),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Request {
    Session(Box<SessionRequest>),
    Job(Box<JobRequest>),
}

impl Request {
    pub fn session(request: SessionRequest) -> Self {
        Self::Session(Box::new(request))
    }

    pub fn job(request: JobRequest) -> Self {
        Self::Job(Box::new(request))
    }
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum SessionRequest {
    Start(SessionId),
    Stop(SessionId),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum JobRequest {
    Start(VerifiedJob, JobStartParams),
    Stop(JobId),
    Attach(JobId),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Event {
    Job(JobEvent),
    Error(Error),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum JobEvent {
    JobStart(
        JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        DateTime<Utc>,
    ),
    JobEnd(JobId, Result<i32, ProcessError>),
    JobError(JobId, ProcessError),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Error {
    ConcurrentSessions {
        own_session: SessionId,
        own_version: Version,
        incoming_session: SessionId,
        incoming_version: Version,
    },
}
