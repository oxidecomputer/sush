//! Messages gossiped via rumors.

use chrono::{DateTime, Utc};
use rumors::{
    Version,
    borsh::{BorshDeserialize, BorshSerialize},
};
use sled_hardware_types::BaseboardId;
use sush_api::JobStartParams;
use thiserror::Error;
use uuid::Uuid;

use sush_common::jobs::{JobId, ProcessError, SessionId, SignedJob};
use sush_common::{
    borsh::{borsh_de_baseboard_id, borsh_de_datetime, borsh_ser_baseboard_id, borsh_ser_datetime},
    jobs::JobOutputState,
};

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
    Start(SignedJob, JobStartParams),
    Stop(JobId),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Event {
    Job(JobEvent),
    Error(Error),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum JobEvent {
    Start(
        JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        DateTime<Utc>,
    ),
    Stop(
        JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        DateTime<Utc>,
        Result<i32, ProcessError>,
        JobOutputState,
    ),
    Error(
        JobId,
        #[borsh(
            serialize_with = "borsh_ser_datetime",
            deserialize_with = "borsh_de_datetime"
        )]
        DateTime<Utc>,
        ProcessError,
    ),
}

#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Error)]
pub enum Error {
    #[error(
        "Concurrent sessions detected: \
         ours is {own_session}@{own_version}, \
         incoming is {incoming_session}@{incoming_version}"
    )]
    ConcurrentSessions {
        own_session: SessionId,
        own_version: Version,
        incoming_session: SessionId,
        incoming_version: Version,
    },
}
