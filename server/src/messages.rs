//! Messages gossiped via rumors.

use std::io;

use chrono::{DateTime, Utc};
use rumors::{
    Version,
    borsh::{BorshDeserialize, BorshSerialize},
};
use sled_hardware_types::BaseboardId;
use sush_api::JobStartParams;
use uuid::Uuid;

use sush_common::jobs::{JobId, ProcessError, SessionId, VerifiedJob};

#[derive(BorshDeserialize, BorshSerialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct RequestId(pub Uuid);

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Message {
    Request(Request),
    Event(
        #[borsh(
            serialize_with = "borsh_serialize_baseboard_id",
            deserialize_with = "borsh_deserialize_baseboard_id"
        )]
        BaseboardId,
        Event,
    ),
}

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize)]
pub enum Request {
    Session(SessionRequest),
    Job(SessionId, JobRequest),
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
            serialize_with = "borsh_serialize_datetime",
            deserialize_with = "borsh_deserialize_datetime"
        )]
        DateTime<Utc>,
    ),
    JobEnd(JobId),
    JobError(ProcessError),
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

pub(crate) fn borsh_serialize_baseboard_id<W: io::Write>(
    value: &BaseboardId,
    writer: &mut W,
) -> io::Result<()> {
    value.part_number.serialize(writer)?;
    value.serial_number.serialize(writer)
}

pub(crate) fn borsh_deserialize_baseboard_id<R: io::Read>(
    reader: &mut R,
) -> io::Result<BaseboardId> {
    Ok(BaseboardId {
        part_number: String::deserialize_reader(reader)?,
        serial_number: String::deserialize_reader(reader)?,
    })
}

/// Serialize a `DateTime<Utc>` as a whole-seconds count plus a subsecond
/// nanosecond remainder. Borsh has no native instant type, and this pair
/// round-trips losslessly without depending on chrono's wire format.
pub(crate) fn borsh_serialize_datetime<W: io::Write>(
    value: &DateTime<Utc>,
    writer: &mut W,
) -> io::Result<()> {
    value.timestamp().serialize(writer)?;
    value.timestamp_subsec_nanos().serialize(writer)
}

pub(crate) fn borsh_deserialize_datetime<R: io::Read>(reader: &mut R) -> io::Result<DateTime<Utc>> {
    let secs = i64::deserialize_reader(reader)?;
    let nanos = u32::deserialize_reader(reader)?;
    DateTime::from_timestamp(secs, nanos).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "timestamp out of range for DateTime<Utc>",
        )
    })
}
