// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Messages gossiped via rumors.

use chrono::{DateTime, Utc};
use rumors::{
    Version,
    borsh::{BorshDeserialize, BorshSerialize},
};
use sled_hardware_types::BaseboardId;
use thiserror::Error;
use uuid::Uuid;
use x509_cert::Certificate;

use sush_api::JobStartParams;
use sush_common::borsh::{
    borsh_de_baseboard_id, borsh_de_cert, borsh_de_datetime, borsh_ser_baseboard_id,
    borsh_ser_cert, borsh_ser_datetime,
};
use sush_common::jobs::JobOutputState;
use sush_common::jobs::{JobId, ProcessError, SessionId, SignedJob};
use sush_common::keys::KeyId;

#[derive(BorshDeserialize, BorshSerialize, Copy, Clone, Debug, Eq, PartialEq)]
pub struct RequestId(pub Uuid);

/// Once a message schema has shipped, it is frozen, since any changes
/// could break decoding of *existing* messages. Each version gets its
/// own module; everything defined there and all of their dependencies
/// (e.g., types shared with the HTTP API, etc.) become part of the frozen
/// version, whose Borsh encoding must not change. New versions must
/// implement `TryInto` to convert old messages into compatible new ones;
/// old servers must tolerate or ignore new messages they can't decode
/// (TODO: verify and implement that policy).
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub enum VersionedMessage {
    V0(v0::Message),
}

pub mod v0 {
    use super::*;

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
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

    impl From<Message> for VersionedMessage {
        fn from(message: Message) -> Self {
            Self::V0(message)
        }
    }

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    pub enum Request {
        Cert(Box<CertRequest>),
        Session(Box<SessionRequest>),
        Job(Box<JobRequest>),
    }

    impl Request {
        pub fn cert(request: CertRequest) -> Self {
            Self::Cert(Box::new(request))
        }

        pub fn session(request: SessionRequest) -> Self {
            Self::Session(Box::new(request))
        }

        pub fn job(request: JobRequest) -> Self {
            Self::Job(Box::new(request))
        }
    }

    /// Certificates are PEM-encoded X.509
    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    #[allow(clippy::large_enum_variant)]
    pub enum CertRequest {
        Import(
            #[borsh(serialize_with = "borsh_ser_cert", deserialize_with = "borsh_de_cert")]
            Certificate,
        ),
        Revoke(
            KeyId,
            #[borsh(
                serialize_with = "borsh_ser_datetime",
                deserialize_with = "borsh_de_datetime"
            )]
            DateTime<Utc>,
        ),
    }

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    pub enum SessionRequest {
        Start(SessionId),
        Stop(SessionId),
        Skip(SessionId, JobId),
    }

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    pub enum JobRequest {
        Start(SignedJob, JobStartParams),
        Stop(JobId),
    }

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    pub enum Event {
        Job(JobEvent),
        Error(Error),
    }

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
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

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, Error, PartialEq)]
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
}

#[cfg(test)]
mod wire_format {
    use super::v0::*;
    use super::*;

    /// Serialize a message and compare against a pinned hex snapshot.
    ///
    /// If this test fails, STOP! You have changed the gossip wire format!
    /// Because borsh enum tags are positional, reordering or inserting
    /// variants (or editing any struct these messages contain) silently
    /// changes how *old* bytes decode. Either revert the schema change
    /// or introduce a new [`VersionedMessage`] variant and re-pin these
    /// snapshots.
    #[track_caller]
    fn assert_wire_format(message: VersionedMessage, expected: &[u8]) {
        let bytes = borsh::to_vec(&message).unwrap();
        assert_eq!(bytes, expected, "gossip wire format changed: {bytes:02x?}");
        let decoded: VersionedMessage = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded, message, "wire format should round-trip");
    }

    #[test]
    fn session_start_request() {
        let msg: VersionedMessage = Message::Request(Request::session(SessionRequest::Start(
            SessionId::from("abandon-ability"),
        )))
        .into();
        assert_wire_format(msg, b"\x00\x00\x01\x00\x0f\x00\x00\x00abandon-ability");
    }

    #[test]
    fn session_stop_request() {
        let msg: VersionedMessage = Message::Request(Request::session(SessionRequest::Stop(
            SessionId::from("abandon-ability"),
        )))
        .into();
        assert_wire_format(msg, b"\x00\x00\x01\x01\x0f\x00\x00\x00abandon-ability");
    }

    // TODO: snapshot more messages
}
