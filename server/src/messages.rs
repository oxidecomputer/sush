// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Messages gossiped via rumors.

use chrono::{DateTime, Utc};
use ciborium::{Value, de::from_reader as from_cbor, ser::into_writer as into_cbor};
use rumors::Version;
use serde::{Deserialize, Serialize};
use sled_hardware_types::BaseboardId;
use thiserror::Error;

use sush_api::JobStartParams;
use sush_common::authn::SignedLogin;
use sush_common::jobs::JobOutputState;
use sush_common::jobs::{Access, JobId, ProcessError, SessionId, SignedJob, SkipReason};
use sush_common::keys::KeyId;
use sush_common::version::VersionInfo;

use crate::format::{NoFormat, Versioned, Wire};

/// Once a message schema has shipped, it is frozen, since any changes
/// could break decoding of *existing* messages. Each version gets its
/// own module; everything defined there and all of their dependencies
/// (e.g., types shared with the HTTP API, etc.) become part of the frozen
/// version, whose serde shape on the gossip wire must not change. A
/// new version must convert [`From`] the old one; the
/// [`Wire`](crate::format::Wire) chain demands it. New variants must
/// keep this enum's encoding: a single-entry, text-keyed map. Older
/// sleds read an unrecognized text key as [`Unknown`](Self::Unknown)
/// and carry on, but an integer key or an array does not decode at
/// all, and a message that fails to decode aborts gossip sessions
/// instead of being ignored.
///
/// Updates go sled by sled, so mixed gossip networks exist for
/// the whole rollout. A message from a newer peer decodes as
/// [`Unknown`](Self::Unknown), and is ignored rather than poisoning
/// the link. Rumors relays its original bytes, so old sleds still
/// retain and spread messages they cannot read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedMessage {
    /// The initial message format.
    V0(v0::Message),

    Unknown {
        version: String,
        message: Vec<u8>,
    },
}

impl Serialize for VersionedMessage {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::V0(message) => {
                serializer.serialize_newtype_variant("VersionedMessage", 0, "V0", message)
            }
            // Emit what was received.
            Self::Unknown { message, .. } => {
                let value: Value = from_cbor(message.as_slice())
                    .expect("the bytes were encoded from a value this module decoded");
                value.serialize(serializer)
            }
        }
    }
}

impl<'de> Deserialize<'de> for VersionedMessage {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error as _, MapAccess, Visitor};

        struct VersionVisitor;

        impl<'de> Visitor<'de> for VersionVisitor {
            type Value = VersionedMessage;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a versioned message")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let Some(version) = map.next_key::<String>()? else {
                    return Err(A::Error::custom("a versioned message without a version"));
                };
                Ok(match version.as_str() {
                    "V0" => VersionedMessage::V0(map.next_value()?),
                    _ => {
                        let value: Value = map.next_value()?;
                        let whole = Value::Map(vec![(Value::Text(version.clone()), value)]);
                        let mut message = Vec::new();
                        into_cbor(&whole, &mut message).expect("writing to a Vec cannot fail");
                        VersionedMessage::Unknown { version, message }
                    }
                })
            }

            fn visit_str<E: serde::de::Error>(self, version: &str) -> Result<Self::Value, E> {
                let mut message = Vec::new();
                into_cbor(&version, &mut message).expect("writing to a Vec cannot fail");
                Ok(VersionedMessage::Unknown {
                    version: version.to_string(),
                    message,
                })
            }
        }

        deserializer.deserialize_any(VersionVisitor)
    }
}

pub mod v0 {
    use super::*;

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[allow(clippy::large_enum_variant)]
    pub enum Message {
        Request(Request),
        Event(BaseboardId, Event),
    }

    impl From<Message> for VersionedMessage {
        fn from(message: Message) -> Self {
            Self::V0(message)
        }
    }

    /// Version 0 is the initial wire format; see [`crate::format`].
    /// A later format converts up from this one infallibly, and the
    /// state machine handles only the latest.
    impl Versioned for Message {
        const VERSION: u16 = 0;
    }

    impl Wire for Message {
        type Previous = NoFormat;
    }

    impl From<NoFormat> for Message {
        fn from(none: NoFormat) -> Self {
            match none {}
        }
    }

    /// A request and the key that made it.
    ///
    /// The actor is attribution, not authority: it names the key whose
    /// possession the accepting server verified, and the record is only
    /// as truthful as that server. Execution authority comes from the
    /// job signature alone.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub struct Attributed<T> {
        pub actor: KeyId,
        pub request: T,
    }

    impl<T> Attributed<T> {
        pub fn as_parts(&self) -> (&KeyId, &T) {
            (&self.actor, &self.request)
        }

        pub fn request(&self) -> &T {
            &self.request
        }
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum Request {
        Session(Box<Attributed<SessionRequest>>),
        Job(Box<Attributed<JobRequest>>),
        Identity(Box<Attributed<IdentityRequest>>),
    }

    impl Request {
        pub fn session(actor: KeyId, request: SessionRequest) -> Self {
            Self::Session(Box::new(Attributed { actor, request }))
        }

        pub fn job(actor: KeyId, request: JobRequest) -> Self {
            Self::Job(Box::new(Attributed { actor, request }))
        }

        pub fn identity(actor: KeyId, request: IdentityRequest) -> Self {
            Self::Identity(Box::new(Attributed { actor, request }))
        }

        pub fn actor(&self) -> &KeyId {
            match self {
                Self::Session(r) => r.as_parts().0,
                Self::Job(r) => r.as_parts().0,
                Self::Identity(r) => r.as_parts().0,
            }
        }

        pub fn kind(&self) -> &'static str {
            match self {
                Self::Session(r) => match r.request {
                    SessionRequest::Start(_) => "session start",
                    SessionRequest::Stop(_) => "session stop",
                    SessionRequest::Skip(..) => "session skip",
                    SessionRequest::AllowAttach(..) => "session allow",
                    SessionRequest::DenyAttach(..) => "session deny",
                },
                Self::Job(r) => match r.request {
                    JobRequest::Start(..) => "job start",
                    JobRequest::Stop(_) => "job stop",
                },
                Self::Identity(r) => match r.request {
                    IdentityRequest::Login(..) => "identity login",
                },
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum SessionRequest {
        Start(SessionId),
        Stop(SessionId),
        Skip(SessionId, JobId),
        AllowAttach(SessionId, KeyId, Access),
        DenyAttach(SessionId, KeyId),
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[allow(clippy::large_enum_variant)]
    pub enum JobRequest {
        Start(SignedJob, JobStartParams),
        Stop(JobId),
    }

    /// Identity gossip carries evidence, not assertions: every sled
    /// verifies a login's challenge-response signature itself, so a
    /// registered identity never depends on another sled's honesty.
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[allow(clippy::large_enum_variant)]
    pub enum IdentityRequest {
        /// OpenSSH public keys are string encoded and decoded at use.
        Login(String, SignedLogin),
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum Event {
        Job(JobEvent),
        Error(Error),
        Version(VersionInfo),
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum JobEvent {
        Start(JobId, DateTime<Utc>),
        Stop(
            JobId,
            DateTime<Utc>,
            Result<i32, ProcessError>,
            JobOutputState,
        ),
        Error(JobId, DateTime<Utc>, ProcessError),
        Skipped(JobId, DateTime<Utc>, SkipReason),
    }

    impl JobEvent {
        pub fn job_id(&self) -> &JobId {
            match self {
                Self::Start(id, ..)
                | Self::Stop(id, ..)
                | Self::Error(id, ..)
                | Self::Skipped(id, ..) => id,
            }
        }
    }

    #[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
    pub enum Error {
        #[error(
            "Concurrent sessions detected: \
             ours is {own_session}@{own_version}, \
             incoming is {incoming_session}@{incoming_version}"
        )]
        ConcurrentSessions {
            own_session: SessionId,
            own_version: Box<Version>,
            incoming_session: SessionId,
            incoming_version: Box<Version>,
        },
        #[error("Sled re-entered a burned universe")]
        UniverseFlipFlop,
        #[error("Sled hopped into a session its record cannot order")]
        SessionHop,
    }
}

#[cfg(test)]
mod wire_format {
    use std::collections::BTreeSet;
    use std::env;
    use std::fs::{read, read_dir, write};

    use sush_api::JobWait;
    use sush_common::authn::{ChallengeResponse, Nonce, RequestVerifier};
    use sush_common::hash::hash;
    use sush_common::jobs::{JobMode, JobStartRequest};
    use sush_common::keys::{EncodedSignature, Signed};

    use super::v0::*;
    use super::*;

    /// Serialize a message as rumors does (CBOR) and compare against
    /// the snapshot in `tests/output/`, or rewrite it under
    /// `EXPECTORATE=overwrite`.
    ///
    /// If this test fails, STOP! You have changed the gossip wire
    /// format! Renaming a type, field, or variant (or editing any
    /// struct these messages contain) silently changes how *old* bytes
    /// decode. Either revert the schema change or introduce a new
    /// [`VersionedMessage`] variant and re-pin the snapshots.
    #[track_caller]
    fn assert_wire_format(name: &str, message: VersionedMessage) {
        let mut bytes = Vec::new();
        into_cbor(&message, &mut bytes).unwrap();
        let path = format!("tests/output/{name}.bin");
        if env::var("EXPECTORATE").as_deref() == Ok("overwrite") {
            write(&path, &bytes).unwrap();
        } else {
            let expected = read(&path).expect("missing snapshot");
            assert_eq!(bytes, expected, "gossip wire format changed: {bytes:02x?}");
        }
        let decoded: VersionedMessage = from_cbor(bytes.as_slice()).unwrap();
        assert_eq!(decoded, message, "wire format should round-trip");
    }

    fn sid(name: &str) -> SessionId {
        name.parse().unwrap()
    }

    fn key(name: &str) -> KeyId {
        name.parse().unwrap()
    }

    /// Maps every message to the snapshot pinning its variant. No
    /// wildcard arms over this module's enums or [`SkipReason`]:
    /// adding a variant fails compilation here until it is named,
    /// built in [`samples`], and its snapshot pinned. Payload enums
    /// with many variants ([`ProcessError`]) are sampled
    /// representatively instead.
    fn snapshot_name(message: &Message) -> &'static str {
        match message {
            Message::Request(Request::Session(r)) => match r.request {
                SessionRequest::Start(_) => "session-start-request",
                SessionRequest::Stop(_) => "session-stop-request",
                SessionRequest::Skip(..) => "session-skip-request",
                SessionRequest::AllowAttach(..) => "session-allow-attach-request",
                SessionRequest::DenyAttach(..) => "session-deny-attach-request",
            },
            Message::Request(Request::Job(r)) => match &r.request {
                JobRequest::Start(_, params) if params.term.is_some() => {
                    "job-start-interactive-request"
                }
                JobRequest::Start(..) => "job-start-request",
                JobRequest::Stop(_) => "job-stop-request",
            },
            Message::Request(Request::Identity(r)) => match r.request {
                IdentityRequest::Login(..) => "identity-login-request",
            },
            Message::Event(_, event) => match event {
                Event::Version(_) => "version-event",
                Event::Job(JobEvent::Start(..)) => "job-start-event",
                Event::Job(JobEvent::Stop(..)) => "job-stop-event",
                Event::Job(JobEvent::Error(_, _, ProcessError::Interrupted)) => {
                    "job-interrupted-event"
                }
                Event::Job(JobEvent::Error(..)) => "job-error-event",
                Event::Job(JobEvent::Skipped(_, _, reason)) => match reason {
                    SkipReason::BelowFloor => "job-skipped-event",
                    SkipReason::AlreadyHandled => "already-handled-skip-event",
                    SkipReason::SessionEnded => "session-ended-skip-event",
                },
                Event::Error(Error::ConcurrentSessions { .. }) => "concurrent-sessions-error",
                Event::Error(Error::SessionHop) => "session-hop-error",
                Event::Error(Error::UniverseFlipFlop) => "universe-flip-flop-error",
            },
        }
    }

    /// One sample per leaf of [`snapshot_name`]'s match, the inputs
    /// to [`wire_formats`].
    fn samples() -> Vec<Message> {
        let actor = || key("zoo-zero");
        let session = sid("abandon-ability");
        let attach = key("able-about");
        let long_job: JobId = "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
            .parse()
            .unwrap();
        let long_session = sid("bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-banana");
        let when = DateTime::from_timestamp(1_756_252_800, 0).unwrap();
        let skip_when = "2026-09-04T20:00:00Z".parse().unwrap();
        let skip_job: JobId = "zoo-zero".parse().unwrap();
        let baseboard = BaseboardId {
            part_number: "913-0000019".to_string(),
            serial_number: "BRM42220030".to_string(),
        };
        let signature = |flags, counter| EncodedSignature {
            r: "abandon".parse().unwrap(),
            s: "zoo".parse().unwrap(),
            flags,
            counter,
        };

        let batch = Signed::new(
            JobStartRequest::new(
                long_job,
                long_session,
                "echo hello",
                JobMode::Batch,
                "14,16".parse().unwrap(),
            ),
            actor(),
            signature(0, 0),
        );
        let interactive = Signed::new(
            JobStartRequest::new(
                long_job,
                long_session,
                "bash",
                JobMode::Interactive,
                "14".parse().unwrap(),
            ),
            actor(),
            signature(1, 38),
        );
        let interactive_params = JobStartParams {
            term: Some("vt100".to_string()),
            rows: Some(24),
            cols: Some(80),
            wait: JobWait::Start,
            ..Default::default()
        };

        // Deterministic login evidence: nonces, then the ed25519
        // basepoint as the verifier.
        let mut epk = [0x66; 32];
        epk[0] = 0x58;
        let response: ChallengeResponse = serde_json::from_value(serde_json::json!({
            "nonce": "abandon".parse::<Nonce>().unwrap(),
            "cnonce": "ability".parse::<Nonce>().unwrap(),
            "epk": RequestVerifier::from_be_bytes(epk),
        }))
        .unwrap();
        let openssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ13gEiGB test@sush";
        let login = Signed::new(response, actor(), signature(0, 0));

        let output = JobOutputState {
            stdout_len: 22,
            stderr_len: 0,
            stdout_hash: hash(b"all pools are healthy\n").into(),
            stderr_hash: hash(b"").into(),
        };

        vec![
            Message::Request(Request::session(actor(), SessionRequest::Start(session))),
            Message::Request(Request::session(actor(), SessionRequest::Stop(session))),
            Message::Request(Request::session(
                actor(),
                SessionRequest::Skip(long_session, long_job),
            )),
            Message::Request(Request::session(
                actor(),
                SessionRequest::AllowAttach(session, attach.clone(), Access::ReadWrite),
            )),
            Message::Request(Request::session(
                actor(),
                SessionRequest::DenyAttach(session, attach),
            )),
            Message::Request(Request::job(
                actor(),
                JobRequest::Start(batch, JobStartParams::default()),
            )),
            Message::Request(Request::job(
                actor(),
                JobRequest::Start(interactive, interactive_params),
            )),
            Message::Request(Request::job(actor(), JobRequest::Stop(long_job))),
            Message::Request(Request::identity(
                actor(),
                IdentityRequest::Login(openssh.to_string(), login),
            )),
            Message::Event(
                baseboard.clone(),
                Event::Version(VersionInfo {
                    version: "0.1.0".to_string(),
                    commit: "f078e863b17359031de072222bb631270f2d5157".to_string(),
                }),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Job(JobEvent::Start(long_job, when)),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Job(JobEvent::Stop(long_job, when, Ok(0), output)),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Job(JobEvent::Error(
                    long_job,
                    when,
                    ProcessError::InvalidJob("interactive jobs cannot stream".to_string()),
                )),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Job(JobEvent::Error(long_job, when, ProcessError::Interrupted)),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Job(JobEvent::Skipped(
                    skip_job,
                    skip_when,
                    SkipReason::BelowFloor,
                )),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Job(JobEvent::Skipped(
                    skip_job,
                    skip_when,
                    SkipReason::AlreadyHandled,
                )),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Job(JobEvent::Skipped(
                    skip_job,
                    skip_when,
                    SkipReason::SessionEnded,
                )),
            ),
            Message::Event(
                baseboard.clone(),
                Event::Error(Error::ConcurrentSessions {
                    own_session: long_session,
                    own_version: Box::new(Version::new()),
                    incoming_session: sid("zoo-zoo-zoo-zoo-zoo-zoo-zoo-zebra"),
                    incoming_version: Box::new(Version::new()),
                }),
            ),
            Message::Event(baseboard.clone(), Event::Error(Error::SessionHop)),
            Message::Event(baseboard, Event::Error(Error::UniverseFlipFlop)),
        ]
    }

    /// Every sample round-trips against its pinned snapshot, and the
    /// snapshot directory holds exactly the pinned set, so a deleted
    /// variant cannot leave a stale snapshot behind.
    #[test]
    fn wire_formats() {
        // The boundary module pins its record format in the same
        // directory.
        let mut expected = BTreeSet::from(["boundary-record-v0.bin".to_string()]);
        for message in samples() {
            let name = snapshot_name(&message);
            assert!(
                expected.insert(format!("{name}.bin")),
                "two samples hit the same arm: {name}"
            );
            assert_wire_format(name, message.into());
        }
        let present: BTreeSet<String> = read_dir("tests/output")
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(present, expected, "tests/output and the samples disagree");
    }

    /// A message from a newer build decodes as `Unknown` instead of
    /// failing at the wire boundary, cannot be sent, and corruption
    /// still fails.
    #[test]
    fn unknown_version_tolerated() {
        let v1 = Value::Map(vec![(
            Value::Text("V1".to_string()),
            Value::Map(vec![(
                Value::Text("frob".to_string()),
                Value::Integer(3.into()),
            )]),
        )]);
        let mut bytes = Vec::new();
        into_cbor(&v1, &mut bytes).unwrap();
        let decoded: VersionedMessage = from_cbor(bytes.as_slice()).unwrap();
        assert!(matches!(&decoded, VersionedMessage::Unknown { version, .. } if version == "V1"));

        // Rumors panics when a message fails to serialize, so this
        // must not fail, and it must emit what was received.
        let mut resent = Vec::new();
        into_cbor(&decoded, &mut resent).unwrap();
        assert_eq!(resent, bytes);

        let corrupt: Result<VersionedMessage, _> = from_cbor([0x01].as_slice());
        assert!(corrupt.is_err());
    }
}
