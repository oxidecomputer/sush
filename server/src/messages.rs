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
    }

    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    pub enum Request {
        Cert(Box<Attributed<CertRequest>>),
        Session(Box<Attributed<SessionRequest>>),
        Job(Box<Attributed<JobRequest>>),
        Identity(Box<Attributed<IdentityRequest>>),
    }

    impl Request {
        pub fn cert(actor: KeyId, request: CertRequest) -> Self {
            Self::Cert(Box::new(Attributed { actor, request }))
        }

        pub fn session(actor: KeyId, request: SessionRequest) -> Self {
            Self::Session(Box::new(Attributed { actor, request }))
        }

        pub fn job(actor: KeyId, request: JobRequest) -> Self {
            Self::Job(Box::new(Attributed { actor, request }))
        }

        pub fn identity(actor: KeyId, request: IdentityRequest) -> Self {
            Self::Identity(Box::new(Attributed { actor, request }))
        }

        pub fn kind(&self) -> &'static str {
            match self {
                Self::Cert(r) => match r.request {
                    CertRequest::Import(_) => "cert import",
                    CertRequest::Revoke(..) => "cert revoke",
                },
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
                    IdentityRequest::Revoke(..) => "identity revoke",
                },
            }
        }
    }

    /// Certificates are PEM-encoded X.509
    #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
    #[allow(clippy::large_enum_variant)]
    pub enum CertRequest {
        /// The certificate's DER bytes, decoded at use.
        Import(#[serde(with = "crate::format::cbor_bytes")] Vec<u8>),
        Revoke(KeyId, DateTime<Utc>),
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
        Revoke(KeyId, DateTime<Utc>),
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

    #[derive(Clone, Debug, Deserialize, Eq, Error, PartialEq, Serialize)]
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
        #[error("Sled re-entered a burned universe")]
        UniverseFlipFlop,
        #[error("Sled hopped into a session its record cannot order")]
        SessionHop,
    }
}

#[cfg(test)]
mod wire_format {
    use std::env;
    use std::fs::{read, write};

    use super::v0::*;
    use super::*;
    use std::str::FromStr as _;
    use sush_common::authn::Nonce;

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

    #[test]
    fn session_start_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from_str("zoo-zero").unwrap(),
            SessionRequest::Start(sid("abandon-ability")),
        ))
        .into();
        assert_wire_format("session-start-request", msg);
    }

    #[test]
    fn session_stop_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from_str("zoo-zero").unwrap(),
            SessionRequest::Stop(sid("abandon-ability")),
        ))
        .into();
        assert_wire_format("session-stop-request", msg);
    }

    #[test]
    fn session_allow_attach_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from_str("zoo-zero").unwrap(),
            SessionRequest::AllowAttach(
                sid("abandon-ability"),
                KeyId::from_str("able-about").unwrap(),
                Access::ReadWrite,
            ),
        ))
        .into();
        assert_wire_format("session-allow-attach-request", msg);
    }

    #[test]
    fn session_deny_attach_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from_str("zoo-zero").unwrap(),
            SessionRequest::DenyAttach(
                sid("abandon-ability"),
                KeyId::from_str("able-about").unwrap(),
            ),
        ))
        .into();
        assert_wire_format("session-deny-attach-request", msg);
    }

    #[test]
    fn job_start_request() {
        use sush_common::jobs::{JobMode, JobStartRequest};
        use sush_common::keys::{EncodedSignature, Signed};

        let request = JobStartRequest::new(
            "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
                .parse()
                .unwrap(),
            "bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-banana"
                .parse()
                .unwrap(),
            "echo hello",
            JobMode::Batch,
            "14,16".parse().unwrap(),
        );
        let signed = Signed::new(
            request,
            KeyId::from_str("zoo-zero").unwrap(),
            EncodedSignature {
                r: "abandon".parse().unwrap(),
                s: "zoo".parse().unwrap(),
                flags: 0,
                counter: 0,
            },
        );
        let msg: VersionedMessage = Message::Request(Request::job(
            KeyId::from_str("zoo-zero").unwrap(),
            JobRequest::Start(signed, JobStartParams::default()),
        ))
        .into();
        assert_wire_format("job-start-request", msg);
    }

    #[test]
    fn identity_login_request() {
        use sush_common::authn::{ChallengeResponse, RequestVerifier};
        use sush_common::keys::{EncodedSignature, Signed};

        // Craft deterministic evidence: nonces, then the ed25519
        // basepoint as the verifier.
        let mut epk = [0x66; 32];
        epk[0] = 0x58;
        let response: ChallengeResponse = serde_json::from_value(serde_json::json!({
            "nonce": Nonce::from_str("abandon").unwrap(),
            "cnonce": Nonce::from_str("ability").unwrap(),
            "epk": RequestVerifier::from_be_bytes(epk),
        }))
        .unwrap();

        let openssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ13gEiGB test@sush";

        let signed = Signed::new(
            response,
            KeyId::from_str("zoo-zero").unwrap(),
            EncodedSignature {
                r: "abandon".parse().unwrap(),
                s: "zoo".parse().unwrap(),
                flags: 0,
                counter: 0,
            },
        );
        let msg: VersionedMessage = Message::Request(Request::identity(
            KeyId::from_str("zoo-zero").unwrap(),
            IdentityRequest::Login(openssh.to_string(), signed),
        ))
        .into();
        assert_wire_format("identity-login-request", msg);
    }

    #[test]
    fn version_event() {
        let msg: VersionedMessage = Message::Event(
            BaseboardId {
                part_number: "913-0000019".to_string(),
                serial_number: "BRM42220030".to_string(),
            },
            Event::Version(VersionInfo {
                version: "0.1.0".to_string(),
                commit: "f078e863b17359031de072222bb631270f2d5157".to_string(),
            }),
        )
        .into();
        assert_wire_format("version-event", msg);
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

    #[test]
    fn session_skip_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from_str("zoo-zero").unwrap(),
            SessionRequest::Skip(
                sid("bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-banana"),
                "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
                    .parse()
                    .unwrap(),
            ),
        ))
        .into();
        assert_wire_format("session-skip-request", msg);
    }

    #[test]
    fn job_stop_request() {
        let msg: VersionedMessage = Message::Request(Request::job(
            KeyId::from_str("zoo-zero").unwrap(),
            JobRequest::Stop(
                "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
                    .parse()
                    .unwrap(),
            ),
        ))
        .into();
        assert_wire_format("job-stop-request", msg);
    }

    #[test]
    fn cert_requests() {
        use x509_cert::Certificate;
        use x509_cert::der::{DecodePem as _, Encode as _};

        let cert = Certificate::from_pem(include_str!("../../client/certs/staging.pem")).unwrap();
        let msg: VersionedMessage = Message::Request(Request::cert(
            KeyId::from_str("zoo-zero").unwrap(),
            CertRequest::Import(cert.to_der().unwrap()),
        ))
        .into();
        assert_wire_format("cert-import-request", msg);

        let msg: VersionedMessage = Message::Request(Request::cert(
            KeyId::from_str("zoo-zero").unwrap(),
            CertRequest::Revoke(
                KeyId::from_str("zoo-zero").unwrap(),
                DateTime::from_timestamp(1_756_252_800, 0).unwrap(),
            ),
        ))
        .into();
        assert_wire_format("cert-revoke-request", msg);
    }

    #[test]
    fn identity_revoke_request() {
        let msg: VersionedMessage = Message::Request(Request::identity(
            KeyId::from_str("zoo-zero").unwrap(),
            IdentityRequest::Revoke(
                KeyId::from_str("zoo-zero").unwrap(),
                DateTime::from_timestamp(1_756_252_800, 0).unwrap(),
            ),
        ))
        .into();
        assert_wire_format("identity-revoke-request", msg);
    }

    #[test]
    fn job_events() {
        use sush_common::hash::hash;
        use sush_common::jobs::JobOutputState;

        let baseboard = BaseboardId {
            part_number: "913-0000019".to_string(),
            serial_number: "BRM42220030".to_string(),
        };
        let job_id = "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
            .parse()
            .unwrap();
        let when = DateTime::from_timestamp(1_756_252_800, 0).unwrap();

        let msg: VersionedMessage =
            Message::Event(baseboard.clone(), Event::Job(JobEvent::Start(job_id, when))).into();
        assert_wire_format("job-start-event", msg);

        let output = JobOutputState {
            stdout_len: 22,
            stderr_len: 0,
            stdout_hash: hash(b"all pools are healthy\n").into(),
            stderr_hash: hash(b"").into(),
        };
        let msg: VersionedMessage = Message::Event(
            baseboard.clone(),
            Event::Job(JobEvent::Stop(job_id, when, Ok(0), output)),
        )
        .into();
        assert_wire_format("job-stop-event", msg);

        let msg: VersionedMessage = Message::Event(
            baseboard.clone(),
            Event::Job(JobEvent::Error(
                job_id,
                when,
                ProcessError::InvalidJob("interactive jobs cannot stream".to_string()),
            )),
        )
        .into();
        assert_wire_format("job-error-event", msg);

        let msg: VersionedMessage = Message::Event(
            baseboard,
            Event::Job(JobEvent::Error(job_id, when, ProcessError::Interrupted)),
        )
        .into();
        assert_wire_format("job-interrupted-event", msg);
    }

    #[test]
    fn concurrent_sessions_error() {
        let msg: VersionedMessage = Message::Event(
            BaseboardId {
                part_number: "913-0000019".to_string(),
                serial_number: "BRM42220030".to_string(),
            },
            Event::Error(Error::ConcurrentSessions {
                own_session: sid("bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-banana"),
                own_version: Version::new(),
                incoming_session: sid("zoo-zoo-zoo-zoo-zoo-zoo-zoo-zebra"),
                incoming_version: Version::new(),
            }),
        )
        .into();
        assert_wire_format("concurrent-sessions-error", msg);
    }

    #[test]
    fn job_skipped_event() {
        let msg: VersionedMessage = Message::Event(
            BaseboardId {
                part_number: "913-0000019".to_string(),
                serial_number: "BRM42220030".to_string(),
            },
            Event::Job(JobEvent::Skipped(
                JobId::from_str("zoo-zero").unwrap(),
                "2026-09-04T20:00:00Z".parse().unwrap(),
                SkipReason::BelowFloor,
            )),
        )
        .into();
        assert_wire_format("job-skipped-event", msg);
    }

    #[test]
    fn session_hop_error() {
        let msg: VersionedMessage = Message::Event(
            BaseboardId {
                part_number: "913-0000019".to_string(),
                serial_number: "BRM42220030".to_string(),
            },
            Event::Error(Error::SessionHop),
        )
        .into();
        assert_wire_format("session-hop-error", msg);
    }

    #[test]
    fn universe_flip_flop_error() {
        let msg: VersionedMessage = Message::Event(
            BaseboardId {
                part_number: "913-0000019".to_string(),
                serial_number: "BRM42220030".to_string(),
            },
            Event::Error(Error::UniverseFlipFlop),
        )
        .into();
        assert_wire_format("universe-flip-flop-error", msg);
    }

    #[test]
    fn job_start_interactive_request() {
        use sush_api::JobWait;
        use sush_common::jobs::{JobMode, JobStartRequest};
        use sush_common::keys::{EncodedSignature, Signed};

        let request = JobStartRequest::new(
            "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
                .parse()
                .unwrap(),
            sid("bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-bamboo-banana"),
            "bash",
            JobMode::Interactive,
            "14".parse().unwrap(),
        );
        let signed = Signed::new(
            request,
            KeyId::from_str("zoo-zero").unwrap(),
            EncodedSignature {
                r: "abandon".parse().unwrap(),
                s: "zoo".parse().unwrap(),
                flags: 1,
                counter: 38,
            },
        );
        let params = JobStartParams {
            term: Some("vt100".to_string()),
            rows: Some(24),
            cols: Some(80),
            wait: JobWait::Start,
            ..Default::default()
        };
        let msg: VersionedMessage = Message::Request(Request::job(
            KeyId::from_str("zoo-zero").unwrap(),
            JobRequest::Start(signed, params),
        ))
        .into();
        assert_wire_format("job-start-interactive-request", msg);
    }
}
