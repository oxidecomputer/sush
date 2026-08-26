// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Messages gossiped via rumors.

use chrono::{DateTime, Utc};
use rumors::Version;
use serde::{Deserialize, Serialize};
use sled_hardware_types::BaseboardId;
use thiserror::Error;
use x509_cert::Certificate;

use sush_api::JobStartParams;
use sush_common::authn::SignedLogin;
use sush_common::jobs::JobOutputState;
use sush_common::jobs::{Access, JobId, ProcessError, SessionId, SignedJob};
use sush_common::keys::{KeyId, SshPublicKey};
use sush_common::version::VersionInfo;

/// Once a message schema has shipped, it is frozen, since any changes
/// could break decoding of *existing* messages. Each version gets its
/// own module; everything defined there and all of their dependencies
/// (e.g., types shared with the HTTP API, etc.) become part of the frozen
/// version, whose serde shape on the gossip wire must not change. New
/// versions must implement `TryInto` to convert old messages into
/// compatible new ones.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum VersionedMessage {
    V0(v0::Message),
}

/// DER bytes for certificates, which have no serde support.
mod cert_der {
    use serde::de::Visitor;
    use serde::ser::Error as _;
    use serde::{Deserializer, Serializer};
    use x509_cert::Certificate;
    use x509_cert::der::{Decode as _, Encode as _};

    pub fn serialize<S: Serializer>(cert: &Certificate, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&cert.to_der().map_err(S::Error::custom)?)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Certificate, D::Error> {
        struct DerVisitor;

        impl<'de> Visitor<'de> for DerVisitor {
            type Value = Certificate;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a DER-encoded certificate")
            }

            fn visit_bytes<E: serde::de::Error>(self, der: &[u8]) -> Result<Self::Value, E> {
                Certificate::from_der(der).map_err(E::custom)
            }
        }

        deserializer.deserialize_bytes(DerVisitor)
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
        Import(#[serde(with = "cert_der")] Certificate),
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
        Login(SshPublicKey, SignedLogin),
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
        ciborium::ser::into_writer(&message, &mut bytes).unwrap();
        let path = format!("tests/output/{name}.bin");
        if env::var("EXPECTORATE").as_deref() == Ok("overwrite") {
            write(&path, &bytes).unwrap();
        } else {
            let expected = read(&path).expect("missing snapshot");
            assert_eq!(bytes, expected, "gossip wire format changed: {bytes:02x?}");
        }
        let decoded: VersionedMessage = ciborium::de::from_reader(bytes.as_slice()).unwrap();
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
        use sush_common::keys::{EncodedSignature, Signed, SshPublicKey};

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
        let public_key: SshPublicKey = serde_json::from_value(serde_json::json!(openssh)).unwrap();

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
            IdentityRequest::Login(public_key, signed),
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

    // TODO: snapshot more messages
}
