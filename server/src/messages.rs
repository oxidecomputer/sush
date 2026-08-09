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
use sush_common::authn::SignedLogin;
use sush_common::borsh::{
    borsh_de_baseboard_id, borsh_de_cert, borsh_de_datetime, borsh_ser_baseboard_id,
    borsh_ser_cert, borsh_ser_datetime,
};
use sush_common::jobs::JobOutputState;
use sush_common::jobs::{Access, JobId, ProcessError, SessionId, SignedJob};
use sush_common::keys::{KeyId, SshPublicKey};

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

    /// A request and the key that made it.
    ///
    /// The actor is attribution, not authority: it names the key whose
    /// possession the accepting server verified, and the record is only
    /// as truthful as that server. Execution authority comes from the
    /// job signature alone.
    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    pub struct Attributed<T> {
        pub actor: KeyId,
        pub request: T,
    }

    impl<T> Attributed<T> {
        pub fn as_parts(&self) -> (&KeyId, &T) {
            (&self.actor, &self.request)
        }
    }

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
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
        AllowAttach(SessionId, KeyId, Access),
        DenyAttach(SessionId, KeyId),
    }

    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    pub enum JobRequest {
        Start(SignedJob, JobStartParams),
        Stop(JobId),
    }

    /// Identity gossip carries evidence, not assertions: every sled
    /// verifies a login's challenge-response signature itself, so a
    /// registered identity never depends on another sled's honesty.
    #[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
    #[allow(clippy::large_enum_variant)]
    pub enum IdentityRequest {
        Login(SshPublicKey, SignedLogin),
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
    use std::env;
    use std::fs::{read, write};

    use super::v0::*;
    use super::*;

    /// Serialize a message and compare against the snapshot in
    /// `tests/output/`, or rewrite it under `EXPECTORATE=overwrite`.
    ///
    /// If this test fails, STOP! You have changed the gossip wire format!
    /// Because borsh enum tags are positional, reordering or inserting
    /// variants (or editing any struct these messages contain) silently
    /// changes how *old* bytes decode. Either revert the schema change
    /// or introduce a new [`VersionedMessage`] variant and re-pin the
    /// snapshots.
    #[track_caller]
    fn assert_wire_format(name: &str, message: VersionedMessage) {
        let bytes = borsh::to_vec(&message).unwrap();
        let path = format!("tests/output/{name}.bin");
        if env::var("EXPECTORATE").as_deref() == Ok("overwrite") {
            write(&path, &bytes).unwrap();
        } else {
            let expected = read(&path).expect("missing snapshot");
            assert_eq!(bytes, expected, "gossip wire format changed: {bytes:02x?}");
        }
        let decoded: VersionedMessage = borsh::from_slice(&bytes).unwrap();
        assert_eq!(decoded, message, "wire format should round-trip");
    }

    #[test]
    fn session_start_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from("zoo-zero".to_string()),
            SessionRequest::Start(SessionId::from("abandon-ability")),
        ))
        .into();
        assert_wire_format("session-start-request", msg);
    }

    #[test]
    fn session_stop_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from("zoo-zero".to_string()),
            SessionRequest::Stop(SessionId::from("abandon-ability")),
        ))
        .into();
        assert_wire_format("session-stop-request", msg);
    }

    #[test]
    fn session_allow_attach_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from("zoo-zero".to_string()),
            SessionRequest::AllowAttach(
                SessionId::from("abandon-ability"),
                KeyId::from("able-about".to_string()),
                Access::ReadWrite,
            ),
        ))
        .into();
        assert_wire_format("session-allow-attach-request", msg);
    }

    #[test]
    fn session_deny_attach_request() {
        let msg: VersionedMessage = Message::Request(Request::session(
            KeyId::from("zoo-zero".to_string()),
            SessionRequest::DenyAttach(
                SessionId::from("abandon-ability"),
                KeyId::from("able-about".to_string()),
            ),
        ))
        .into();
        assert_wire_format("session-deny-attach-request", msg);
    }

    #[test]
    fn job_start_request() {
        use sush_common::jobs::JobStartRequest;
        use sush_common::keys::{EncodedSignature, Signed};

        let request = JobStartRequest::new(
            "abandon-abandon-abandon-abandon-abandon-abandon-abandon-ability"
                .parse()
                .unwrap(),
            "echo hello",
            false,
            "14,16".parse().unwrap(),
        );
        let signed = Signed::new(
            request,
            KeyId::from("zoo-zero".to_string()),
            EncodedSignature {
                r: "abandon".to_string(),
                s: "zoo".to_string(),
                flags: 0,
                counter: 0,
            },
        );
        let msg: VersionedMessage = Message::Request(Request::job(
            KeyId::from("zoo-zero".to_string()),
            JobRequest::Start(signed, JobStartParams::default()),
        ))
        .into();
        assert_wire_format("job-start-request", msg);
    }

    #[test]
    fn identity_login_request() {
        use sush_common::authn::ChallengeResponse;
        use sush_common::keys::{EncodedSignature, Signed, SshPublicKey};

        // Craft deterministic evidence: nonces, then the ed25519
        // basepoint as the verifier.
        let mut evidence = Vec::new();
        for nonce in ["abandon", "ability"] {
            evidence.extend((nonce.len() as u32).to_le_bytes());
            evidence.extend(nonce.as_bytes());
        }
        evidence.push(0x58);
        evidence.extend([0x66; 31]);
        let response = ChallengeResponse::try_from_slice(&evidence).unwrap();

        let openssh = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ13gEiGB test@sush";
        let mut key = Vec::new();
        key.extend((openssh.len() as u32).to_le_bytes());
        key.extend(openssh.as_bytes());
        let public_key = SshPublicKey::try_from_slice(&key).unwrap();

        let signed = Signed::new(
            response,
            KeyId::from("zoo-zero".to_string()),
            EncodedSignature {
                r: "abandon".to_string(),
                s: "zoo".to_string(),
                flags: 0,
                counter: 0,
            },
        );
        let msg: VersionedMessage = Message::Request(Request::identity(
            KeyId::from("zoo-zero".to_string()),
            IdentityRequest::Login(public_key, signed),
        ))
        .into();
        assert_wire_format("identity-login-request", msg);
    }

    // TODO: snapshot more messages
}
