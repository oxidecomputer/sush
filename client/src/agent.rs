// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The client half of the [SSH agent protocol]: the two exchanges we
//! need, request-identities and sign-request.
//!
//! A message is a `u32` length, a type byte, and a type-specific
//! payload; strings within are length-prefixed bytes.
//!
//! [SSH agent protocol]: https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent

// Handle raw SSH public keys, algorithms, and signatures.
#![allow(clippy::disallowed_types)]

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut, TryGetError};
use ssh_key::{PublicKey, Signature};
use thiserror::Error;

/// Request type bytes, named as in draft-miller-ssh-agent.
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

/// Response type bytes.
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Ceiling on any one message, matching OpenSSH's `MAX_AGENT_REPLY_LEN`.
pub const MAX_MESSAGE: u32 = 256 * 1024;

/// No sign-request flags: our key algorithms define one signature
/// scheme each.
const NO_FLAGS: u32 = 0;

/// What went wrong on the wire.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("empty agent message")]
    Empty,
    #[error("SSH agent refused the request")]
    Failure,
    #[error("message of {0} bytes exceeds the {MAX_MESSAGE}-byte cap")]
    Oversized(u64),
    #[error("SSH key: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("bytes left over after a complete message")]
    Trailing,
    #[error("truncated agent message")]
    Truncated,
    #[error("unexpected response type {got} to request type {sent}")]
    Unexpected { sent: u8, got: u8 },
}

impl From<TryGetError> for AgentError {
    fn from(_: TryGetError) -> Self {
        AgentError::Truncated
    }
}

/// The error for a response that doesn't answer `sent`.
pub fn unexpected(sent: u8, got: u8) -> AgentError {
    if got == SSH_AGENT_FAILURE {
        AgentError::Failure
    } else {
        AgentError::Unexpected { sent, got }
    }
}

/// Encode a request-identities message.
pub fn request_identities() -> Bytes {
    let mut body = BytesMut::with_capacity(1);
    body.put_u8(SSH_AGENTC_REQUEST_IDENTITIES);
    frame(body).expect("one byte fits any frame")
}

/// Encode a sign-request for `data` under `key`.
pub fn sign_request(key: &PublicKey, data: &[u8]) -> Result<Bytes, AgentError> {
    let blob = key.to_bytes()?;
    let mut body = BytesMut::with_capacity(1 + 4 + blob.len() + 4 + data.len() + 4);
    body.put_u8(SSH_AGENTC_SIGN_REQUEST);
    put_string(&mut body, &blob)?;
    put_string(&mut body, data)?;
    body.put_u32(NO_FLAGS);
    frame(body)
}

/// Parse an identities-answer payload into its keys. Comments are
/// consumed and dropped; our key IDs derive from the key material.
pub fn identities_answer(mut payload: Bytes) -> Result<Vec<PublicKey>, AgentError> {
    let count = payload.try_get_u32()?;
    let mut keys = Vec::new();
    for _ in 0..count {
        let blob = get_string(&mut payload)?;
        let _comment = get_string(&mut payload)?;
        keys.push(PublicKey::from_bytes(&blob)?);
    }
    done(payload)?;
    Ok(keys)
}

/// Parse a sign-response payload.
pub fn sign_response(mut payload: Bytes) -> Result<Signature, AgentError> {
    let signature = get_string(&mut payload)?;
    done(payload)?;
    Ok(Signature::try_from(signature.as_ref())?)
}

/// Length-prefix one complete message body.
fn frame(body: BytesMut) -> Result<Bytes, AgentError> {
    let mut framed = BytesMut::with_capacity(4 + body.len());
    framed.put_u32(length(body.len())?);
    framed.put_slice(&body);
    Ok(framed.freeze())
}

/// A length that fits the protocol's `u32`, under the message cap.
fn length(len: usize) -> Result<u32, AgentError> {
    match u32::try_from(len) {
        Ok(len) if len <= MAX_MESSAGE => Ok(len),
        _ => Err(AgentError::Oversized(len as u64)),
    }
}

/// Append one string to `buf`.
fn put_string(buf: &mut BytesMut, bytes: &[u8]) -> Result<(), AgentError> {
    buf.put_u32(length(bytes.len())?);
    buf.put_slice(bytes);
    Ok(())
}

/// Take one string off the front of `buf`.
fn get_string(buf: &mut Bytes) -> Result<Bytes, AgentError> {
    let length = buf.try_get_u32()? as usize;
    if buf.remaining() < length {
        return Err(AgentError::Truncated);
    }
    Ok(buf.copy_to_bytes(length))
}

/// Require a fully-consumed payload.
fn done(payload: Bytes) -> Result<(), AgentError> {
    if payload.has_remaining() {
        return Err(AgentError::Trailing);
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    /// A fixed key so encodings are deterministic.
    fn key() -> PublicKey {
        PublicKey::from_openssh(concat!(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ13gEiGB",
            " test@sush",
        ))
        .unwrap()
    }

    #[test]
    fn request_identities_frame() {
        assert_eq!(
            request_identities().as_ref(),
            [0, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES],
        );
    }

    /// A sign-request round-trips into its key blob, data, and flags.
    #[test]
    fn sign_request_frame() {
        let mut frame = sign_request(&key(), b"data").unwrap();
        let length = frame.get_u32();
        assert_eq!(length as usize, frame.remaining());
        assert_eq!(frame.get_u8(), SSH_AGENTC_SIGN_REQUEST);
        assert_eq!(get_string(&mut frame).unwrap(), key().to_bytes().unwrap(),);
        assert_eq!(get_string(&mut frame).unwrap().as_ref(), b"data");
        assert_eq!(frame.get_u32(), NO_FLAGS);
        done(frame).unwrap();
    }

    /// An identities-answer parses to its keys, dropping comments.
    #[test]
    fn identities_answer_roundtrip() {
        let mut payload = BytesMut::new();
        payload.put_u32(1);
        put_string(&mut payload, &key().to_bytes().unwrap()).unwrap();
        put_string(&mut payload, b"a comment").unwrap();
        let keys = identities_answer(payload.freeze()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_data(), key().key_data());
    }

    /// Truncated and oversized payloads are rejected, not misread.
    #[test]
    fn malformed_payloads() {
        let mut payload = BytesMut::new();
        payload.put_u32(2);
        put_string(&mut payload, &key().to_bytes().unwrap()).unwrap();
        put_string(&mut payload, b"only one key follows").unwrap();
        assert!(matches!(
            identities_answer(payload.freeze()),
            Err(AgentError::Truncated),
        ));

        let mut payload = BytesMut::new();
        put_string(&mut payload, b"ssh-ed25519 but trailing").unwrap();
        payload.put_u8(0);
        assert!(matches!(
            sign_response(payload.freeze()),
            Err(AgentError::Trailing),
        ));

        assert!(matches!(
            sign_request(&key(), &vec![0; MAX_MESSAGE as usize + 1]),
            Err(AgentError::Oversized(_)),
        ));
    }

    /// A signature blob round-trips through sign-response.
    #[test]
    fn sign_response_roundtrip() {
        let mut blob = BytesMut::new();
        put_string(&mut blob, b"ssh-ed25519").unwrap();
        put_string(&mut blob, &[0; 64]).unwrap();
        let mut payload = BytesMut::new();
        put_string(&mut payload, &blob).unwrap();
        let signature = sign_response(payload.freeze()).unwrap();
        assert_eq!(signature.algorithm(), ssh_key::Algorithm::Ed25519);
    }
}
