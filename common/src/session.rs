//! Interactive job session protocol over WebSockets.
//!
//! Control messages (e.g., window change events) are encoded as JSON
//! and sent as WebSocket `Text` messages:
//!
//! ```json
//! WindowChange { rows: 24, cols: 80 }
//! ```
//!
//! Data packets are encoded and sent as `Binary` messages. We use
//! BLAKE3's arbitrary output length capability to combine data
//! integrity and random padding into one operation; we choose a
//! small random number `n: u8` of hash output bytes, prepend that
//! number to the payload, and append the `n` byte hash:
//!
//! ```text
//! ┌───┬─────────────────────────────┬────────────────┐
//! │ n │ payload (len - n - 1 bytes) │ hash (n bytes) │
//! └───┴─────────────────────────────┴────────────────┘
//! ```
//!
//! Each side uses a pair of randomly keyed hashers, which may be
//! rekeyed at will using `Ping` & `Pong` messages.
//!
//! TODO: Randomize packets in time as well as space, like SSH does.

use std::time::Duration;

use blake3::{Hasher, derive_key};
use bytes::{BufMut as _, Bytes, BytesMut};
use rand::Rng as _;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use serde_json::{from_str as from_json, to_string as to_json};
use thiserror::Error;
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;

pub const SESSION_BUFFER_SIZE: usize = 0x10000;
pub const SESSION_KEY_CONTEXT: &str = "Oxide Support Shell Session Encoding v1";
pub const SESSION_KEY_LEN: usize = 32;
pub const SESSION_REKEY_PERIOD: Duration = Duration::from_secs(30);

/// An interactive session message.
#[derive(Debug)]
pub enum SessionMessage {
    Control(SessionControl),
    Data(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close,
}

impl From<SessionControl> for SessionMessage {
    fn from(message: SessionControl) -> Self {
        Self::Control(message)
    }
}

/// A session control message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SessionControl {
    WindowChange(WindowSize),
}

/// Size of an interactive session pseudoterminal.
/// Shells sometimes call these `$LINES` and `$COLUMNS`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
}

/// Data packet decoder.
#[derive(Debug, Default)]
pub struct SessionDecoder {
    count: u64,
    hasher: Hasher,
}

impl SessionDecoder {
    pub fn count(&self) -> u64 {
        self.count + self.hasher.count()
    }

    pub fn rekey(&mut self, key_material: &[u8]) {
        let key = derive_key(SESSION_KEY_CONTEXT, key_material);
        self.count += self.hasher.count();
        self.hasher = Hasher::new_keyed(&key);
    }

    pub fn decode(&mut self, message: WebSocketMessage) -> Result<SessionMessage, SessionError> {
        match message {
            WebSocketMessage::Text(message) => Ok(SessionMessage::Control(from_json(&message)?)),
            WebSocketMessage::Binary(bytes) => Ok(SessionMessage::Data(self.decode_bytes(&bytes)?)),
            WebSocketMessage::Ping(bytes) => Ok(SessionMessage::Ping(bytes)),
            WebSocketMessage::Pong(bytes) => Ok(SessionMessage::Pong(bytes)),
            WebSocketMessage::Close(_) => Ok(SessionMessage::Close),
            WebSocketMessage::Frame(_) => Err(SessionError::Decode),
        }
    }

    fn decode_bytes(&mut self, bytes: &[u8]) -> Result<Bytes, SessionError> {
        if let Some((pad, rest)) = bytes.split_at_checked(1)
            && let pad = pad[0] as usize
            && let len = rest.len()
            && len >= pad
            && let (payload, hash) = rest.split_at(len - pad)
            && hash_xof(&mut self.hasher, payload, pad) == hash
        {
            Ok(Bytes::copy_from_slice(payload))
        } else {
            Err(SessionError::Decode)
        }
    }
}

/// Data packet encoder.
#[derive(Debug, Default)]
pub struct SessionEncoder {
    count: u64,
    hasher: Hasher,
}

impl SessionEncoder {
    pub fn count(&self) -> u64 {
        self.count + self.hasher.count()
    }

    pub fn rekey(
        &mut self,
        ping: Option<&SessionMessage>,
    ) -> Result<WebSocketMessage, SessionError> {
        let key_material = rand_key();
        let key = derive_key(SESSION_KEY_CONTEXT, &key_material);
        let message = self.encode(if matches!(ping, Some(SessionMessage::Ping(_))) {
            SessionMessage::Pong(key_material)
        } else {
            SessionMessage::Ping(key_material)
        });
        self.count += self.hasher.count();
        self.hasher = Hasher::new_keyed(&key);
        message
    }

    pub fn encode(&mut self, message: SessionMessage) -> Result<WebSocketMessage, SessionError> {
        match message {
            SessionMessage::Control(msg) => Ok(WebSocketMessage::Text(to_json(&msg)?.into())),
            SessionMessage::Data(bytes) => Ok(WebSocketMessage::Binary(self.encode_bytes(&bytes))),
            SessionMessage::Ping(bytes) => Ok(WebSocketMessage::Ping(bytes)),
            SessionMessage::Pong(bytes) => Ok(WebSocketMessage::Pong(bytes)),
            SessionMessage::Close => Ok(WebSocketMessage::Close(None)),
        }
    }

    fn encode_bytes(&mut self, payload: &[u8]) -> Bytes {
        let pad = rand_len();
        let len = 1 + payload.len() + pad as usize;
        let mut packet = BytesMut::with_capacity(len);
        packet.put_u8(pad);
        packet.extend(payload);
        packet.extend(hash_xof(&mut self.hasher, payload, pad as usize));
        assert_eq!(packet.len(), len);
        packet.freeze()
    }
}

fn hash_xof(hasher: &mut Hasher, input: &[u8], output_len: usize) -> Bytes {
    let mut output = BytesMut::zeroed(output_len);
    hasher.update(input);
    hasher.finalize_xof().fill(&mut output);
    output.freeze()
}

fn rand_key() -> Bytes {
    let mut key = BytesMut::zeroed(SESSION_KEY_LEN);
    OsRng.fill_bytes(&mut key);
    key.freeze()
}

fn rand_len() -> u8 {
    OsRng.gen_range(8..255)
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Client closed connection")]
    Close,
    #[error("Can't decode data packet, session synchronization lost")]
    Decode,
    #[error("Can't encode session message")]
    Encode,
    #[error("Session I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Session I/O error: {0}")]
    IoErrno(#[from] rustix::io::Errno),
    #[error("Job ended")]
    JobEnded,
    #[error("Can't join session task: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Can't (de)serialize JSON session control message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Can't send shutdown signal")]
    Shutdown,
    #[error("WebSocket error: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::error::Error),
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn round_trip_packets() {
        let mut decoder = SessionDecoder::default();
        let mut encoder = SessionEncoder::default();
        let mut count = 0;
        let mut rng = thread_rng();
        for i in 0..1000 {
            if i % 10 == 0 {
                let message = encoder.rekey(None).unwrap();
                if let Ok(SessionMessage::Ping(key_material)) = decoder.decode(message) {
                    decoder.rekey(&key_material);
                } else {
                    panic!("invalid rekey message");
                }
            }

            let mut bytes = BytesMut::zeroed(rng.gen_range(0..1000));
            rng.fill_bytes(&mut bytes);

            let packet = encoder.encode_bytes(&bytes);
            assert_eq!(packet[0] as usize, packet.len() - bytes.len() - 1);
            assert_ne!(packet, bytes);

            let decoded = decoder.decode_bytes(&packet).unwrap();
            assert_eq!(bytes, decoded);

            count += bytes.len() as u64;
            assert_eq!(encoder.count(), count);
            assert_eq!(decoder.count(), count);
        }
    }
}
