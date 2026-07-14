//! Interactive job protocol over WebSockets.
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
//! Each side uses a pair of randomly keyed hashers, which may be rekeyed
//! using `Ping` & `Pong` messages. The server generates a random `key`,
//! rekeys its encoder, and sends `Ping(key)` to the client. On receipt of
//! the `Ping`, the client rekeys its decoder to `key`, generates a fresh
//! `ckey` and rekeys its encoder, then responds with `Pong(key ^ ckey)`.
//! On receipt of the `Pong`, the server rekeys its own decoder to `ckey`.
//! This ensures that each `Pong` corresponds to exactly one `Ping`.
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

pub const INTERACTIVE_JOB_BUFFER_SIZE: usize = 0x10000;
pub const INTERACTIVE_JOB_KEY_CONTEXT: &str = "Oxide Support Shell Interactive Job Encoding v1";
pub const INTERACTIVE_JOB_KEY_LEN: usize = 32;
pub const INTERACTIVE_JOB_REKEY_PERIOD: Duration = Duration::from_secs(30);

/// An interactive session message.
#[derive(Clone, Debug)]
pub enum InteractiveJobMessage {
    Control(InteractiveJobControl),
    Data(Bytes),
    Ping(Bytes),
    Pong(Bytes),
    Close,
}

impl From<InteractiveJobControl> for InteractiveJobMessage {
    fn from(message: InteractiveJobControl) -> Self {
        Self::Control(message)
    }
}

/// A session control message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum InteractiveJobControl {
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
pub struct InteractiveJobDecoder {
    count: u64,
    hasher: Hasher,
}

impl InteractiveJobDecoder {
    pub fn count(&self) -> u64 {
        self.count + self.hasher.count()
    }

    pub fn rekey(&mut self, mut key_material: Bytes, mask: Option<Bytes>) {
        if let Some(mask) = mask {
            key_material = xor_bytes(&key_material, &mask);
        }
        let key = derive_key(INTERACTIVE_JOB_KEY_CONTEXT, &key_material);
        self.count += self.hasher.count();
        self.hasher = Hasher::new_keyed(&key);
    }

    pub fn decode(
        &mut self,
        message: WebSocketMessage,
    ) -> Result<InteractiveJobMessage, InteractiveJobError> {
        use InteractiveJobMessage as Message;
        use WebSocketMessage as WebSocket;
        match message {
            WebSocket::Text(message) => Ok(Message::Control(from_json(&message)?)),
            WebSocket::Binary(bytes) => Ok(Message::Data(self.decode_data(&bytes)?)),
            WebSocket::Ping(bytes) => Ok(Message::Ping(bytes)),
            WebSocket::Pong(bytes) => Ok(Message::Pong(bytes)),
            WebSocket::Close(_) => Ok(Message::Close),
            WebSocket::Frame(_) => Err(InteractiveJobError::Decode),
        }
    }

    fn decode_data(&mut self, bytes: &[u8]) -> Result<Bytes, InteractiveJobError> {
        if let Some((pad, rest)) = bytes.split_at_checked(1)
            && let pad = pad[0] as usize
            && let len = rest.len()
            && len >= pad
            && let (payload, hash) = rest.split_at(len - pad)
            && hash_xof(&mut self.hasher, payload, pad) == hash
        {
            Ok(Bytes::copy_from_slice(payload))
        } else {
            Err(InteractiveJobError::Decode)
        }
    }
}

/// Data packet encoder.
#[derive(Debug, Default)]
pub struct InteractiveJobEncoder {
    count: u64,
    hasher: Hasher,
}

impl InteractiveJobEncoder {
    pub fn count(&self) -> u64 {
        self.count + self.hasher.count()
    }

    pub fn rekey(
        &mut self,
        ping_bytes: Option<&Bytes>,
    ) -> Result<InteractiveJobMessage, InteractiveJobError> {
        let key_material = rand_key();
        let key = derive_key(INTERACTIVE_JOB_KEY_CONTEXT, &key_material);
        let message = if let Some(ping_bytes) = ping_bytes {
            InteractiveJobMessage::Pong(xor_bytes(&key_material, ping_bytes))
        } else {
            InteractiveJobMessage::Ping(key_material)
        };
        self.count += self.hasher.count();
        self.hasher = Hasher::new_keyed(&key);
        Ok(message)
    }

    pub fn encode(
        &mut self,
        message: InteractiveJobMessage,
    ) -> Result<WebSocketMessage, InteractiveJobError> {
        use InteractiveJobMessage as Message;
        use WebSocketMessage as WebSocket;
        match message {
            Message::Control(msg) => Ok(WebSocket::Text(to_json(&msg)?.into())),
            Message::Data(bytes) => Ok(WebSocket::Binary(self.encode_data(&bytes))),
            Message::Ping(bytes) => Ok(WebSocket::Ping(bytes)),
            Message::Pong(bytes) => Ok(WebSocket::Pong(bytes)),
            Message::Close => Ok(WebSocket::Close(None)),
        }
    }

    fn encode_data(&mut self, payload: &[u8]) -> Bytes {
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
    let mut key = BytesMut::zeroed(INTERACTIVE_JOB_KEY_LEN);
    OsRng.fill_bytes(&mut key);
    key.freeze()
}

fn rand_len() -> u8 {
    OsRng.gen_range(8..255)
}

fn xor_bytes(x: &Bytes, y: &Bytes) -> Bytes {
    x.iter().zip(y.iter()).map(|(x, y)| *x ^ *y).collect()
}

#[derive(Debug, Error)]
pub enum InteractiveJobError {
    #[error("Client closed connection")]
    Close,
    #[error("Can't decode interactive job data packet, synchronization lost")]
    Decode,
    #[error("Can't encode interactive job message")]
    Encode,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("I/O error: {0}")]
    IoErrno(#[from] rustix::io::Errno),
    #[error("Job ended")]
    JobEnded,
    #[error("Can't join task: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Can't (de)serialize JSON control message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Can't send shutdown signal")]
    Shutdown,
    #[error("WebSocket error: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::error::Error),
    #[error("Unsolicited ping from client")]
    UnsolicitedPing,
}

#[cfg(test)]
mod test {
    use rand::thread_rng;

    use super::*;

    #[test]
    fn round_trip_packets() {
        let mut server_decoder = InteractiveJobDecoder::default();
        let mut server_encoder = InteractiveJobEncoder::default();
        let mut client_decoder = InteractiveJobDecoder::default();
        let mut client_encoder = InteractiveJobEncoder::default();
        let mut count = 0;
        let mut rng = thread_rng();
        for i in 0..1000 {
            if i % 10 == 0 {
                let key;
                if let InteractiveJobMessage::Ping(bytes) = server_encoder.rekey(None).unwrap() {
                    key = bytes.clone();
                    client_decoder.rekey(bytes, None);
                } else {
                    panic!("invalid server rekey message");
                }

                if let InteractiveJobMessage::Pong(ckey) = client_encoder.rekey(Some(&key)).unwrap()
                {
                    server_decoder.rekey(ckey, Some(key));
                } else {
                    panic!("invalid client rekey message");
                }
            }

            let mut data = BytesMut::zeroed(rng.gen_range(0..1000));
            rng.fill_bytes(&mut data);
            count += data.len() as u64;

            let server_packet = server_encoder.encode_data(&data);
            assert_eq!(
                server_packet[0] as usize,
                server_packet.len() - data.len() - 1
            );
            assert_ne!(server_packet, data);

            let client_decoded = client_decoder.decode_data(&server_packet).unwrap();
            assert_eq!(data, client_decoded);
            assert_eq!(server_encoder.count(), count);
            assert_eq!(client_decoder.count(), count);

            let client_packet = client_encoder.encode_data(&client_decoded);
            assert_eq!(
                client_packet[0] as usize,
                client_packet.len() - client_decoded.len() - 1
            );
            assert_ne!(client_packet, client_decoded);

            let server_decoded = server_decoder.decode_data(&client_packet).unwrap();
            assert_eq!(data, server_decoded);
            assert_eq!(server_decoder.count(), count);
            assert_eq!(client_encoder.count(), count);
        }
    }
}
