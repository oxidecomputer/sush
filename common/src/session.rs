//! Interactive job sessions over WebSocket.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug)]
pub enum ClientMessage {
    Control(ClientControlMessage),
    Data(DataPacket),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ClientControlMessage {}

#[derive(Debug)]
pub struct DataPacket {
    _payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Can't connect, session is over")]
    Connect,
    #[error("Session I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Session I/O error: {0}")]
    IoErrno(#[from] rustix::io::Errno),
    #[error("Job ended")]
    JobEnded,
    #[error("Can't join session task: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("WebSocket error: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::error::Error),
}
