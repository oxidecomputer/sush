//! Simple interactive job protocol over WebSockets.
//!
//! Data packets are sent as `Binary` messages. Control messages
//! (e.g., window change events) are encoded as JSON and sent as
//! `Text` messages:
//!
//! ```json
//! WindowChange { rows: 24, cols: 80 }
//! ```
//!
//! This protocol currently offers *no authentication or confidentiality*;
//! it *must* be run in production atop a secure transport protocol such
//! as sprockets or TLS.

use bytes::Bytes;
use rustix::termios::Winsize;
use serde::{Deserialize, Serialize};
use serde_json::{from_str as from_json, to_string as to_json};
use thiserror::Error;
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;

pub const INTERACTIVE_JOB_BUFFER_SIZE: usize = 0x10000;

/// An interactive job message.
#[derive(Clone, Debug)]
pub enum InteractiveJobMessage {
    Control(InteractiveJobControl),
    Data(Bytes),
    Ignore,
    Close,
}

impl TryFrom<WebSocketMessage> for InteractiveJobMessage {
    type Error = InteractiveJobError;

    fn try_from(message: WebSocketMessage) -> Result<Self, Self::Error> {
        match message {
            WebSocketMessage::Text(message) => Ok(Self::Control(from_json(&message)?)),
            WebSocketMessage::Binary(bytes) => Ok(Self::Data(bytes)),
            WebSocketMessage::Close(_) => Ok(Self::Close),
            _ => Ok(Self::Ignore),
        }
    }
}

impl TryInto<WebSocketMessage> for InteractiveJobMessage {
    type Error = InteractiveJobError;

    fn try_into(self) -> Result<WebSocketMessage, Self::Error> {
        match self {
            Self::Control(msg) => Ok(WebSocketMessage::Text(to_json(&msg)?.into())),
            Self::Data(bytes) => Ok(WebSocketMessage::Binary(bytes)),
            Self::Close => Ok(WebSocketMessage::Close(None)),
            Self::Ignore => Err(Self::Error::IgnoredMessage),
        }
    }
}

impl From<InteractiveJobControl> for InteractiveJobMessage {
    fn from(message: InteractiveJobControl) -> Self {
        Self::Control(message)
    }
}

/// An interactive job control message.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum InteractiveJobControl {
    WindowChange(WindowSize),
}

/// The size of an interactive job pseudoterminal.
/// Shells sometimes call these `$LINES` and `$COLUMNS`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WindowSize {
    pub rows: u16,
    pub cols: u16,
}

impl From<Winsize> for WindowSize {
    fn from(Winsize { ws_row, ws_col, .. }: Winsize) -> Self {
        Self {
            rows: ws_row,
            cols: ws_col,
        }
    }
}

impl From<WindowSize> for Winsize {
    fn from(WindowSize { rows, cols }: WindowSize) -> Self {
        Self {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

/// What went wrong with an interactive job.
#[derive(Debug, Error)]
pub enum InteractiveJobError {
    #[error("Ignored messages should not be sent")]
    IgnoredMessage,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("I/O error: {0}")]
    IoErrno(#[from] rustix::io::Errno),
    #[error("Can't join task: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Can't (de)serialize JSON control message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Can't send shutdown signal")]
    Shutdown,
    #[error("WebSocket error: {0}")]
    Tungstenite(#[from] tokio_tungstenite::tungstenite::error::Error),
}
