//! Interactive job sessions, server side.

use std::future::pending;
use std::io::{self, SeekFrom};

use bytes::{Buf as _, Bytes, BytesMut};
use dropshot::WebsocketConnectionRaw;
use futures::{SinkExt as _, Stream, StreamExt as _};
use rust_pty::{UnixPtyMaster, WindowSize};
use slog::{Logger, error, info};
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval};
use tokio::{select, spawn};
use tokio_tungstenite::WebSocketStream;

use sush_common::session::{
    SESSION_BUFFER_SIZE, SESSION_REKEY_PERIOD, SessionControl, SessionDecoder, SessionEncoder,
    SessionError, SessionMessage,
};

pub type SocketStream = WebSocketStream<WebsocketConnectionRaw>;
pub type SocketSender = mpsc::Sender<SocketStream>;

pub struct Session {
    task: JoinHandle<Result<(), SessionError>>,
    tx_client: SocketSender,
    tx_shutdown: oneshot::Sender<()>,
}

impl Session {
    pub fn start(log: Logger, output_file: File, pty: UnixPtyMaster) -> Self {
        let (tx_client, rx_client) = mpsc::channel::<SocketStream>(1);
        let (tx_shutdown, rx_shutdown) = oneshot::channel();
        let task = spawn(session(log, output_file, pty, rx_client, rx_shutdown));
        Self {
            task,
            tx_client,
            tx_shutdown,
        }
    }

    pub fn clients(&self) -> SocketSender {
        self.tx_client.clone()
    }

    pub async fn shutdown(self) -> Result<(), SessionError> {
        let _ = self.tx_shutdown.send(());
        self.task.await??;
        Ok(())
    }
}

/// Run an interactive job that allows, but does not require,
/// a client connection via WebSocket.
async fn session(
    log: Logger,
    mut output_file: File,
    mut pty: UnixPtyMaster,
    mut rx_client: mpsc::Receiver<SocketStream>,
    mut rx_shutdown: oneshot::Receiver<()>,
) -> Result<(), SessionError> {
    let mut buffer = BytesMut::with_capacity(SESSION_BUFFER_SIZE);
    let mut client = None::<SocketStream>;
    let mut decoder = SessionDecoder::default();
    let mut encoder = SessionEncoder::default();
    let mut interval = interval(SESSION_REKEY_PERIOD);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Client-induced errors must not break the loop;
    // close the client, log the error, and continue.
    macro_rules! close_client {
        ($stream:ident) => {{
            let _ = $stream.close(None).await;
            let _ = $stream.flush().await;
            client.take();
        }};
        ($stream:ident, $msg:literal; $($keys:tt)*) => {{
            close_client!($stream);
            error!(log, $msg; $($keys)*);
            continue;
        }};
    }

    macro_rules! rekey_client {
        ($stream:ident) => {{
            match $stream.send(encoder.rekey(None)?).await {
                Ok(()) => info!(log, "rekeyed session encoder"),
                Err(error) => {
                    close_client!($stream, "failed to rekey client"; "error" => %error);
                }
            }
        }};
    }

    loop {
        select! {
            // Read job output, record it, and relay it to the client if there is one.
            Ok(n) = pty.read_buf(&mut buffer) => {
                if n == 0 {
                    error!(log, "EOF from interactive job");
                    break;
                }
                output_file.write_all(&buffer[..n]).await?;
                if let Some(stream) = client.as_mut() {
                    let message = SessionMessage::Data(buffer.copy_to_bytes(n));
                    if let Err(error) = stream.send(encoder.encode(message)?).await {
                        close_client!(stream, "failed to relay job output"; "error" => %error);
                    }
                }
                buffer.truncate(0);
            }

            // Accept a new client, rekey it, and play back the last buffer.
            Some(mut stream) = rx_client.recv() => {
                rekey_client!(stream);
                if let Some(playback) = playback_buffer(&mut output_file, SESSION_BUFFER_SIZE).await? {
                    let playback_len = playback.len();
                    let message = SessionMessage::Data(playback);
                    match stream.send(encoder.encode(message)?).await {
                        Ok(()) => {
                            info!(log, "played back output"; "bytes" => playback_len);
                        }
                        Err(error) => {
                            close_client!(stream, "failed to play back output"; "error" => %error);
                        }
                    }
                }
                client = Some(stream);
            }

            // Handle a message from the client.
            Some(Ok(message)) = next_if_some(&mut client) => {
                match decoder.decode(message) {
                    Err(error) => error!(log, "failed to decode client message"; "error" => %error),
                    Ok(message) => {
                        if let Some(stream) = client.as_mut() {
                            match handle_client_message(&log, &mut pty, &mut decoder, message).await {
                                Ok(()) => (),
                                Err(SessionError::Close) => {
                                    info!(log, "client closed connection");
                                    client = None;
                                }
                                Err(error) => {
                                    close_client!(stream, "failed to handle client message"; "error" => %error);
                                }
                            }
                        }
                    }
                }
            }

            // Periodically rekey.
            _ = interval.tick() => {
                if let Some(stream) = client.as_mut() {
                    rekey_client!(stream);
                }
            }

            // Shutdown when the job ends.
            Ok(()) = &mut rx_shutdown => break,

            // Errors, etc.
            else => break,
        }
    }

    output_file.flush().await?;
    if let Some(stream) = client.as_mut() {
        close_client!(stream);
    }
    info!(
        log,
        "session ended";
        "encoded_bytes" => encoder.count(),
        "decoded_bytes" => decoder.count()
    );
    Ok(())
}

async fn handle_client_message(
    log: &Logger,
    pty: &mut UnixPtyMaster,
    decoder: &mut SessionDecoder,
    message: SessionMessage,
) -> Result<(), SessionError> {
    match message {
        SessionMessage::Control(message) => match message {
            SessionControl::WindowChange { cols, rows } => {
                pty.set_window_size(WindowSize::new(cols, rows))?;
            }
        },
        SessionMessage::Data(bytes) => pty.write_all(&bytes).await?,
        SessionMessage::Ping(_) => (),
        SessionMessage::Pong(bytes) => {
            decoder.rekey(&bytes);
            info!(log, "rekeyed session decoder");
        }
        SessionMessage::Close => return Err(SessionError::Close),
    }
    Ok(())
}

/// Clients may connect and disconnect at will (but only one at a time).
/// This helper lets us poll optional clients in a `select!` loop. From
/// <https://users.rust-lang.org/t/optional-future-for-optional-connections/77005>
async fn next_if_some<S>(s: &mut Option<S>) -> Option<S::Item>
where
    S: Stream + Unpin,
{
    match s.as_mut() {
        None => pending().await,
        Some(stream) => stream.next().await,
    }
}

/// Fetch the last few bytes of the output file for client play back.
/// Errors here indicate problems with the output file, and so should
/// be treated as session-ending.
async fn playback_buffer(
    output_file: &mut File,
    output_bytes: usize,
) -> Result<Option<Bytes>, io::Error> {
    let output_len = output_file.metadata().await?.len();
    let output_bytes = output_len.min(output_bytes as u64) as i64;
    if output_bytes == 0 {
        return Ok(None);
    }

    output_file.seek(SeekFrom::End(-output_bytes)).await?;
    let mut buffer = BytesMut::zeroed(output_bytes as usize);
    output_file.read_exact(&mut buffer).await?;
    Ok(Some(buffer.freeze()))
}
