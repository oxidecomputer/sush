//! Interactive job sessions, server side.

use std::future::pending;
use std::io::SeekFrom;

use dropshot::WebsocketConnectionRaw;
use futures::{SinkExt as _, Stream, StreamExt as _};
use rust_pty::{UnixPtyMaster, WindowSize};
use serde_json::from_str as from_json;
use slog::{Logger, error, info};
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::{select, spawn};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message};

use sush_common::codephrases::generate_id;
use sush_common::session::{ClientControlMessage, SessionError};

pub type SocketStream = WebSocketStream<WebsocketConnectionRaw>;
pub type SocketSender = mpsc::Sender<SocketStream>;

pub struct Session {
    task: JoinHandle<Result<(), SessionError>>,
    tx_client: SocketSender,
    tx_shutdown: oneshot::Sender<()>,
}

impl Session {
    const SESSION_BUFFER_SIZE: usize = 0xFFFF;

    pub fn start(log: Logger, mut output_file: File, mut pty: UnixPtyMaster) -> Self {
        let (tx_client, mut rx_client) = mpsc::channel::<SocketStream>(1);
        let (tx_shutdown, mut rx_shutdown) = oneshot::channel();
        let task = spawn({
            async move {
                let mut buffer = Vec::with_capacity(Self::SESSION_BUFFER_SIZE);
                let mut client: Option<SocketStream> = None;
                let mut client_id = generate_id();
                loop {
                    select! {
                        Ok(n) = pty.read_buf(&mut buffer) => {
                            // Relay output from the job.
                            if n == 0 {
                                error!(log, "EOF from interactive job");
                                break;
                            } else {
                                output_file.write_all(&buffer[..n]).await?;
                            }
                            if let Some(ref mut client) = client {
                                let message = Message::Binary(buffer.drain(..n).collect());
                                if let Err(error) = client.send(message).await {
                                    error!(log, "can't send message to client"; "error" => %error);
                                }
                            }
                        }
                        Some(mut stream) = rx_client.recv() => {
                            // Accept a new client connection.
                            client_id = generate_id();
                            if let Err(error) = stream.send(Message::Ping(client_id.clone().into())).await {
                                error!(log, "can't ping client"; "error" => %error);
                            }
                            if let Err(error) = playback(
                                &mut output_file,
                                &mut stream,
                                Self::SESSION_BUFFER_SIZE as i64
                            ).await {
                                error!(log, "can't playback job output for client"; "error" => %error);
                                continue;
                            }
                            if let Err(error) = stream.flush().await {
                                error!(log, "can't flush client socket"; "error" => %error);
                            }
                            client = Some(stream);
                        }
                        Some(Ok(message)) = next_if_some(&mut client) => {
                            // Handle a message from the client.
                            match message {
                                Message::Text(message) => {
                                    match from_json::<ClientControlMessage>(&message) {
                                        Ok(ClientControlMessage::WindowSize { cols, rows }) => {
                                            info!(log, "received window size message"; "cols" => cols, "rows" => rows);
                                            if let Err(error) = pty.set_window_size(WindowSize::new(cols, rows)) {
                                                error!(log, "can't set window size"; "error" => %error);
                                            }
                                        }
                                        Err(error) => {
                                            error!(log, "received invalid control message"; "error" => %error);
                                        }
                                    }
                                }
                                Message::Binary(bytes) => {
                                    pty.write_all(&bytes).await?;
                                }
                                Message::Ping(bytes) => {
                                    if let Some(ref mut client) = client
                                        && let Err(error) = client.send(Message::Pong(bytes)).await {
                                        error!(log, "can't respond to ping from client"; "error" => %error);
                                    }
                                }
                                Message::Pong(bytes) => {
                                    let pong = String::from_utf8_lossy(&bytes);
                                    if pong != client_id  {
                                        error!(log, "invalid pong from client"; "pong" => pong, "nonce" => %client_id);
                                    }
                                },
                                Message::Close(_) => break,
                                Message::Frame(_) => unreachable!("should not receive raw frame"),
                            }
                        }
                        Ok(()) = &mut rx_shutdown => {
                            // Shut it down!
                            if let Some(ref mut client) = client {
                                let _ = client
                                    .close(Some(CloseFrame {
                                        code: CloseCode::Normal,
                                        reason: "job ended".into(),
                                    }))
                                    .await;
                            }
                            break;
                        },
                        else => break,
                    }
                }
                output_file.flush().await?;
                Ok::<_, SessionError>(())
            }
        });

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

/// Clients may connect and disconnect at will (but only one at a time).
/// This helper lets us poll optional clients in a `select!` loop. From
/// <https://users.rust-lang.org/t/optional-future-for-optional-connections/77005>
async fn next_if_some<S>(s: &mut Option<S>) -> Option<S::Item>
where
    S: Stream + Unpin,
{
    match s.as_mut() {
        Some(stream) => stream.next().await,
        None => pending().await,
    }
}

/// Play back the last few bytes of the output file.
async fn playback(
    output_file: &mut File,
    stream: &mut SocketStream,
    n: i64,
) -> Result<i64, SessionError> {
    let len = output_file.metadata().await?.len();
    let n = n.min(len as i64);
    output_file.seek(SeekFrom::End(-n)).await?;

    let mut buf = Vec::with_capacity(n as usize);
    output_file.read_buf(&mut buf).await?;
    let msg = Message::Binary(buf.into());
    stream.send(msg).await?;

    Ok(n)
}
