//! Interactive jobs, server side.
//!
//! When a client attaches to an interactive job, what that means on the
//! server is that we have a new (stream made from a) WebSocket connection
//! with the (authenticated) client on the other end. So an _attachment
//! point_ is an MPSC channel over which we send the WebSocket stream,
//! i.e., a [`SocketSender`]. The interactive job select loop receives
//! the new socket and begins processing/relaying messages from/to it.
//! Multiple clients may be simultaneously attached.

use std::collections::BTreeMap;
use std::io::{self, SeekFrom};
use std::process::ExitStatus;

use bytes::{Buf as _, Bytes, BytesMut};
use dropshot::WebsocketConnectionRaw;
use futures::{SinkExt as _, StreamExt as _};
use slog::{Logger, debug, error, info};
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, sleep};
use tokio::{pin, select, spawn};
use tokio_stream::StreamMap;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;

use sush_common::interactive::{
    INTERACTIVE_JOB_BUFFER_SIZE, InteractiveJobControl as Control, InteractiveJobError as Error,
    InteractiveJobMessage as Message,
};
use tokio_util::sync::CancellationToken;

use crate::pty::Pty;

pub type SocketStream = WebSocketStream<WebsocketConnectionRaw>;
pub type SocketSender = mpsc::Sender<SocketStream>;
pub type SocketReceiver = mpsc::Receiver<SocketStream>;

pub struct InteractiveJob {
    task: JoinHandle<Result<ExitStatus, Error>>,
    tx_client: SocketSender,
}

impl InteractiveJob {
    pub fn start(
        log: Logger,
        child: Child,
        pty: Pty,
        output: File,
        stop: CancellationToken,
    ) -> Self {
        let (tx_client, rx_client) = mpsc::channel::<SocketStream>(1);
        Self {
            task: spawn(interactive_job(log, child, pty, output, rx_client, stop)),
            tx_client,
        }
    }

    pub fn attachment(&self) -> SocketSender {
        self.tx_client.clone()
    }

    pub async fn wait(self) -> Result<ExitStatus, Error> {
        self.task.await?
    }
}

/// How long to continue trying to read from a dead job.
const DRAIN_TIMEOUT: Duration = Duration::from_millis(10);

/// Run an interactive job that allows, but does not require,
/// a client connection via WebSocket.
async fn interactive_job(
    log: Logger,
    mut child: Child,
    mut pty: Pty,
    mut output: File,
    mut rx_client: mpsc::Receiver<SocketStream>,
    stop: CancellationToken,
) -> Result<ExitStatus, Error> {
    type ClientId = usize;

    let mut buffer = BytesMut::with_capacity(INTERACTIVE_JOB_BUFFER_SIZE);
    let mut clients = StreamMap::<ClientId, SocketStream>::new();
    let mut client_id: ClientId = 0;

    // Client-induced errors must not break the loop;
    // close the client, log the error, and continue.
    macro_rules! close_client {
        ($client_id:ident) => {{
            if let Some(mut client) = clients.remove(&$client_id) {
                let _ = client.close(None).await;
            }
        }};
        ($client_id:ident, $msg:literal; $($keys:tt)*) => {{
            close_client!($client_id);
            error!(log, $msg; $($keys)*);
        }};
    }

    // Distribute a message to every client.
    // TODO: better, buffered broadcast
    macro_rules! broadcast {
        ($clients:ident, $message:expr) => {{
            let mut to_close = BTreeMap::new();
            for (client_id, client) in $clients.iter_mut() {
                if let Err(error) = client.send($message.clone()).await {
                    to_close.insert(*client_id, error);
                }
            }
            for (client_id, error) in to_close {
                close_client!(
                    client_id,
                    "failed to relay broadcast message";
                    "client_id" => %client_id,
                    "message" => %$message,
                    "error" => %error,
                );
            }
        }}
    }

    // Set up death watch and output drain timer.
    let mut killed = false;
    let mut dead = false;
    let drain_timeout = sleep(Duration::MAX);
    pin!(drain_timeout);

    // Handle interactive job events.
    loop {
        buffer.reserve(INTERACTIVE_JOB_BUFFER_SIZE);
        select! {
            // Read available job output, record it, and relay it to the clients
            // if there are any. We try to read regardless of whether the process
            // is known to be dead; it is essential to drain output that may be
            // sent before the process dies, but which arrives after detection
            // of its death.
            read = pty.read_buf(&mut buffer) => {
                match read {
                    Ok(0) => {
                        debug!(log, "EOF from job process");
                        break;
                    }
                    Ok(n) => {
                        output.write_all(&buffer[..n]).await?;
                        let data = buffer.copy_to_bytes(n);

                        // TODO: better broadcast
                        let Ok::<WebSocketMessage, _>(message) = Message::Data(data.clone()).try_into() else {
                            error!(log, "failed to encode data message for relay");
                            buffer.truncate(0);
                            continue;
                        };
                        broadcast!(clients, message);
                        buffer.truncate(0);
                    }
                    Err(error) => {
                        if !dead {
                            error!(log, "error reading from PTY"; "error" => %error);
                        }
                        break;
                    }
                }
            }

            // Attach a new client, send it the current window size, and play back the last buffer.
            Some(mut client) = rx_client.recv(), if !dead => {
                match pty.get_window_size() {
                    Err(error) => error!(log, "failed to get pseudoterminal window size"; "error" => %error),
                    Ok(size) => {
                        match client.send(Message::Control(Control::WindowChange(size.clone())).try_into()?).await {
                            Err(error) => error!(log, "failed to send pty window size"; "error" => %error),
                            Ok(()) => debug!(log, "sent pty window size"; "size" => ?size),
                        }
                    }
                }

                if let Some(playback) = playback_buffer(&mut output, INTERACTIVE_JOB_BUFFER_SIZE).await? {
                    let playback_len = playback.len();
                    match client.send(Message::Data(playback).try_into()?).await {
                        Err(error) => error!(log, "failed to play back job output"; "error" => %error),
                        Ok(()) => debug!(log, "played back output"; "bytes" => playback_len),
                    }
                }

                client_id += 1;
                clients.insert(client_id, client);
            }

            // Handle a message from a client.
            next = clients.next(), if !clients.is_empty() && !dead => {
                match next {
                    None => {
                        debug!(log, "all clients disconnected");
                    }
                    Some((client_id, Err(error))) => {
                        close_client!(client_id, "failed to read from client"; "error" => %error);
                    }
                    Some((client_id, Ok(message))) => {
                        match Message::try_from(message) {
                            Ok(Message::Control(message)) => match message {
                                Control::WindowChange(size) => {
                                    if let Err(error) = pty.set_window_size(size.clone()) {
                                        error!(log, "failed to set window size"; "size" => ?size, "error" => %error);
                                    }

                                    // TODO: better broadcast
                                    // TODO: hysteresis control
                                    let winch = Control::WindowChange(size.clone());
                                    let Ok::<WebSocketMessage, _>(message) = Message::Control(winch).try_into() else {
                                        error!(log, "failed to encode window change for relay");
                                        continue;
                                    };
                                    broadcast!(clients, message);
                                }
                            },
                            Ok(Message::Data(bytes)) => pty.write_all(&bytes).await?,
                            Ok(Message::Ignore) => (),
                            Ok(Message::Close) => {
                                close_client!(client_id);
                                info!(log, "client closed connection");
                            }
                            Err(error) => {
                                close_client!(client_id, "failed to decode message from client"; "error" => %error);
                            }
                        }
                    }
                }
            }

            // Stop job on cancellation signal, but only once.
            _ = stop.cancelled(), if !killed => {
                match child.start_kill() {
                    Err(err) => error!(log, "unable to kill job"; "error" => %err),
                    Ok(()) => debug!(log, "killed job processes"),
                }
                debug!(log, "killed job process");
                killed = true;
            }

            // Notice when the job dies, but do not exit the loop;
            // we must continue reading output until we hit EOF or
            // the drain timeout expires.
            _ = child.wait(), if !dead => {
                debug!(log, "reaped job process");
                drain_timeout.as_mut().reset(Instant::now() + DRAIN_TIMEOUT);
                dead = true;
            }

            // Give output a chance to drain from a dead process. It would
            // be great if there were a reliable, non-timeout way of doing
            // this, but it appears there is not. OpenSSH does this too, FWIW.
            _ = &mut drain_timeout, if dead => {
                debug!(log, "drained job output");
                break;
            }
        }
    }

    // Close clients.
    for client_id in clients.keys().cloned().collect::<Vec<ClientId>>() {
        close_client!(client_id);
    }

    // Reap the process.
    let status = child.wait().await?;
    info!(log, "interactive job stopped");
    Ok(status)
}

/// Fetch the last few bytes of the output file for client play back.
/// Errors here indicate problems with the output file, and so should
/// be treated as job-ending.
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

#[cfg(test)]
mod test {
    use std::fs::read_to_string;

    use slog::{Drain as _, o};
    use slog_term::{FullFormat, PlainSyncDecorator, TestStdoutWriter};
    use tempfile::NamedTempFile;
    use tokio::process::Command;

    use super::*;

    /// Exercise the race between process exit and slurping all of its
    /// output from the pseudoterminal.
    #[named]
    #[tokio::test]
    async fn tty() {
        for _ in 0..100 {
            let decorator = PlainSyncDecorator::new(TestStdoutWriter);
            let drain = FullFormat::new(decorator).build().fuse();
            let log = Logger::root(drain, o!("test" => function_name!()));
            let (pty, pts, pts_path) = Pty::open().unwrap();
            assert!(pts_path.starts_with("/dev/pts/"));

            let output_file = NamedTempFile::new().unwrap();
            let child = Command::new("tty")
                .stdin(pts.try_clone().unwrap())
                .stdout(pts.try_clone().unwrap())
                .spawn()
                .unwrap();
            let job = InteractiveJob::start(
                log,
                child,
                pty,
                output_file.reopen().unwrap().into(),
                CancellationToken::new(),
            );
            assert!(job.wait().await.unwrap().success());

            // The output of `tty` on GNU/Linux is written using puts(3),
            // which uses two write(2) calls: one for the string, and one
            // for the line terminator. If we don't drain with a timeout,
            // it is possible to catch the first write without the second.
            let output = read_to_string(&output_file).unwrap();
            assert_eq!(output, format!("{}\r\n", pts_path.display()));
        }
    }
}
