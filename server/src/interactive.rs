//! Interactive job sessions, server side.

use std::future::pending;
use std::io::{self, SeekFrom};
use std::process::ExitStatus;
use std::time::Duration;

use bytes::{Buf as _, Bytes, BytesMut};
use dropshot::WebsocketConnectionRaw;
use futures::{SinkExt as _, Stream, StreamExt as _};
use slog::{Logger, error, info};
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::process::Child;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{MissedTickBehavior, interval, sleep};
use tokio::{select, spawn};
use tokio_tungstenite::WebSocketStream;

use sush_common::interactive::{
    INTERACTIVE_SESSION_BUFFER_SIZE, INTERACTIVE_SESSION_REKEY_PERIOD, InteractiveSessionControl,
    InteractiveSessionDecoder, InteractiveSessionEncoder, InteractiveSessionError,
    InteractiveSessionMessage,
};

use crate::pty::Pty;

pub type ShutdownSession = oneshot::Sender<()>;
pub type SocketStream = WebSocketStream<WebsocketConnectionRaw>;
pub type SocketSender = mpsc::Sender<SocketStream>;

pub struct InteractiveSession {
    task: JoinHandle<Result<ExitStatus, InteractiveSessionError>>,
    tx_client: SocketSender,
}

impl InteractiveSession {
    pub fn start(log: Logger, child: Child, pty: Pty, output: File) -> (Self, ShutdownSession) {
        let (tx_client, rx_client) = mpsc::channel::<SocketStream>(1);
        let (tx_shutdown, rx_shutdown) = oneshot::channel();
        let task = spawn(interactive_session(
            log,
            child,
            pty,
            output,
            rx_client,
            rx_shutdown,
        ));
        (Self { task, tx_client }, tx_shutdown)
    }

    pub fn clients(&self) -> SocketSender {
        self.tx_client.clone()
    }

    pub async fn wait(self) -> Result<ExitStatus, InteractiveSessionError> {
        self.task.await?
    }
}

/// How long to continue trying to read from a dead process.
const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_millis(10);

/// Run an interactive job that allows, but does not require,
/// a client connection via WebSocket.
async fn interactive_session(
    log: Logger,
    mut child: Child,
    mut pty: Pty,
    mut output: File,
    mut rx_client: mpsc::Receiver<SocketStream>,
    mut rx_shutdown: oneshot::Receiver<()>,
) -> Result<ExitStatus, InteractiveSessionError> {
    let mut buffer = BytesMut::with_capacity(INTERACTIVE_SESSION_BUFFER_SIZE);
    let mut client = None::<SocketStream>;
    let mut ping = None::<InteractiveSessionMessage>;
    let mut decoder = InteractiveSessionDecoder::default();
    let mut encoder = InteractiveSessionEncoder::default();
    let mut interval = interval(INTERACTIVE_SESSION_REKEY_PERIOD);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut sigchld = signal(SignalKind::child())?;
    let mut shutdown = false;
    let mut died = false;

    // Client-induced errors must not break the loop;
    // close the client, log the error, and continue.
    macro_rules! close_client {
        ($stream:ident) => {{
            let _ = $stream.close(None).await;
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
            let msg = encoder.rekey(None)?;
            ping = Some(msg.clone());
            match $stream.send(encoder.encode(msg)?).await {
                Ok(()) => {
                    info!(log, "rekeyed session encoder");
                }
                Err(error) => {
                    close_client!($stream, "failed to rekey client"; "error" => %error);
                }
            }
        }};
    }

    loop {
        buffer.reserve(INTERACTIVE_SESSION_BUFFER_SIZE);
        select! {
            // Read available job output, record it, and relay it to the client
            // if there is one. We try to read regardless of whether the process
            // is known to be dead. It is essential to drain output that may be
            // sent before the process dies, but which arrives after the signal
            // of its death; the dead cannot speak, yet they may still be heard.
            Ok(n) = pty.read_buf(&mut buffer) => {
                if n == 0 {
                    info!(log, "EOF from job process");
                    break;
                }
                output.write_all(&buffer[..n]).await?;
                let data = buffer.copy_to_bytes(n);
                if let Some(stream) = client.as_mut() {
                    let message = InteractiveSessionMessage::Data(data);
                    if let Err(error) = stream.send(encoder.encode(message)?).await {
                        close_client!(stream, "failed to relay job output"; "error" => %error);
                    }
                }
                buffer.truncate(0);
            }

            // Give output a chance to drain from a dead process. It would
            // be great if there were a reliable, non-timeout way of doing
            // this, but it appears there is not. OpenSSH does this too, FWIW.
            _ = sleep(SESSION_DRAIN_TIMEOUT), if died || child.try_wait()?.is_some() => {
                info!(log, "job output drained");
                break;
            }

            // Accept a new client, rekey it, and play back the last buffer.
            Some(mut stream) = rx_client.recv(), if !died => {
                rekey_client!(stream);
                if let Some(playback) = playback_buffer(&mut output, INTERACTIVE_SESSION_BUFFER_SIZE).await? {
                    let playback_len = playback.len();
                    let message = InteractiveSessionMessage::Data(playback);
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
            Some(Ok(message)) = next_if_some(&mut client), if !died => {
                match decoder.decode(message) {
                    Ok(message) => {
                        if let Some(stream) = client.as_mut() {
                            match handle_client_message(&log, &mut pty, &mut decoder, &mut ping, message).await {
                                Ok(()) => (),
                                Err(InteractiveSessionError::Close) => {
                                    info!(log, "client closed connection");
                                    client = None;
                                }
                                Err(error) => {
                                    close_client!(stream, "failed to handle client message"; "error" => %error);
                                }
                            }
                        }
                    }
                    Err(error) => {
                        if let Some(stream) = client.as_mut() {
                            close_client!(stream, "failed to decode client message"; "error" => %error);
                        }
                    }
                }
            }

            // Periodically rekey the client.
            _ = interval.tick() => {
                if let Some(stream) = client.as_mut() {
                    rekey_client!(stream);
                }
            }

            // Notice when the job dies, but do not exit the loop;
            // we must continue reading output until we hit EOF or
            // the drain timeout expires.
            _ = sigchld.recv(), if !died => {
                info!(log, "job process died");
                died = true;
            }

            // Kill job on shutdown signal, but only once.
            Ok(()) = &mut rx_shutdown, if !died && !shutdown => {
                info!(log, "job shutdown on signal");
                child.start_kill()?;
                shutdown = true;
            }
        }
    }

    // Reap the job and collect its exit status.
    let status = child.wait().await?;
    if let Some(stream) = client.as_mut() {
        close_client!(stream);
    }
    info!(
        log,
        "interactive job ended";
        "encoded_bytes" => encoder.count(),
        "decoded_bytes" => decoder.count()
    );
    Ok(status)
}

async fn handle_client_message(
    log: &Logger,
    pty: &mut Pty,
    decoder: &mut InteractiveSessionDecoder,
    ping: &mut Option<InteractiveSessionMessage>,
    message: InteractiveSessionMessage,
) -> Result<(), InteractiveSessionError> {
    use InteractiveSessionMessage as ISM;
    match message {
        ISM::Control(message) => match message {
            InteractiveSessionControl::WindowChange(size) => pty.set_window_size(size)?,
        },
        ISM::Data(bytes) => pty.write_all(&bytes).await?,
        ISM::Ping(_) => return Err(InteractiveSessionError::UnsolicitedPing),
        ISM::Pong(pong) => {
            if let Some(ISM::Ping(ping)) = ping.take() {
                decoder.rekey(pong, Some(ping));
                info!(log, "rekeyed session decoder");
            }
        }
        ISM::Close => return Err(InteractiveSessionError::Close),
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
            let (session, shutdown) =
                InteractiveSession::start(log, child, pty, output_file.reopen().unwrap().into());
            assert!(session.wait().await.unwrap().success());
            assert!(shutdown.send(()).is_err());

            // The output of `tty` on GNU/Linux is written using puts(3),
            // which uses two write(2) calls: one for the string, and one
            // for the line terminator. If we don't drain with a timeout,
            // it is possible to catch the first write without the second.
            let output = read_to_string(&output_file).unwrap();
            assert_eq!(output, format!("{}\r\n", pts_path.display()));
        }
    }
}
