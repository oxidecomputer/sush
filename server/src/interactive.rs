//! Interactive jobs, server side.
//!
//! When a client attaches to an interactive job, what that means on the
//! server is that we have a new (stream made from a) WebSocket connection
//! with the (authenticated) client on the other end. So an _attachment
//! point_ is an MPSC channel over which we send the WebSocket stream,
//! i.e., a [`SocketSender`]. The interactive job `select!` loop will
//! receive the new socket and begin processing/relaying messages from/to
//! it.

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
use tokio::time::{Duration, Instant, MissedTickBehavior, interval, sleep};
use tokio::{pin, select, spawn};
use tokio_stream::StreamMap;
use tokio_tungstenite::WebSocketStream;

use sush_common::interactive::{
    INTERACTIVE_JOB_BUFFER_SIZE, INTERACTIVE_JOB_REKEY_PERIOD, InteractiveJobControl,
    InteractiveJobDecoder as Decoder, InteractiveJobEncoder as Encoder, InteractiveJobError,
    InteractiveJobMessage,
};
use tokio_util::sync::CancellationToken;

use crate::pty::Pty;

pub type SocketStream = WebSocketStream<WebsocketConnectionRaw>;
pub type SocketSender = mpsc::Sender<SocketStream>;
pub type SocketReceiver = mpsc::Receiver<SocketStream>;

pub struct InteractiveJob {
    task: JoinHandle<Result<ExitStatus, InteractiveJobError>>,
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

    pub async fn wait(self) -> Result<ExitStatus, InteractiveJobError> {
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
) -> Result<ExitStatus, InteractiveJobError> {
    type ClientId = usize;

    let mut buffer = BytesMut::with_capacity(INTERACTIVE_JOB_BUFFER_SIZE);
    let mut client_id: ClientId = 0;
    let mut streams = StreamMap::<ClientId, SocketStream>::new();
    let mut encoders = BTreeMap::<ClientId, (Encoder, Decoder)>::new();
    let mut pings = BTreeMap::<ClientId, Option<InteractiveJobMessage>>::new();
    let mut interval = interval(INTERACTIVE_JOB_REKEY_PERIOD);
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Client-induced errors must not break the loop;
    // close the client, log the error, and continue.
    macro_rules! close_client {
        ($client_id:expr, $stream:ident) => {{
            let _ = $stream.close(None).await;
            encoders.remove(&$client_id);
            pings.remove(&$client_id);
        }};
        ($client_id:expr, $stream:ident, $msg:literal; $($keys:tt)*) => {{
            close_client!($client_id, $stream);
            error!(log, $msg; $($keys)*);
            continue;
        }};
    }

    macro_rules! rekey_client {
        ($client_id:expr, $stream:ident, $encoder:ident) => {{
            let msg = $encoder.rekey(None)?;
            pings.insert($client_id, Some(msg.clone()));
            match $stream.send($encoder.encode(msg)?).await {
                Ok(()) => {
                    info!(log, "rekeyed interactive job encoder");
                }
                Err(error) => {
                    close_client!($client_id, $stream, "failed to rekey client"; "error" => %error);
                }
            }
        }};
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
                        // TODO: send in parallel
                        for (client_id, stream) in streams.iter_mut() {
                            if let Some((encoder, _decoder)) = encoders.get_mut(client_id) {
                                let message = InteractiveJobMessage::Data(data.clone());
                                match encoder.encode(message) {
                                    Ok(encoded) => if let Err(error) = stream.send(encoded).await {
                                        close_client!(client_id, stream, "failed to relay job output"; "error" => %error);
                                    }
                                    Err(error) => close_client!(client_id, stream, "failed to encode message"; "error" => %error),
                                }
                            }
                        }
                        buffer.truncate(0);
                        if dead {
                            drain_timeout.as_mut().reset(Instant::now() + DRAIN_TIMEOUT);
                        }
                    }
                    Err(error) => {
                        if !dead {
                            error!(log, "error reading from PTY"; "error" => %error);
                        }
                        break;
                    }
                }
            }

            // Accept a new client, rekey it, and play back the last buffer.
            Some(mut stream) = rx_client.recv(), if !dead => {
                client_id += 1;
                let decoder = Decoder::default();
                let mut encoder = Encoder::default();
                rekey_client!(client_id, stream, encoder);
                if let Some(playback) = playback_buffer(&mut output, INTERACTIVE_JOB_BUFFER_SIZE).await? {
                    let playback_len = playback.len();
                    let message = InteractiveJobMessage::Data(playback);
                    match encoder.encode(message) {
                        Ok(encoded) => match stream.send(encoded).await {
                            Ok(()) => debug!(log, "played back output"; "bytes" => playback_len),
                            Err(error) => close_client!(client_id, stream, "failed to play back job output"; "error" => %error),
                        }
                        Err(error) => close_client!(client_id, stream, "failed to encode message"; "error" => %error),
                    }
                }
                encoders.insert(client_id, (encoder, decoder));
                streams.insert(client_id, stream);
            }

            // Handle a message from a client.
            next = streams.next(), if !streams.is_empty() => {
                match next {
                    None => {
                        debug!(log, "all clients disconnected");
                    }
                    Some((client_id, Err(error))) => {
                        if let Some(mut stream) = streams.remove(&client_id) {
                            close_client!(client_id, stream, "client read error"; "error" => %error);
                        }
                    }
                    Some((client_id, Ok(message))) => {
                        if let Some((_encoder, decoder)) = encoders.get_mut(&client_id) {
                            match decoder.decode(message) {
                                Ok(message) => {
                                    match handle_client_message(
                                        &log,
                                        &mut pty,
                                        decoder,
                                        pings.entry(client_id).or_default(),
                                        message
                                    ).await {
                                        Ok(()) => (),
                                        Err(InteractiveJobError::Close) => {
                                            info!(log, "client closed connection");
                                        }
                                        Err(error) => {
                                            if let Some(mut stream) = streams.remove(&client_id) {
                                                close_client!(client_id, stream, "failed to handle client message"; "error" => %error);
                                            }
                                        }
                                    }
                                }
                                Err(error) => {
                                    if let Some(mut stream) = streams.remove(&client_id) {
                                        close_client!(client_id, stream, "failed to decode client message"; "error" => %error);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Periodically rekey all the clients.
            // TODO: independent, random intervals
            _ = interval.tick() => {
                for (client_id, stream) in streams.iter_mut() {
                    if let Some((encoder, _decoder)) = encoders.get_mut(&client_id) {
                        rekey_client!(*client_id, stream, encoder);
                    }
                }
            }

            // Stop job on cancellation signal, but only once.
            _ = stop.cancelled(), if !killed => {
                match child.start_kill() {
                    Ok(()) => debug!(log, "killed job processes"),
                    Err(err) => error!(log, "unable to kill job"; "error" => %err),
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
    for (client_id, stream) in streams.iter_mut() {
        close_client!(client_id, stream);
    }

    // Reap the process.
    let status = child.wait().await?;
    info!(log, "interactive job stopped");
    Ok(status)
}

async fn handle_client_message(
    log: &Logger,
    pty: &mut Pty,
    decoder: &mut Decoder,
    ping: &mut Option<InteractiveJobMessage>,
    message: InteractiveJobMessage,
) -> Result<(), InteractiveJobError> {
    use InteractiveJobMessage as Message;
    match message {
        Message::Control(message) => match message {
            InteractiveJobControl::WindowChange(size) => pty.set_window_size(size)?,
        },
        Message::Data(bytes) => pty.write_all(&bytes).await?,
        Message::Ping(_) => return Err(InteractiveJobError::UnsolicitedPing),
        Message::Pong(pong) => {
            if let Some(Message::Ping(ping)) = ping.take() {
                decoder.rekey(pong, Some(ping));
                info!(log, "rekeyed interactive job decoder");
            }
        }
        Message::Close => return Err(InteractiveJobError::Close),
    }
    Ok(())
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
