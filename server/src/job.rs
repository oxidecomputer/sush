// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Batch and interactive jobs, server side.
//!
//! Standard output and standard error streams for all jobs are hashed
//! online and recorded in files. If we cannot write to an output file,
//! the job is terminated.
//!
//! Batch jobs are treated as interactive jobs without a pseudoterminal
//! but with potentially non-trivial error output streams. Batch jobs
//! also don't need to drain their output; when we get EOF from both
//! output streams, we're done. Input to batch jobs is ignored.
//!
//! When a client attaches to a job, what that means is that we have a
//! new (stream made from a) WebSocket connection with the (authenticated)
//! client on the other end. So an _attachment point_ is an MPSC channel
//! over which we send the WebSocket stream, i.e., a [`SocketSender`].
//! The select loop receives the new socket and begins processing/relaying
//! messages from/to it. Multiple clients may be simultaneously attached
//! using a [`WebSocketMux`].

use std::io::{self, SeekFrom};
use std::os::unix::process::ExitStatusExt as _;
use std::process::ExitStatus;

use blake3::Hasher;
use bytes::{Bytes, BytesMut};
use dropshot::WebsocketConnectionRaw;
use futures::{SinkExt as _, StreamExt as _};
use slog::{Logger, debug, error, info, warn};
use tokio::fs::File;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::{Duration, Instant, sleep, timeout};
use tokio::{pin, select, spawn};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message as WebSocketMessage;

use sush_common::interactive::{
    INTERACTIVE_JOB_BUFFER_SIZE, InteractiveJobControl as Control, InteractiveJobMessage as Message,
};
use sush_common::jobs::{
    Access, JobLimits, JobOutputState, JobOutputStream::*, ProcessError, Streaming,
};
use tokio_util::sync::CancellationToken;

use crate::executor::kill_job;
use crate::io::JobIo;
use crate::mux::WebSocketMux;

pub type SocketStream = WebSocketStream<WebsocketConnectionRaw>;
pub type SocketSender = mpsc::Sender<(SocketStream, Access)>;
pub type SocketReceiver = mpsc::Receiver<(SocketStream, Access)>;

/// How long a finished streaming job waits for its consumer to
/// attach or make progress.
const STREAMING_LINGER: Duration = Duration::from_secs(600);

/// How long a single send to a streaming consumer may stall
/// before the job is cancelled.
const STREAMING_SEND_TIMEOUT: Duration = Duration::from_secs(60);

pub struct Job {
    task: JoinHandle<(Result<i32, ProcessError>, JobOutputState)>,
    tx_client: SocketSender,
}

impl Job {
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        log: Logger,
        limits: JobLimits,
        child: Child,
        io: JobIo,
        stdout: File,
        stderr: File,
        streaming: Streaming,
        stop: CancellationToken,
    ) -> Self {
        let (tx_client, rx_client) = mpsc::channel(1);
        Self {
            task: spawn(job(
                log, limits, child, io, stdout, stderr, streaming, rx_client, stop,
            )),
            tx_client,
        }
    }

    pub fn attachment(&self) -> SocketSender {
        self.tx_client.clone()
    }

    pub async fn wait(self) -> Result<(Result<i32, ProcessError>, JobOutputState), JoinError> {
        self.task.await
    }
}

/// Run a job that allows for client connections.
/// It need not have a controlling (pseudo)terminal.
#[allow(clippy::too_many_arguments)]
async fn job(
    log: Logger,
    JobLimits { max_fsize, .. }: JobLimits,
    mut child: Child,
    mut io: JobIo,
    mut stdout_file: File,
    mut stderr_file: File,
    streaming: Streaming,
    mut rx_client: SocketReceiver,
    stop: CancellationToken,
) -> (Result<i32, ProcessError>, JobOutputState) {
    let mut stdout_hasher = Hasher::new();
    let mut stderr_hasher = Hasher::new();
    let mut clients = WebSocketMux::new();
    let mut fatal = Option::<ProcessError>::None;
    let mut killed = false;
    let mut dead = false;
    let streaming = matches!(streaming, Streaming::Output);
    let mut pending = Option::<Bytes>::None;
    let mut attached = false;
    let (tx_output, rx_output) = mpsc::channel(1);
    let (tx_socket, rx_socket) = mpsc::channel(1);
    if streaming {
        spawn(stream_output(
            log.clone(),
            rx_socket,
            rx_output,
            stop.clone(),
        ));
    }
    let mut eof = false;
    let drain_timeout = sleep(Duration::default());
    pin!(drain_timeout);
    let linger = sleep(Duration::default());
    pin!(linger);
    loop {
        // A finished stream is done once its consumer has taken every chunk.
        if eof && attached && pending.is_none() {
            break;
        }
        select! {
            // Read available job output, record it, and relay it to the clients
            // if there are any. We try to read regardless of whether the process
            // is known to be dead; it is essential to drain output that may be
            // sent before it dies, but which arrives after detection of its death.
            read = io.read_output(), if pending.is_none() && !eof => {
                match read {
                    Ok((buf, _)) if buf.is_empty() => {
                        debug!(log, "EOF on all job output streams");
                        if !streaming {
                            break;
                        }
                        eof = true;
                        linger.as_mut().reset(Instant::now() + STREAMING_LINGER);
                    }
                    Ok((buf, stream)) => {
                        if dead && streaming {
                            drain_timeout.as_mut().reset(Instant::now() + io.drain_timeout());
                        }
                        match stream {
                            Stdout if streaming => {
                                stdout_hasher.update(&buf);
                                pending = Some(buf);
                                continue;
                            }
                            Stdout => {
                                stdout_hasher.update(&buf);
                                if let Err(error) = stdout_file.write_all(&buf).await {
                                    error!(log, "failed to record standard output"; "error" => %error);
                                    stop.cancel();
                                }
                                if stdout_hasher.count() > max_fsize {
                                    error!(log, "standard output over limit"; "max_fsize" => %max_fsize);
                                    io.stop_recording(stream);
                                    stop.cancel();
                                    fatal.get_or_insert(ProcessError::OutputLimitExceeded {
                                        stream,
                                        limit: max_fsize,
                                    });
                                }
                            }
                            Stderr => {
                                stderr_hasher.update(&buf);
                                if let Err(error) = stderr_file.write_all(&buf).await {
                                    error!(log, "failed to record error output"; "error" => %error);
                                    stop.cancel();
                                }
                                if stderr_hasher.count() > max_fsize {
                                    error!(log, "error output over limit"; "max_fsize" => %max_fsize);
                                    io.stop_recording(stream);
                                    stop.cancel();
                                    fatal.get_or_insert(ProcessError::OutputLimitExceeded {
                                        stream,
                                        limit: max_fsize,
                                    });
                                }
                            }
                        }
                        if !clients.is_empty() {
                            let Ok::<WebSocketMessage, _>(message) = Message::Data(buf).try_into() else {
                                error!(log, "failed to encode data message for relay");
                                continue;
                            };
                            if let Err(error) = clients.send(message) {
                                error!(log, "failed to relay data message to clients"; "error" => %error);
                            }
                        }
                    }
                    Err(error) => {
                        if !dead {
                            error!(log, "error reading from job process"; "error" => %error);
                        }
                        if streaming {
                            eof = true;
                            linger.as_mut().reset(Instant::now() + STREAMING_LINGER);
                            continue;
                        }
                        if let Err(error) = clients.send(Message::Close.try_into().unwrap()) {
                            error!(log, "failed to send close message to clients"; "error" => %error);
                        }
                        break;
                    }
                }
            }

            permit = tx_output.reserve(), if pending.is_some() => {
                match permit {
                    Ok(permit) => {
                        if dead {
                            drain_timeout.as_mut().reset(Instant::now() + io.drain_timeout());
                        }
                        if eof {
                            linger.as_mut().reset(Instant::now() + STREAMING_LINGER);
                        }
                        if let Some(buf) = pending.take() {
                            permit.send(buf);
                        }
                    }
                    Err(_) => pending = None,
                }
            }

            // Attach a new client, send it the current window size, and play back the last buffer.
            // Streaming jobs accept one read-write consumer, even posthumously.
            Some((client, access)) = rx_client.recv(), if !dead || streaming => {
                if streaming {
                    if access != Access::ReadWrite || attached || tx_socket.try_send(client).is_err() {
                        debug!(log, "refused streaming client");
                    } else {
                        attached = true;
                    }
                    continue;
                }
                let mut initial = Vec::new();
                match io.get_window_size() {
                    Err(error) => error!(log, "failed to get pseudoterminal window size"; "error" => %error),
                    Ok(size) => {
                        debug!(log, "sending pty window size"; "size" => ?size);
                        initial.push(Message::Control(Control::WindowChange(size)).try_into().unwrap());
                    }
                }

                if let Ok(Some(playback)) = playback_buffer(&mut stdout_file, INTERACTIVE_JOB_BUFFER_SIZE).await {
                    debug!(log, "playing back output"; "bytes" => playback.len());
                    initial.push(Message::Data(playback).try_into().unwrap());
                }

                clients.add(client, access, initial, stop.child_token());
            }

            // Handle a message from a client.
            next = clients.next(), if !clients.is_empty() && !dead => {
                match next {
                    None => {
                        debug!(log, "all clients disconnected");
                    }
                    Some((client_id, Err(error))) => {
                        error!(log, "failed to read from client"; "client_id" => %client_id, "error" => %error);
                        clients.remove(&client_id);
                    }
                    Some((client_id, Ok(message))) => {
                        let read_only = clients.access(&client_id) == Some(Access::ReadOnly);
                        match Message::try_from(message) {
                            Ok(_) if read_only => (),
                            Ok(Message::Control(message)) => match message {
                                Control::WindowChange(size) => {
                                    if let Err(error) = io.set_window_size(size.clone()) {
                                        error!(log, "failed to set window size"; "size" => ?size, "error" => %error);
                                    }

                                    // TODO: hysteresis control
                                    let winch = Control::WindowChange(size.clone());
                                    let Ok::<WebSocketMessage, _>(message) = Message::Control(winch).try_into() else {
                                        error!(log, "failed to encode window change for relay");
                                        continue;
                                    };
                                    if let Err(error) = clients.send(message) {
                                        error!(log, "failed to relay window change to clients"; "client_id" => %client_id, "error" => %error);
                                    }
                                }
                            },
                            Ok(Message::Data(bytes)) => io.write_input(bytes),
                            Ok(Message::Ignore) => (),
                            Ok(Message::Close) => {
                                info!(log, "client closed connection"; "client_id" => %client_id);
                                clients.remove(&client_id);
                            }
                            Err(error) => {
                                error!(log, "failed to decode message from client"; "client_id" => %client_id, "error" => %error);
                                clients.remove(&client_id);
                            }
                        }
                    }
                }
            }

            // Stop job on cancellation signal, but only once.
            _ = stop.cancelled(), if !killed => {
                kill_job(&log, &child);
                killed = true;
            }

            // Notice when the job dies, but do not exit the loop;
            // we must continue reading output until we hit EOF or
            // the drain timeout expires.
            _ = child.wait(), if !dead => {
                debug!(log, "reaped job process");
                drain_timeout.as_mut().reset(Instant::now() + io.drain_timeout());
                dead = true;
            }

            // Give up on a stream whose consumer never drained it.
            _ = &mut linger, if eof => {
                warn!(log, "streaming consumer never drained the output");
                break;
            }

            // Give output a chance to drain from a dead process.
            _ = &mut drain_timeout, if dead && !eof => {
                match io {
                    JobIo::Interactive { .. } => debug!(log, "drained job output"),
                    JobIo::Batch { .. } => warn!(
                        log,
                        "batch job output pipes never closed, possible escaped descendant";
                        "timeout_ms" => %io.drain_timeout().as_millis()
                    ),
                }
                break;
            }
        }
    }

    if let Some(buf) = pending {
        let _ = tx_output.try_send(buf);
    }

    // Reap the process.
    let exit_status = select! {
        status = child.wait() => status,
        _ = stop.cancelled(), if !killed => {
            kill_job(&log, &child);
            child.wait().await
        }
    };
    let result = match fatal {
        Some(error) => Err(error),
        None => match exit_status {
            Ok(status) => process_exit(status),
            Err(error) => Err(ProcessError::Interactive(error.to_string())),
        },
    };
    info!(log, "job stopped");

    // Construct the output state directly from the hashers;
    // no need to hit the file system.
    let output_state = JobOutputState {
        stdout_len: stdout_hasher.count(),
        stderr_len: stderr_hasher.count(),
        stdout_hash: stdout_hasher.finalize().into(),
        stderr_hash: stderr_hasher.finalize().into(),
    };

    (result, output_state)
}

/// Deliver streamed output to the single attached client.
async fn stream_output(
    log: Logger,
    mut rx_socket: mpsc::Receiver<SocketStream>,
    mut rx_output: mpsc::Receiver<Bytes>,
    stop: CancellationToken,
) {
    let Some(mut client) = rx_socket.recv().await else {
        return;
    };
    while let Some(buf) = rx_output.recv().await {
        match timeout(
            STREAMING_SEND_TIMEOUT,
            client.send(Message::Data(buf).try_into().unwrap()),
        )
        .await
        {
            Ok(Ok(())) => continue,
            Ok(Err(error)) => error!(log, "failed to stream output to client"; "error" => %error),
            Err(_) => error!(log, "timed out streaming output to client"),
        }
        stop.cancel();
        return;
    }
    let _ = timeout(STREAMING_SEND_TIMEOUT, async {
        let _ = client.send(Message::Close.try_into().unwrap()).await;
        let _ = client.close(None).await;
    })
    .await;
}

fn process_exit(exit_status: ExitStatus) -> Result<i32, ProcessError> {
    if let Some(code) = exit_status.code() {
        Ok(code)
    } else if let Some(signal) = exit_status.signal() {
        Err(ProcessError::Killed(signal))
    } else {
        // Processes should either exit with a code or
        // be killed by a signal; there is no third option
        // on Unix. But since the type system does not
        // guarantee that, this branch is technically
        // reachable, but impossible in practice.
        Err(ProcessError::Unknown)
    }
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

    use crate::io::JobIo;
    use crate::pty::open_pty;

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
            let (pty, writer, pts, pts_path) = open_pty().unwrap();
            assert!(pts_path.starts_with("/dev/pts/"));

            let output_file = NamedTempFile::new().unwrap();
            let child = Command::new("tty")
                .stdin(pts.try_clone().unwrap())
                .stdout(pts.try_clone().unwrap())
                .spawn()
                .unwrap();
            let stop = CancellationToken::new();
            let io = JobIo::interactive(pty, writer, stop.child_token());
            let job = Job::start(
                log,
                JobLimits::default(),
                child,
                io,
                output_file.reopen().unwrap().into(),
                File::options()
                    .append(true)
                    .open("/dev/null")
                    .await
                    .unwrap(),
                Streaming::None,
                stop,
            );
            assert_eq!(job.wait().await.unwrap().0.unwrap(), 0);

            // The output of `tty` on GNU/Linux is written using puts(3),
            // which uses two write(2) calls: one for the string, and one
            // for the line terminator. If we don't drain with a timeout,
            // it is possible to catch the first write without the second.
            let output = read_to_string(&output_file).unwrap();
            assert_eq!(output, format!("{}\r\n", pts_path.display()));
        }
    }
}
