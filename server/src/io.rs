// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job process I/O.
//!
//! We handle interactive jobs, which have an attached pseudoterminal
//! (but no error output stream), as well as batch jobs, which do not
//! (but require additional bookkeeping to track EOF status). Input
//! to batch jobs is dropped; input to interactive jobs is relayed over
//! a bounded channel, and dropped if the channel is full.

use std::io;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use rustix::io::Errno;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::sync::mpsc;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

use sush_common::interactive::WindowSize;
use sush_common::jobs::JobOutputStream::{self, *};

use crate::pty::{PtyReader, PtyWriter};

const INPUT_CHANNEL_CAPACITY: usize = 100;
pub const BATCH_OUTPUT_BUFFER_SIZE: usize = 0x10000;
const INTERACTIVE_OUTPUT_BUFFER_SIZE: usize = 0x2000;

pub struct StreamState<R> {
    reader: R,
    buf: BytesMut,
    eof: bool,
    rec: bool,
}

impl<R: AsyncRead + Unpin> StreamState<R> {
    fn new(reader: R, buf_size: usize) -> Self {
        Self {
            reader,
            buf: BytesMut::with_capacity(buf_size),
            eof: false,
            rec: true,
        }
    }

    async fn read(&mut self) -> io::Result<Option<Bytes>> {
        self.buf.clear();
        match self.reader.read_buf(&mut self.buf).await? {
            0 => {
                self.eof = true;
                Ok(None)
            }
            _ if !self.rec => Ok(None),
            n => Ok(Some(Bytes::copy_from_slice(&self.buf[..n]))),
        }
    }
}

pub enum JobIo {
    Interactive {
        pty: StreamState<PtyReader>,
        tx_input: mpsc::Sender<Bytes>,
    },
    Batch {
        stdout: StreamState<ChildStdout>,
        stderr: StreamState<ChildStderr>,
    },
}

impl JobIo {
    pub fn interactive(pty: PtyReader, writer: PtyWriter, stop: CancellationToken) -> Self {
        let (tx_input, rx_input) = mpsc::channel::<Bytes>(INPUT_CHANNEL_CAPACITY);
        spawn(Self::relay_input(rx_input, writer, stop));
        Self::Interactive {
            pty: StreamState::new(pty, INTERACTIVE_OUTPUT_BUFFER_SIZE),
            tx_input,
        }
    }

    pub fn batch(stdout: ChildStdout, stderr: ChildStderr) -> Self {
        Self::Batch {
            stdout: StreamState::new(stdout, BATCH_OUTPUT_BUFFER_SIZE),
            stderr: StreamState::new(stderr, BATCH_OUTPUT_BUFFER_SIZE),
        }
    }

    async fn relay_input(
        mut rx_input: mpsc::Receiver<Bytes>,
        mut pty_writer: PtyWriter,
        stop: CancellationToken,
    ) -> io::Result<()> {
        loop {
            select! {
                recvd = rx_input.recv() => {
                    if let Some(input) = recvd {
                        pty_writer.write_all(&input).await?;
                    } else {
                        break;
                    }
                }
                _ = stop.cancelled() => {
                    break;
                }
            }
        }
        Ok::<_, io::Error>(())
    }

    pub async fn read_output(&mut self) -> io::Result<(Bytes, JobOutputStream)> {
        match self {
            Self::Interactive { pty, .. } => loop {
                match pty.read().await {
                    Ok(Some(b)) => return Ok((b, Stdout)),
                    Ok(None) if pty.eof => return Ok((Bytes::new(), Stdout)),
                    Ok(None) => (), // drained, keep reading
                    Err(error) if Errno::from_io_error(&error) == Some(Errno::IO) => {
                        // A pty master reads EIO once its last slave closes,
                        // which is EOF here, not an error.
                        return Ok((Bytes::new(), Stdout));
                    }
                    Err(error) => return Err(error),
                }
            },
            Self::Batch { stdout, stderr } => loop {
                select! {
                    r = stdout.read(), if !stdout.eof => {
                        if let Some(b) = r? {
                            return Ok((b, Stdout));
                        }
                    }
                    r = stderr.read(), if !stderr.eof => {
                        if let Some(b) = r? {
                            return Ok((b, Stderr));
                        }
                    }
                    else => return Ok((Bytes::new(), Stdout)), // both streams at EOF
                }
            },
        }
    }

    /// Drop input for batch jobs or if the channel is full.
    pub fn write_input(&mut self, buf: Bytes) {
        match self {
            Self::Interactive { tx_input, .. } => {
                let _ = tx_input.try_send(buf);
            }
            Self::Batch { .. } => (),
        }
    }

    pub fn get_window_size(&self) -> io::Result<WindowSize> {
        match self {
            Self::Interactive { pty, .. } => pty.reader.get_window_size(),
            Self::Batch { .. } => Err(unsupported("batch jobs have no window size")),
        }
    }

    pub fn set_window_size(&mut self, size: WindowSize) -> io::Result<()> {
        match self {
            Self::Interactive { pty, .. } => pty.reader.set_window_size(size),
            Self::Batch { .. } => Err(unsupported("batch jobs have no windows")),
        }
    }

    /// How long to keep reading output after the child dies.
    ///
    /// For a pty there is no portable EOF signal; a short window
    /// after death is the best we can do (OpenSSH does this too).
    /// Pipes deliver EOF once every writer exits, so this is only a
    /// backstop against a descendant that escaped the process group
    /// while holding the inherited pipe open.
    pub fn drain_timeout(&self) -> Duration {
        match self {
            Self::Interactive { .. } => Duration::from_millis(10),
            Self::Batch { .. } => Duration::from_secs(5),
        }
    }

    pub fn stop_recording(&mut self, stream: JobOutputStream) {
        match self {
            Self::Interactive { pty, .. } => pty.rec = false,
            Self::Batch { stdout, stderr, .. } => match stream {
                Stdout => stdout.rec = false,
                Stderr => stderr.rec = false,
            },
        }
    }
}

fn unsupported(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg)
}
