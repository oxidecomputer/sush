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
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::{ChildStderr, ChildStdout};
use tokio::sync::mpsc;
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;

use sush_common::interactive::WindowSize;
use sush_common::jobs::JobOutputStream::{self, *};

use crate::pty::{PtyReader, PtyWriter};

const INPUT_CHANNEL_CAPACITY: usize = 100;
const BATCH_OUTPUT_BUFFER_SIZE: usize = 0x10000;
const INTERACTIVE_OUTPUT_BUFFER_SIZE: usize = 0x2000;

pub enum JobIo {
    Interactive {
        pty: PtyReader,
        tx_input: mpsc::Sender<Bytes>,
    },
    Batch {
        stdout: ChildStdout,
        stderr: ChildStderr,
        stdout_eof: bool,
        stderr_eof: bool,
    },
}

impl JobIo {
    pub fn interactive(pty: PtyReader, writer: PtyWriter, stop: CancellationToken) -> Self {
        let (tx_input, rx_input) = mpsc::channel::<Bytes>(INPUT_CHANNEL_CAPACITY);
        spawn(Self::relay_input(rx_input, writer, stop));
        Self::Interactive { pty, tx_input }
    }

    pub fn batch(stdout: ChildStdout, stderr: ChildStderr) -> Self {
        Self::Batch {
            stdout,
            stderr,
            stdout_eof: false,
            stderr_eof: false,
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
            Self::Interactive { pty, .. } => {
                let mut buf = BytesMut::with_capacity(INTERACTIVE_OUTPUT_BUFFER_SIZE);
                let n = pty.read_buf(&mut buf).await?;
                Ok((Bytes::copy_from_slice(&buf[..n]), Stdout))
            }
            Self::Batch {
                stdout,
                stderr,
                stdout_eof,
                stderr_eof,
            } => {
                let mut stdout_buf = BytesMut::with_capacity(BATCH_OUTPUT_BUFFER_SIZE);
                let mut stderr_buf = BytesMut::with_capacity(BATCH_OUTPUT_BUFFER_SIZE);
                loop {
                    select! {
                        n = stdout.read_buf(&mut stdout_buf), if !*stdout_eof => {
                            match n? {
                                0 => *stdout_eof = true,
                                n => return Ok((Bytes::copy_from_slice(&stdout_buf[..n]), Stdout)),
                            }
                        }
                        n = stderr.read_buf(&mut stderr_buf), if !*stderr_eof => {
                            match n? {
                                0 => *stderr_eof = true,
                                n => return Ok((Bytes::copy_from_slice(&stderr_buf[..n]), Stderr)),
                            }
                        }
                        else => return Ok((Bytes::new(), Stdout)), // both streams at EOF
                    }
                }
            }
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
            Self::Interactive { pty, .. } => pty.get_window_size(),
            Self::Batch { .. } => Err(unsupported("batch jobs have no window size")),
        }
    }

    pub fn set_window_size(&mut self, size: WindowSize) -> io::Result<()> {
        match self {
            Self::Interactive { pty, .. } => pty.set_window_size(size),
            Self::Batch { .. } => Err(unsupported("batch jobs have no windows")),
        }
    }

    /// How long to keep reading output after the child dies.
    ///
    /// For a pty there is no EOF; a short quiet period is the
    /// only way to know we've drained (OpenSSH does this too).
    /// Pipes deliver EOF once every writer exits, so this is only
    /// a backstop against a descendant that escaped the process
    /// group while holding the inherited pipe open.
    pub fn drain_timeout(&self) -> Duration {
        match self {
            Self::Interactive { .. } => Duration::from_millis(10),
            Self::Batch { .. } => Duration::from_secs(5),
        }
    }
}

fn unsupported(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, msg)
}
