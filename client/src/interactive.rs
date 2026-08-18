// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Interactive jobs, client side.

use std::env;
use std::io::{Stdin, Stdout, stdin, stdout};
use std::os::fd::{AsFd, AsRawFd};

use bytes::{Buf as _, BytesMut};
use futures::{SinkExt as _, StreamExt as _};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr, tcsetwinsize};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tokio_fd::AsyncFd;
use tokio_tungstenite::WebSocketStream;

use sush_common::interactive::{
    INTERACTIVE_JOB_BUFFER_SIZE, InteractiveJobControl as Control, InteractiveJobError as Error,
    InteractiveJobMessage as Message, WindowSize,
};

/// Drive an interactive job, relaying stdin/stdout to/from a WebSocket.
/// The terminal is put into "raw" mode for the duration of `interactive_job_inner`,
/// and (we hope) restored when it ends.
pub async fn interactive_job<T>(stream: WebSocketStream<T>) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut stdin = stdin();
    let mut stdout = stdout();
    let mode = raw_mode(&stdin)?;
    let result = interactive_job_inner(&mut stdin, &mut stdout, stream).await;
    restore_mode(&stdin, mode)?;
    result
}

async fn interactive_job_inner<T>(
    stdin: &mut Stdin,
    stdout: &mut Stdout,
    mut stream: WebSocketStream<T>,
) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = BytesMut::with_capacity(INTERACTIVE_JOB_BUFFER_SIZE);
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigwinch = signal(SignalKind::window_change())?;
    let mut size = WindowSize::from(tcgetwinsize(&mut *stdin)?);
    let mut stdin_async = AsyncFd::try_from(stdin.as_raw_fd())?;
    let mut stdout_async = AsyncFd::try_from(stdout.as_raw_fd())?;
    loop {
        buffer.reserve(INTERACTIVE_JOB_BUFFER_SIZE);
        select! {
            // Relay input from the terminal.
            Ok(n) = stdin_async.read_buf(&mut buffer) => {
                // EOF or the telnet(1) “escape character”
                if n == 0 || buffer == "\x1d" {
                    break;
                }
                stream.send(Message::Data(buffer.copy_to_bytes(n)).try_into()?).await?;
                buffer.truncate(0);
            }

            // Handle a message from the server, or its disconnection.
            message = stream.next() => {
                let Some(message) = message else { break };
                match Message::try_from(message?)? {
                    Message::Control(control) => match control {
                        Control::WindowChange(new) => {
                            set_window_size(stdin, &mut stdout_async, new.clone()).await?;
                            size = new;
                        }
                    }
                    Message::Data(bytes) => {
                        stdout_async.write_all(&bytes).await?;
                    }
                    Message::Ignore => (),
                    Message::Close => break,
                }
            }

            // Send window size on change.
            // TODO: hysteresis control
            Some(()) = sigwinch.recv() => {
                size = send_window_size(stdin, &mut stream, size).await?;
            }

            // Break on other signals, errors, etc.
            _ = sighup.recv() => break,
            _ = sigint.recv() => break,
            _ = sigquit.recv() => break,
            _ = sigterm.recv() => break,
            else => break,
        }
    }
    let _ = stream.close(None).await;
    let _ = stream.flush().await;
    Ok(())
}

/// Send the current terminal window size as a control message.
async fn send_window_size<T>(
    stdin: &Stdin,
    stream: &mut WebSocketStream<T>,
    old: WindowSize,
) -> Result<WindowSize, Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let new = WindowSize::from(tcgetwinsize(stdin)?);
    if new == old {
        Ok(old)
    } else {
        stream
            .send(Message::from(Control::WindowChange(new.clone())).try_into()?)
            .await?;
        Ok(new)
    }
}

/// Reconcile the server's window size with our own. If they differ, it's
/// probably because we're attaching to a pre-existing job, so we should
/// adjust our window to fit it rather than vice-versa. We adjust the
/// window size by means of an XTerm Control Sequence if the terminal looks
/// compatible; otherwise, we fall back to raw ioctl (which will probably
/// not physically resize the terminal).
async fn set_window_size(
    stdin: &Stdin,
    mut stdout: impl AsyncWrite + Unpin,
    size: WindowSize,
) -> Result<(), Error> {
    if WindowSize::from(tcgetwinsize(stdin)?) != size {
        let WindowSize { rows, cols } = size;
        if let Ok(term) = env::var("TERM")
            && (term.starts_with("xterm") || term == "ghostty" || term == "wezterm")
        {
            let csi = "\x1b[";
            let seq = format!("{csi}8;{rows};{cols}t");
            stdout.write_all(seq.as_bytes()).await?;
            stdout.flush().await?;
        } else {
            tcsetwinsize(stdin, size.into())?;
        }
    }
    Ok(())
}

/// Put the client terminal in "raw" mode. This is always a risky
/// proposition; if an interactive job is interrupted, it may leave
/// the terminal in a corrupted state.
fn raw_mode(fd: impl AsFd) -> Result<Termios, Error> {
    let old = tcgetattr(&fd)?;
    let mut new = old.clone();
    new.make_raw();
    tcsetattr(&fd, OptionalActions::Drain, &new)?;
    Ok(old)
}

/// Restore the client terminal to its previous, "cooked" mode.
/// Does not send any terminal escape sequences, and so may not
/// actually reset the terminal to a good state.
fn restore_mode(fd: impl AsFd, mode: Termios) -> Result<(), Error> {
    tcsetattr(&fd, OptionalActions::Drain, &mode)?;

    // AsyncFd sets O_NONBLOCK, so we have to turn it back off again.
    let flags = fcntl_getfl(&fd)?;
    fcntl_setfl(&fd, flags & !OFlags::NONBLOCK)?;

    Ok(())
}
