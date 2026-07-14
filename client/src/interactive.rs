//! Interactive jobs, client side.

use std::io::{Stdin, Stdout, stdin, stdout};
use std::os::fd::{AsFd, AsRawFd};

use bytes::{Buf as _, BytesMut};
use futures::{SinkExt as _, StreamExt as _};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::select;
use tokio::signal::unix::{SignalKind, signal};
use tokio_fd::AsyncFd;
use tokio_tungstenite::WebSocketStream;

use sush_common::interactive::{
    INTERACTIVE_JOB_BUFFER_SIZE, InteractiveJobControl, InteractiveJobDecoder,
    InteractiveJobEncoder, InteractiveJobError, InteractiveJobMessage, WindowSize,
};

/// Drive an interactive job, relaying stdin/stdout to/from a WebSocket.
/// The terminal is put into "raw" mode for the duration of `interactive_job_inner`,
/// and (we hope) restored when it ends.
pub async fn interactive_job<T>(stream: WebSocketStream<T>) -> Result<(), InteractiveJobError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    let stdin = stdin();
    let stdout = stdout();
    let mode = raw_mode(&stdin)?;
    let result = interactive_job_inner(&stdin, &stdout, stream).await;
    restore_mode(&stdin, mode)?;
    result
}

async fn interactive_job_inner<T>(
    stdin: &Stdin,
    stdout: &Stdout,
    mut stream: WebSocketStream<T>,
) -> Result<(), InteractiveJobError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    use InteractiveJobControl as Control;
    use InteractiveJobMessage as Message;

    let mut buffer = BytesMut::with_capacity(INTERACTIVE_JOB_BUFFER_SIZE);
    let mut decoder = InteractiveJobDecoder::default();
    let mut encoder = InteractiveJobEncoder::default();
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigwinch = signal(SignalKind::window_change())?;
    let mut stdin_async = AsyncFd::try_from(stdin.as_raw_fd())?;
    let mut stdout_async = AsyncFd::try_from(stdout.as_raw_fd())?;
    loop {
        buffer.reserve(INTERACTIVE_JOB_BUFFER_SIZE);
        select! {
            // Relay input from the terminal.
            Ok(n) = stdin_async.read_buf(&mut buffer) => {
                // EOF or the telnet(1) “escape character”
                if n == 0 || buffer == "" {
                    break;
                }
                let message = Message::Data(buffer.copy_to_bytes(n));
                stream.send(encoder.encode(message)?).await?;
                buffer.truncate(0);
            }

            // Handle a message from the server.
            Some(Ok(message)) = stream.next() => {
                match decoder.decode(message)? {
                    Message::Control(control) => match control {
                        Control::WindowChange { .. } => (),
                    }
                    Message::Data(bytes) => {
                        stdout_async.write_all(&bytes).await?;
                    }
                    Message::Ping(bytes) => {
                        let pong = encoder.rekey(Some(&bytes))?;
                        stream.send(encoder.encode(pong)?).await?;
                        decoder.rekey(bytes, None);
                    }
                    Message::Pong(_) => (),
                    Message::Close => break,
                }
            }

            // Send window size on change.
            Some(()) = sigwinch.recv() => {
                let winsize = tcgetwinsize(stdin)?;
                let message = Control::WindowChange(WindowSize {
                    rows: winsize.ws_row,
                    cols: winsize.ws_col,
                }).into();
                stream.send(encoder.encode(message)?).await?;
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

/// Put the client terminal in "raw" mode. This is always a risky
/// proposition; if an interactive job is interrupted, it may leave
/// the terminal in a corrupted state.
fn raw_mode(fd: impl AsFd) -> Result<Termios, InteractiveJobError> {
    let old = tcgetattr(&fd)?;
    let mut new = old.clone();
    new.make_raw();
    tcsetattr(&fd, OptionalActions::Drain, &new)?;
    Ok(old)
}

/// Restore the client terminal to its previous, "cooked" mode.
/// Does not send any terminal escape sequences, and so may not
/// actually reset the terminal to a good state.
fn restore_mode(fd: impl AsFd, mode: Termios) -> Result<(), InteractiveJobError> {
    tcsetattr(&fd, OptionalActions::Drain, &mode)?;

    // AsyncFd sets O_NONBLOCK, so we have to turn it back off again.
    let flags = fcntl_getfl(&fd)?;
    fcntl_setfl(&fd, flags & !OFlags::NONBLOCK)?;

    Ok(())
}
