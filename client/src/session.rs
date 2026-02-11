//! Interactive job sessions, client side.

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

use sush_common::session::{
    SESSION_BUFFER_SIZE, SessionControl, SessionDecoder, SessionEncoder, SessionError,
    SessionMessage, WindowSize,
};

/// Drive an interactive job session, relaying stdin/stdout to/from a WebSocket.
/// The terminal is put into "raw" mode for the duration of `session_inner`, and
/// (we hope) restored when the session ends.
pub async fn session<T>(stream: WebSocketStream<T>) -> Result<(), SessionError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    let stdin = stdin();
    let stdout = stdout();
    let mode = raw_mode(&stdin)?;
    let result = session_inner(&stdin, &stdout, stream).await;
    restore_mode(&stdin, mode)?;
    result
}

async fn session_inner<T>(
    stdin: &Stdin,
    stdout: &Stdout,
    mut stream: WebSocketStream<T>,
) -> Result<(), SessionError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = BytesMut::with_capacity(SESSION_BUFFER_SIZE);
    let mut decoder = SessionDecoder::default();
    let mut encoder = SessionEncoder::default();
    let mut sighup = signal(SignalKind::hangup())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigwinch = signal(SignalKind::window_change())?;
    let mut stdin_async = AsyncFd::try_from(stdin.as_raw_fd())?;
    let mut stdout_async = AsyncFd::try_from(stdout.as_raw_fd())?;
    loop {
        select! {
            // Relay input from the terminal.
            Ok(n) = stdin_async.read_buf(&mut buffer) => {
                // EOF or the telnet(1) “escape character”
                if n == 0 || buffer == "" {
                    break;
                }
                let message = SessionMessage::Data(buffer.copy_to_bytes(n));
                stream.send(encoder.encode(message)?).await?;
                buffer.truncate(0);
            }

            // Handle a message from the server.
            Some(Ok(message)) = stream.next() => {
                match &decoder.decode(message)? {
                    SessionMessage::Control(control) => match control {
                        SessionControl::WindowChange { .. } => (),
                    }
                    SessionMessage::Data(bytes) => {
                        stdout_async.write_all(bytes).await?;
                    }
                    msg @ SessionMessage::Ping(bytes) => {
                        decoder.rekey(bytes);
                        stream.send(encoder.rekey(Some(msg))?).await?;
                    }
                    SessionMessage::Pong(_) => (),
                    SessionMessage::Close => break,
                }
            }

            // Send window size on change.
            Some(()) = sigwinch.recv() => {
                let winsize = tcgetwinsize(stdin)?;
                let message = SessionControl::WindowChange(WindowSize {
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
fn raw_mode(fd: impl AsFd) -> Result<Termios, SessionError> {
    let old = tcgetattr(&fd)?;
    let mut new = old.clone();
    new.make_raw();
    tcsetattr(&fd, OptionalActions::Drain, &new)?;
    Ok(old)
}

/// Restore the client terminal to its previous, "cooked" mode.
/// Does not send any terminal escape sequences, and so may not
/// actually reset the terminal to a good state.
fn restore_mode(fd: impl AsFd, mode: Termios) -> Result<(), SessionError> {
    tcsetattr(&fd, OptionalActions::Drain, &mode)?;

    // AsyncFd sets O_NONBLOCK, so we have to turn it back off again.
    let flags = fcntl_getfl(&fd)?;
    fcntl_setfl(&fd, flags & !OFlags::NONBLOCK)?;

    Ok(())
}
