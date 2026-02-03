//! Interactive job sessions, client side.

use std::io::{stdin, stdout};
use std::os::fd::{AsFd, AsRawFd};

use futures::{SinkExt as _, StreamExt as _};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcgetwinsize, tcsetattr};
use serde_json::to_string as to_json;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::select;
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio_fd::AsyncFd;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message;

use sush_common::session::{ClientControlMessage, SessionError};

/// Drive an interactive job session, relaying stdin/stdout to/from a WebSocket.
pub async fn session<T>(stream: WebSocketStream<T>) -> Result<(), SessionError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    let sigwinch = signal(SignalKind::window_change())?;
    let stdin = stdin();
    let _ = stdin.lock();
    let stdout = stdout();
    let stdin_async = AsyncFd::try_from(stdin.as_raw_fd())?;
    let stdout_async = AsyncFd::try_from(stdout.as_raw_fd())?;
    let stdin_mode = raw_mode(&stdin)?;
    session_inner(&stdin, stdin_async, stdout_async, stream, sigwinch).await;
    restore_mode(&stdin, stdin_mode)?;
    Ok(())
}

/// Infallible core of session, to ensure we always reset the terminal to "cooked" mode.
async fn session_inner<T>(
    stdin: impl AsFd,
    mut stdin_async: AsyncFd,
    mut stdout: AsyncFd,
    mut stream: WebSocketStream<T>,
    mut sigwinch: Signal,
) where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    loop {
        select! {
            Ok(n) = stdin_async.read_buf(&mut buffer) => {
                if n == 0 {
                    let _ = stream.close(None).await;
                    break;
                }
                let message = Message::Binary(buffer.drain(..n).collect());
                if stream.send(message).await.is_err() {
                    break;
                }
            }
            Some(Ok(message)) = stream.next() => {
                match message {
                    Message::Text(message) => todo!("control message: {message}"),
                    Message::Binary(bytes) => {
                        if stdout.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    Message::Ping(bytes) => {
                        if stream.send(Message::Pong(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Message::Pong(_) => (),
                    Message::Close(_) => break,
                    Message::Frame(_) => unreachable!("should not receive raw frame"),
                }
            }
            Some(()) = sigwinch.recv() => {
                if let Ok(winsize) = tcgetwinsize(stdin.as_fd())
                    && let Ok(message) = to_json(&ClientControlMessage::WindowSize {
                        rows: winsize.ws_row,
                        cols: winsize.ws_col
                    })
                    && stream.send(Message::Text(message.into())).await.is_err()
                {
                    break;
                }
            }
            else => break,
        }
    }
}

fn raw_mode(fd: impl AsFd) -> Result<Termios, SessionError> {
    let fd = fd.as_fd();
    let old = tcgetattr(fd)?;
    let mut new = old.clone();
    new.make_raw();
    tcsetattr(fd, OptionalActions::Drain, &new)?;
    Ok(old)
}

fn restore_mode(fd: impl AsFd, mode: Termios) -> Result<(), SessionError> {
    tcsetattr(&fd, OptionalActions::Drain, &mode)?;

    // AsyncFd sets O_NONBLOCK, so we have to turn it back off again.
    let flags = fcntl_getfl(&fd)?;
    fcntl_setfl(&fd, flags & !OFlags::NONBLOCK)?;

    Ok(())
}
