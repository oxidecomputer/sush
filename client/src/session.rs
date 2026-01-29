//! Interactive job sessions, client side.

use std::io::{stdin, stdout};
use std::os::fd::{AsFd, AsRawFd};

use futures::{SinkExt as _, StreamExt as _};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::termios::{OptionalActions, Termios, tcgetattr, tcsetattr};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::select;
use tokio_fd::AsyncFd;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message;

use sush_common::session::SessionError;

/// Drive an interactive job session, relaying stdin/stdout to/from a WebSocket.
pub async fn session<T>(stream: WebSocketStream<T>) -> Result<(), SessionError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    let stdin = stdin();
    let stdout = stdout();
    let stdin_async = AsyncFd::try_from(stdin.as_raw_fd())?;
    let stdout_async = AsyncFd::try_from(stdout.as_raw_fd())?;
    let stdin_mode = raw_mode(stdin.as_fd())?;
    session_inner(stdin_async, stdout_async, stream).await;
    restore_mode(stdin, stdin_mode)?;
    Ok(())
}

/// Infallible core of session, to ensure we always reset the terminal to "cooked" mode.
async fn session_inner<T>(mut stdin: AsyncFd, mut stdout: AsyncFd, mut stream: WebSocketStream<T>)
where
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    loop {
        select! {
            Ok(n) = stdin.read_buf(&mut buffer) => {
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
