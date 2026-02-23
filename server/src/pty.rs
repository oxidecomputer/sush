//! Asynchronous pseudoterminal driver.
//!
//! Loosely based on the `rust-pty` crate;
//! uses `rustix` for low-level operations.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};

use rustix::fs::{Mode, OFlags, fcntl_setfl, open};
use rustix::io::{read, write};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{Winsize, tcsetwinsize};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use sush_common::session::WindowSize;

/// Unix pseudoterminal.
#[derive(Debug)]
pub struct Pty(AsyncFd<OwnedFd>);

impl Pty {
    /// Open and configure the pseudoterminal.
    pub fn open() -> io::Result<(Self, OwnedFd, PathBuf)> {
        let pty = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        grantpt(&pty)?;
        unlockpt(&pty)?;
        fcntl_setfl(&pty, OFlags::NONBLOCK)?;

        let pts_name = ptsname(&pty, Vec::new())?;
        let pts_path = PathBuf::from(OsStr::from_bytes(pts_name.to_bytes()));
        let pts = open(&pts_path, OFlags::RDWR | OFlags::NOCTTY, Mode::empty())?;

        // Push the terminal interface STREAMS modules; see pts(4D).
        #[cfg(target_os = "illumos")]
        unsafe {
            let fd = pts.as_raw_fd();
            if libc::ioctl(fd, libc::I_PUSH, c"ptem") != 0
                || libc::ioctl(fd, libc::I_PUSH, c"ldterm") != 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        Ok((Self(AsyncFd::new(pty)?), pts, pts_path))
    }

    /// Set the pseudoterminal window size.
    pub fn set_window_size(&self, WindowSize { rows, cols }: WindowSize) -> io::Result<()> {
        Ok(tcsetwinsize(
            &self.0,
            Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )?)
    }
}

impl AsFd for Pty {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for Pty {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsyncRead for Pty {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = match self.0.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|inner| Ok(read(inner.get_ref(), unfilled)?)) {
                Ok(Ok(len)) => {
                    buf.advance(len);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(err)) => return Poll::Ready(Err(err)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for Pty {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = match self.0.poll_write_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|inner| Ok(write(inner.get_ref(), buf)?)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rustix::fs::fcntl_getfl;
    use rustix::termios::tcgetwinsize;

    #[tokio::test]
    async fn open_pty() {
        let (pty, pts, pts_path) = Pty::open().unwrap();
        let pty_flags = fcntl_getfl(&pty).unwrap();
        let pts_flags = fcntl_getfl(&pts).unwrap();
        assert!(!(pty_flags & OFlags::RDWR).is_empty());
        assert!(!(pty_flags & OFlags::NONBLOCK).is_empty());
        assert!(!(pts_flags & OFlags::RDWR).is_empty());
        assert!(pts_path.starts_with("/dev/pts/"));
    }

    #[tokio::test]
    async fn set_window_size() {
        let (pty, pts, _pts_path) = Pty::open().unwrap();
        let winsz = tcgetwinsize(&pts).unwrap();
        let rows = winsz.ws_row + 80;
        let cols = winsz.ws_col + 24;
        pty.set_window_size(WindowSize { rows, cols }).unwrap();
        let winsz = tcgetwinsize(&pts).unwrap();
        assert_eq!(winsz.ws_row, rows);
        assert_eq!(winsz.ws_col, cols);
    }
}
