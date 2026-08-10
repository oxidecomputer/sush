// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
use std::task::{Context, Poll, ready};

use rustix::fs::{Mode, OFlags, fcntl_setfl, open};
use rustix::io::{FdFlags, fcntl_setfd, read, write};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{tcgetwinsize, tcsetwinsize};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use sush_common::interactive::WindowSize;

/// Open and configure a Unix pseudoterminal. We return a reader/control
/// handle, a write handle, the slave fd, and its path. The master gets
/// CLOEXEC after the fact, because illumos cannot set it atomically at
/// open.
pub fn open_pty() -> io::Result<(PtyReader, PtyWriter, OwnedFd, PathBuf)> {
    let pty = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
    fcntl_setfd(&pty, FdFlags::CLOEXEC)?;
    grantpt(&pty)?;
    unlockpt(&pty)?;
    fcntl_setfl(&pty, OFlags::NONBLOCK)?;

    let pts_name = ptsname(&pty, Vec::new())?;
    let pts_path = PathBuf::from(OsStr::from_bytes(pts_name.to_bytes()));
    let pts = open(
        &pts_path,
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;

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

    let dup = AsyncFd::new(pty.try_clone()?)?;
    let fd = AsyncFd::new(pty)?;
    Ok((PtyReader(fd), PtyWriter(dup), pts, pts_path))
}

#[derive(Debug)]
pub struct PtyReader(AsyncFd<OwnedFd>);

impl PtyReader {
    /// Get the current pseudoterminal window size.
    pub fn get_window_size(&self) -> io::Result<WindowSize> {
        Ok(tcgetwinsize(&self.0)?.into())
    }

    /// Set the pseudoterminal window size.
    pub fn set_window_size(&self, size: WindowSize) -> io::Result<()> {
        Ok(tcsetwinsize(&self.0, size.into())?)
    }
}

impl AsyncRead for PtyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.0.poll_read_ready(cx))?;
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

impl AsFd for PtyReader {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for PtyReader {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[derive(Debug)]
pub struct PtyWriter(AsyncFd<OwnedFd>);

impl AsFd for PtyWriter {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsRawFd for PtyWriter {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl AsyncWrite for PtyWriter {
    /// Write some input to a pseudoterminal.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.0.poll_write_ready(cx))?;
            match guard.try_io(|inner| Ok(write(inner.get_ref(), buf)?)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    /// Writes go straight to the fd, so there's nothing to flush.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Can't half-close a pty, the fd closes on drop.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rustix::fs::fcntl_getfl;
    use rustix::io::{FdFlags, fcntl_getfd};
    use rustix::termios::tcgetwinsize;

    #[tokio::test]
    async fn pty() {
        let (pty, writer, pts, pts_path) = open_pty().unwrap();
        for fd in [pty.as_fd(), writer.as_fd(), pts.as_fd()] {
            assert!(fcntl_getfd(fd).unwrap().contains(FdFlags::CLOEXEC));
        }
        let pty_flags = fcntl_getfl(&pty).unwrap();
        let pts_flags = fcntl_getfl(&pts).unwrap();
        assert!(!(pty_flags & OFlags::RDWR).is_empty());
        assert!(!(pty_flags & OFlags::NONBLOCK).is_empty());
        assert!(!(pts_flags & OFlags::RDWR).is_empty());
        assert!(pts_path.starts_with("/dev/pts/"));
    }

    #[tokio::test]
    async fn set_window_size() {
        let (pty, _writer, pts, _pts_path) = open_pty().unwrap();
        let winsz = tcgetwinsize(&pts).unwrap();
        let rows = winsz.ws_row + 80;
        let cols = winsz.ws_col + 24;
        pty.set_window_size(WindowSize { rows, cols }).unwrap();
        let winsz = tcgetwinsize(&pts).unwrap();
        assert_eq!(winsz.ws_row, rows);
        assert_eq!(winsz.ws_col, cols);
    }
}
