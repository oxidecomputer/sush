// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Spawn and reap job processes without forking.
//!
//! On illumos, posix_spawn(3C) builds the child in the kernel, without
//! copying our address space or stopping our threads. Avoiding both
//! matters because we run inside `sled-agent`, a large, heavily
//! multithreaded program. We call posix_spawn ourselves because
//! [`std::process::Command`] falls back to fork on illumos whenever a
//! child needs a new session, a reset signal mask, or a controlling
//! terminal.

#[cfg(target_vendor = "apple")]
use std::ffi::c_char;
use std::ffi::{CString, OsStr, c_int, c_short};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::ptr::null_mut;

#[cfg(target_os = "illumos")]
use libc::ctid_t;
use libc::{
    EINTR, EIO, O_RDONLY, O_RDWR, POSIX_SPAWN_SETSIGDEF, POSIX_SPAWN_SETSIGMASK, SIGKILL, SIGSTOP,
    WNOHANG, posix_spawn, posix_spawn_file_actions_adddup2, posix_spawn_file_actions_addopen,
    posix_spawn_file_actions_destroy, posix_spawn_file_actions_init, posix_spawn_file_actions_t,
    posix_spawnattr_destroy, posix_spawnattr_init, posix_spawnattr_setflags,
    posix_spawnattr_setsigdefault, posix_spawnattr_setsigmask, posix_spawnattr_t, sigdelset,
    sigemptyset, sigfillset, sigset_t, waitpid,
};
#[cfg(not(target_vendor = "apple"))]
use libc::{POSIX_SPAWN_SETSID, posix_spawn_file_actions_addchdir_np};
use rustix::process::{Pid, Signal, kill_process_group};
use tokio::runtime::Handle;
use tokio::signal::unix::{Signal as SignalStream, SignalKind, signal};

#[cfg(target_os = "illumos")]
use crate::contract::signal_contract;
use crate::error::{check_errno, io_context};

// The libc crate lacks these for macOS, which has had both since 10.15.
#[cfg(target_vendor = "apple")]
const POSIX_SPAWN_SETSID: c_short = 0x0400;
#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut posix_spawn_file_actions_t,
        path: *const c_char,
    ) -> c_int;
}

fn c_string(bytes: impl Into<Vec<u8>>) -> io::Result<CString> {
    CString::new(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

/// Our handles to the child's side of its standard input and output.
/// [`PosixSpawn::stdio`] takes them, and [`PosixSpawn::spawn`] closes
/// them once the child is spawned.
pub enum SpawnStdio {
    /// The child will open the pts at `path` as its standard input and
    /// output. Until it does, we hold `pts` open; on illumos, the last
    /// close of a pts pops its terminal modules, and the child would
    /// then open a stream that is not a terminal.
    Terminal { pts: OwnedFd, path: PathBuf },

    /// The child will read from `/dev/null` and write to these pipes.
    /// A pipe signals EOF only after every write end is closed,
    /// so we must close these once the child has its copies.
    Pipes { stdout: OwnedFd, stderr: OwnedFd },
}

/// Spawns job processes. Each child leads a new session, starts with
/// every signal at its default action, and blocks no signals.
pub struct PosixSpawn {
    attr: Box<MaybeUninit<posix_spawnattr_t>>,
    actions: Box<MaybeUninit<posix_spawn_file_actions_t>>,
    stdio: Option<SpawnStdio>,
}

impl PosixSpawn {
    pub fn new() -> io::Result<Self> {
        let mut attr = Box::new(MaybeUninit::uninit());
        check_errno("initializing spawn attributes", unsafe {
            posix_spawnattr_init(attr.as_mut_ptr())
        })?;

        let mut actions = Box::new(MaybeUninit::uninit());
        if let Err(error) = check_errno("initializing spawn file actions", unsafe {
            posix_spawn_file_actions_init(actions.as_mut_ptr())
        }) {
            unsafe { posix_spawnattr_destroy(attr.as_mut_ptr()) };
            return Err(error);
        }
        let mut posix_spawn = Self {
            attr,
            actions,
            stdio: None,
        };

        unsafe {
            let attr = posix_spawn.attr.as_mut_ptr();
            let mut defaults = MaybeUninit::<sigset_t>::uninit();
            sigfillset(defaults.as_mut_ptr());
            // SIGKILL and SIGSTOP can't be changed.
            sigdelset(defaults.as_mut_ptr(), SIGKILL);
            sigdelset(defaults.as_mut_ptr(), SIGSTOP);
            check_errno(
                "setting default signals",
                posix_spawnattr_setsigdefault(attr, defaults.as_ptr()),
            )?;

            let mut mask = MaybeUninit::<sigset_t>::uninit();
            sigemptyset(mask.as_mut_ptr());
            check_errno(
                "setting signal mask",
                posix_spawnattr_setsigmask(attr, mask.as_ptr()),
            )?;

            let flags = POSIX_SPAWN_SETSID as c_short
                | POSIX_SPAWN_SETSIGDEF as c_short
                | POSIX_SPAWN_SETSIGMASK as c_short;
            check_errno("setting spawn flags", posix_spawnattr_setflags(attr, flags))?;
        }

        Ok(posix_spawn)
    }

    /// Run the child in `dir`.
    pub fn chdir(&mut self, dir: impl AsRef<Path>) -> io::Result<()> {
        let what = format!("changing to `{}`", dir.as_ref().display());
        let dir = c_string(dir.as_ref().as_os_str().as_bytes())?;
        check_errno(what, unsafe {
            posix_spawn_file_actions_addchdir_np(self.actions.as_mut_ptr(), dir.as_ptr())
        })
    }

    /// Open `path` as the child's `fd`. The child opens it after it
    /// starts its new session, so if `path` is a terminal, it becomes
    /// the child's controlling terminal.
    fn open(&mut self, fd: RawFd, path: impl AsRef<Path>, flags: c_int) -> io::Result<()> {
        let what = format!("opening `{}` as fd {fd}", path.as_ref().display());
        let path = c_string(path.as_ref().as_os_str().as_bytes())?;
        check_errno(what, unsafe {
            posix_spawn_file_actions_addopen(self.actions.as_mut_ptr(), fd, path.as_ptr(), flags, 0)
        })
    }

    /// Duplicate our descriptor `from` onto the child's descriptor `to`.
    fn dup2(&mut self, from: RawFd, to: RawFd) -> io::Result<()> {
        check_errno(format!("duplicating fd {from} onto fd {to}"), unsafe {
            posix_spawn_file_actions_adddup2(self.actions.as_mut_ptr(), from, to)
        })
    }

    /// Give the child `stdio` as its standard input and output.
    pub fn stdio(&mut self, stdio: SpawnStdio) -> io::Result<()> {
        match &stdio {
            SpawnStdio::Terminal { path, .. } => {
                self.open(0, path, O_RDWR)?;
                self.dup2(0, 1)?;
                self.dup2(0, 2)?;
            }
            SpawnStdio::Pipes { stdout, stderr } => {
                self.open(0, "/dev/null", O_RDONLY)?;
                self.dup2(stdout.as_raw_fd(), 1)?;
                self.dup2(stderr.as_raw_fd(), 2)?;
            }
        }
        self.stdio = Some(stdio);
        Ok(())
    }

    /// Start `program`, which must be an absolute path, because
    /// posix_spawn does not search `PATH`. `args` begins with `argv[0]`,
    /// and `env` is the child's entire environment.
    pub fn spawn(
        self,
        program: impl AsRef<Path>,
        args: &[impl AsRef<OsStr>],
        env: &[(impl AsRef<OsStr>, impl AsRef<OsStr>)],
    ) -> io::Result<JobChild> {
        let path = program.as_ref();
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("`{}` is not an absolute path", path.display()),
            ));
        }
        let program = c_string(path.as_os_str().as_bytes())?;
        let args = args
            .iter()
            .map(|arg| c_string(arg.as_ref().as_bytes()))
            .collect::<io::Result<Vec<_>>>()?;
        let env = env
            .iter()
            .map(|(name, value)| {
                let (name, value) = (name.as_ref().as_bytes(), value.as_ref().as_bytes());
                c_string([name, b"=", value].concat())
            })
            .collect::<io::Result<Vec<_>>>()?;
        let mut argv: Vec<_> = args.iter().map(|arg| arg.as_ptr().cast_mut()).collect();
        argv.push(null_mut());
        let mut envp: Vec<_> = env.iter().map(|var| var.as_ptr().cast_mut()).collect();
        envp.push(null_mut());

        let sigchld = signal(SignalKind::child())
            .map_err(|error| io_context("listening for SIGCHLD", error))?;
        let mut pid = 0;
        check_errno(format!("spawning `{}`", path.display()), unsafe {
            posix_spawn(
                &mut pid,
                program.as_ptr(),
                self.actions.as_ptr(),
                self.attr.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        })?;
        let pid = Pid::from_raw(pid).ok_or_else(|| io::Error::other("spawned pid 0"))?;
        Ok(JobChild::new(pid, sigchld))
    }
}

impl Drop for PosixSpawn {
    fn drop(&mut self) {
        unsafe {
            posix_spawn_file_actions_destroy(self.actions.as_mut_ptr());
            posix_spawnattr_destroy(self.attr.as_mut_ptr());
        }
    }
}

/// A spawned job process. Only [`JobChild::wait`] reaps it.
pub struct JobChild {
    pid: Pid,
    #[cfg(target_os = "illumos")]
    contract: Option<ctid_t>,
    sigchld: SignalStream,
    /// The exit status, or the error number `waitpid` failed with.
    reaped: Option<Result<ExitStatus, i32>>,
}

impl JobChild {
    fn new(pid: Pid, sigchld: SignalStream) -> Self {
        Self {
            pid,
            #[cfg(target_os = "illumos")]
            contract: None,
            sigchld,
            reaped: None,
        }
    }

    /// Record the contract that holds the child and its descendants.
    #[cfg(target_os = "illumos")]
    pub fn in_contract(mut self, ctid: ctid_t) -> Self {
        self.contract = Some(ctid);
        self
    }

    /// Send `signal` to every process in the job: its contract if we
    /// know it, or else its process group, which the child leads.
    /// Signalling the contract also reaches descendants that left the
    /// process group.
    pub fn kill(&self, signal: Signal) -> io::Result<()> {
        #[cfg(target_os = "illumos")]
        if let Some(ctid) = self.contract {
            return signal_contract(ctid, signal);
        }
        Ok(kill_process_group(self.pid, signal)?)
    }

    /// Wait for the child to exit, and reap it. Cancelling the wait
    /// never loses the exit status.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        let reaped = match self.reaped {
            Some(reaped) => reaped,
            None => *self.reaped.insert(reap(self.pid, &mut self.sigchld).await),
        };
        reaped.map_err(io::Error::from_raw_os_error)
    }
}

/// Kill a job that [`JobChild::wait`] never reaped, and reap its child
/// in the background. An unreaped child still holds its pid, so the
/// kill cannot reach another process. If [`JobChild::wait`] failed to
/// reap the child, another process may hold its pid by now, so we leave
/// it alone.
impl Drop for JobChild {
    fn drop(&mut self) {
        if self.reaped.is_some() {
            return;
        }
        let _ = self.kill(Signal::KILL);
        if let Ok(handle) = Handle::try_current() {
            let pid = self.pid;
            handle.spawn(async move {
                if let Ok(mut sigchld) = signal(SignalKind::child()) {
                    let _ = reap(pid, &mut sigchld).await;
                }
            });
        }
    }
}

/// Wait for `pid` to exit, and reap it after the last `.await`. Returns
/// the error number if `waitpid` fails.
async fn reap(pid: Pid, sigchld: &mut SignalStream) -> Result<ExitStatus, i32> {
    loop {
        if let Some(status) = try_wait(pid)? {
            return Ok(status);
        }
        sigchld.recv().await;
    }
}

/// Reap `pid` if it has exited.
fn try_wait(pid: Pid) -> Result<Option<ExitStatus>, i32> {
    let mut status = 0;
    loop {
        match unsafe { waitpid(pid.as_raw_nonzero().get(), &mut status, WNOHANG) } {
            0 => return Ok(None),
            -1 => match io::Error::last_os_error().raw_os_error() {
                Some(EINTR) => continue,
                errno => return Err(errno.unwrap_or(EIO)),
            },
            _ => return Ok(Some(ExitStatus::from_raw(status))),
        }
    }
}
