// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Process contracts for jobs; see contract(5) and process(5).
//!
//! `sled-agent` runs in a contract held by `ctrun -o noorphan`, so any job
//! spawned into that contract dies with it. This breaks bare `reboot` as
//! a job: its `SIGTERM` broadcast kills `ctrun`, the contract is orphaned,
//! and the kernel kills `reboot` before it can call `uadmin`, leaving the
//! sled wedged until a power cycle. We therefore spawn each job into a new
//! contract and abandon it, so that jobs may outlive `sled-agent`. The
//! template settings and the abandonment follow what `sshd` does for each
//! login session, in OpenSSH's `openbsd-compat/port-solaris.c`.

use std::ffi::{CString, c_int};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;
use std::ptr::null_mut;

use libc::ctid_t;
use libcontract_sys::{
    CT_PR_EV_HWERR, CT_PR_PGRPONLY, CTD_COMMON, ct_ctl_abandon, ct_pr_tmpl_set_fatal,
    ct_pr_tmpl_set_param, ct_pr_tmpl_set_svc_aux, ct_stathdl_t, ct_status_free, ct_status_get_id,
    ct_status_read, ct_tmpl_activate, ct_tmpl_clear, ct_tmpl_set_critical, ct_tmpl_set_informative,
};
use rustix::fs::{Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::process::Signal;

use sush_common::jobs::JobId;

use crate::error::check_errno;

unsafe extern "C" {
    fn sigsend(idtype: libc::idtype_t, id: libc::id_t, sig: c_int) -> c_int;
}

const PROCESS: &str = "/system/contract/process";

/// Open a ctfs file, naming it in any error. Until illumos 18395, ctfs
/// refuses opens with `O_CLOEXEC`, which `std::fs` always sets, so we
/// open without it and set `FD_CLOEXEC` afterward.
fn open(flags: OFlags, path: String) -> io::Result<File> {
    let named = |error: Errno| {
        let error = io::Error::from(error);
        io::Error::new(error.kind(), format!("opening {path}: {error}"))
    };
    let fd = rustix::fs::open(&path, flags, Mode::empty()).map_err(named)?;
    fcntl_setfd(&fd, FdFlags::CLOEXEC).map_err(named)?;
    Ok(File::from(fd))
}

/// Send `signal` to every process in contract `ctid`.
pub fn signal_contract(ctid: ctid_t, signal: Signal) -> io::Result<()> {
    if unsafe { sigsend(libc::P_CTID, ctid, signal.as_raw()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Run `spawn` with a job's contract template active, then abandon the
/// new contract that holds the child. The template is per thread, so
/// `spawn` must create the child on the calling thread; being
/// synchronous, it cannot move to another. If `spawn` fails after
/// creating a child, or abandoning fails, the empty contract lingers
/// until we exit.
pub fn spawn_in_contract<T>(
    job_id: &JobId,
    spawn: impl FnOnce() -> io::Result<T>,
) -> io::Result<(T, ctid_t)> {
    let template = Template::activate(job_id)?;
    let child = spawn()?;
    let ctid = template.abandon_latest()?;
    Ok((child, ctid))
}

/// An active process contract template. While it lives, every child
/// the calling thread creates starts in a new contract.
struct Template(File);

impl Template {
    /// Activate a template for a job's contract on the calling thread.
    /// As in sshd, a hardware error kills only the process group of the
    /// process it struck. The contract is labeled by job ID.
    fn activate(job_id: &JobId) -> io::Result<Self> {
        let file = open(OFlags::RDWR, format!("{PROCESS}/template"))?;
        let fd = file.as_raw_fd();
        let aux = CString::new(format!("sush job {job_id}")).map_err(io::Error::other)?;
        unsafe {
            check_errno(
                "setting fatal events",
                ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR),
            )?;
            check_errno("setting critical events", ct_tmpl_set_critical(fd, 0))?;
            check_errno("setting informative events", ct_tmpl_set_informative(fd, 0))?;
            check_errno(
                "setting parameters",
                ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY),
            )?;
            check_errno("setting label", ct_pr_tmpl_set_svc_aux(fd, aux.as_ptr()))?;
            check_errno("activating template", ct_tmpl_activate(fd))?;
        }
        Ok(Self(file))
    }

    /// Abandon the newest contract this thread created, and return its
    /// ID.
    fn abandon_latest(self) -> io::Result<ctid_t> {
        let latest = open(OFlags::RDONLY, format!("{PROCESS}/latest"))?;
        let ctid = unsafe {
            let mut status: *mut ct_stathdl_t = null_mut();
            check_errno(
                "reading latest contract",
                ct_status_read(latest.as_raw_fd(), CTD_COMMON, &mut status),
            )?;
            let ctid = ct_status_get_id(status);
            ct_status_free(status);
            ctid
        };
        let ctl = open(OFlags::WRONLY, format!("{PROCESS}/{ctid}/ctl"))?;
        check_errno("abandoning contract", unsafe {
            ct_ctl_abandon(ctl.as_raw_fd())
        })?;
        Ok(ctid)
    }
}

impl Drop for Template {
    fn drop(&mut self) {
        unsafe { ct_tmpl_clear(self.0.as_raw_fd()) };
    }
}
