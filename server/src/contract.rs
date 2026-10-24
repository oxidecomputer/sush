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

use std::ffi::{CString, c_char, c_int, c_uint};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd as _;

use libc::ctid_t;
use rustix::process::Signal;

use sush_common::jobs::JobId;

use crate::error::check_errno;

#[allow(non_camel_case_types)]
type ct_stathdl_t = *mut libc::c_void;

#[link(name = "contract")]
unsafe extern "C" {
    fn ct_tmpl_activate(fd: c_int) -> c_int;
    fn ct_tmpl_clear(fd: c_int) -> c_int;
    fn ct_tmpl_set_critical(fd: c_int, events: c_uint) -> c_int;
    fn ct_tmpl_set_informative(fd: c_int, events: c_uint) -> c_int;
    fn ct_pr_tmpl_set_fatal(fd: c_int, events: c_uint) -> c_int;
    fn ct_pr_tmpl_set_param(fd: c_int, params: c_uint) -> c_int;
    fn ct_pr_tmpl_set_svc_aux(fd: c_int, aux: *const c_char) -> c_int;
    fn ct_status_read(fd: c_int, detail: c_int, stathdl: *mut ct_stathdl_t) -> c_int;
    fn ct_status_get_id(stathdl: ct_stathdl_t) -> ctid_t;
    fn ct_status_free(stathdl: ct_stathdl_t);
    fn ct_ctl_abandon(fd: c_int) -> c_int;
}

unsafe extern "C" {
    fn sigsend(idtype: libc::idtype_t, id: libc::id_t, sig: c_int) -> c_int;
}

/// Process had an uncorrectable hardware error.
const CT_PR_EV_HWERR: c_uint = 0x20;

/// A fatal event kills only the affected process group.
const CT_PR_PGRPONLY: c_uint = 0x04;

/// Status detail level for `ct_status_read`.
const CTD_COMMON: c_int = 0;

const PROCESS: &str = "/system/contract/process";

/// Open a ctfs file, naming it in any error.
fn open(options: &OpenOptions, path: String) -> io::Result<File> {
    options
        .open(&path)
        .map_err(|error| io::Error::new(error.kind(), format!("opening {path}: {error}")))
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
        let file = open(
            OpenOptions::new().read(true).write(true),
            format!("{PROCESS}/template"),
        )?;
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
        let latest = open(OpenOptions::new().read(true), format!("{PROCESS}/latest"))?;
        let ctid = unsafe {
            let mut status: ct_stathdl_t = std::ptr::null_mut();
            check_errno(
                "reading latest contract",
                ct_status_read(latest.as_raw_fd(), CTD_COMMON, &mut status),
            )?;
            let ctid = ct_status_get_id(status);
            ct_status_free(status);
            ctid
        };
        let ctl = open(
            OpenOptions::new().write(true),
            format!("{PROCESS}/{ctid}/ctl"),
        )?;
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
