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
//! contract and abandon it (like `sshd` does), so that jobs may outlive
//! `sled-agent`.

use std::ffi::{CString, c_char, c_int, c_uint};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd as _;

use libc::ctid_t;
use rustix::fs::{Mode, OFlags};
use rustix::io::{Errno, FdFlags, fcntl_setfd};

use sush_common::jobs::JobId;

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

/// Process had an uncorrectable hardware error.
const CT_PR_EV_HWERR: c_uint = 0x20;

/// Status detail level for `ct_status_read`.
const CTD_COMMON: c_int = 0;

const PROCESS: &str = "/system/contract/process";

/// libcontract returns an error number rather than setting `errno`.
fn check(what: &str, errno: c_int) -> io::Result<()> {
    if errno == 0 {
        Ok(())
    } else {
        let error = io::Error::from_raw_os_error(errno);
        Err(io::Error::new(error.kind(), format!("{what}: {error}")))
    }
}

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

/// Run `spawn` with a job's contract template active, then abandon the
/// contract its `fork` created. The template is per thread, so `spawn`
/// must fork on the calling thread; being synchronous, it cannot move
/// to another. If `spawn` fails after forking or abandoning fails,
/// the empty contract lingers until we exit.
pub fn spawn_in_contract<T>(
    job_id: &JobId,
    spawn: impl FnOnce() -> io::Result<T>,
) -> io::Result<(T, ctid_t)> {
    let template = Template::activate(job_id)?;
    let child = spawn()?;
    let ctid = template.abandon_latest()?;
    Ok((child, ctid))
}

/// An active process contract template. While it lives, every `fork`
/// on the calling thread creates a new contract.
struct Template(File);

impl Template {
    /// Activate a template for a job's contract on the calling thread.
    /// Only a hardware error is fatal, and the contract is labeled by
    /// job ID.
    fn activate(job_id: &JobId) -> io::Result<Self> {
        let file = open(OFlags::RDWR, format!("{PROCESS}/template"))?;
        let fd = file.as_raw_fd();
        let aux = CString::new(format!("sush job {job_id}")).map_err(io::Error::other)?;
        unsafe {
            check(
                "setting fatal events",
                ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR),
            )?;
            check("setting critical events", ct_tmpl_set_critical(fd, 0))?;
            check("setting informative events", ct_tmpl_set_informative(fd, 0))?;
            check("setting parameters", ct_pr_tmpl_set_param(fd, 0))?;
            check("setting label", ct_pr_tmpl_set_svc_aux(fd, aux.as_ptr()))?;
            check("activating template", ct_tmpl_activate(fd))?;
        }
        Ok(Self(file))
    }

    /// Abandon the contract created by the last `fork` on this thread,
    /// and return its ID.
    fn abandon_latest(self) -> io::Result<ctid_t> {
        let latest = open(OFlags::RDONLY, format!("{PROCESS}/latest"))?;
        let ctid = unsafe {
            let mut status: ct_stathdl_t = std::ptr::null_mut();
            check(
                "reading latest contract",
                ct_status_read(latest.as_raw_fd(), CTD_COMMON, &mut status),
            )?;
            let ctid = ct_status_get_id(status);
            ct_status_free(status);
            ctid
        };
        let ctl = open(OFlags::WRONLY, format!("{PROCESS}/{ctid}/ctl"))?;
        check("abandoning contract", unsafe {
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
