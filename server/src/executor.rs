// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job execution engine.
//!
//! Start, stop, and watch job processes. Driven by the session state
//! machine, but session agnostic.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::AsRawFd as _;
use std::process::Stdio;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use futures::Stream;
use pwd::Passwd;
use rustix::io::close;
use rustix::process::{Pid, Signal, ioctl_tiocsctty, kill_process_group, setsid};
use slog::{Logger, debug, error, o, warn};
use tokio::fs::{DirBuilder, OpenOptions};
use tokio::process::{Child, Command};
use tokio::spawn;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use sush_api::JobStartParams;
use sush_common::interactive::WindowSize;
use sush_common::jobs::{
    JobId, JobOutputStream, JobStartRequest, ProcessError, SignedJob, VerifiedJob,
};

use crate::io::JobIo;
use crate::job::{Job, SocketSender};
use crate::messages::v0::{Event, JobEvent};
use crate::output::JobOutputDir;
use crate::pty::open_pty;
use crate::state::{Certificates, cert_chain};

pub const DEFAULT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
pub const DEFAULT_TERM: &str = "vt100";

/// This queue size is an arbitrary choice. We expect to consume
/// messages from the channel very rapidly, so should not
/// experience backpressure; if we do, something is wrong.
const EVENTS_CHANNEL_CAPACITY: usize = 16;

pub struct Executor {
    log: Logger,
    events: Arc<RwLock<Option<mpsc::Sender<Event>>>>,
    path_isolation: PathIsolation,
    output_dir: JobOutputDir,
    shutdown: CancellationToken,
    stop: BTreeMap<JobId, CancellationToken>,
}

/// Executor methods should be infallible; errors are reported via events.
impl Executor {
    pub fn new(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: JobOutputDir,
        shutdown: CancellationToken,
    ) -> (Self, impl Stream<Item = Event> + Send + 'static) {
        let (tx_events, rx_events) = mpsc::channel(EVENTS_CHANNEL_CAPACITY);
        let events = Arc::new(RwLock::new(Some(tx_events)));

        // Stop sending new events to the state manager on shutdown.
        spawn({
            let events = events.clone();
            let shutdown = shutdown.clone();
            async move {
                shutdown.cancelled().await;
                events.write().unwrap().take();
            }
        });

        // Return the executor and event stream.
        (
            Self {
                log,
                events,
                path_isolation,
                output_dir,
                shutdown,
                stop: BTreeMap::new(),
            },
            ReceiverStream::new(rx_events),
        )
    }

    pub fn job_start(
        &mut self,
        certs: &mut Certificates,
        request: SignedJob,
        params: JobStartParams,
        tx_attachment: watch::Sender<Option<SocketSender>>,
    ) {
        let Some(events) = self.events.read().unwrap().as_ref().cloned() else {
            // No more events ⇒ shutting down ⇒ no new jobs allowed.
            return;
        };

        // Validate the job request.
        let job_id = request.payload().job_id().to_owned();
        macro_rules! fail {
            ($err:expr) => {{
                let log = self.log.clone();
                let job_id = job_id.clone();
                let events = events.clone();
                spawn(async move {
                    send_error(&log, &job_id, &events, $err).await;
                });
                return;
            }};
        }
        if request.payload().command.starts_with('-') {
            fail!(ProcessError::InvalidCommand);
        }
        let chain = match cert_chain(certs, request.key_id()) {
            Ok(chain) => chain,
            Err(error) => fail!(ProcessError::InvalidJob(error.to_string())),
        };
        let leaf = chain.last().expect("cert chain should be non-empty");
        let verified_request = match request.verify_with_cert(leaf) {
            Ok(request) => request,
            Err(error) => fail!(ProcessError::InvalidJob(error.to_string())),
        };

        let stop = self.shutdown.child_token();
        self.stop.insert(job_id, stop.clone());
        spawn(job_spawn(
            self.log.new(o!("job_id" => job_id)),
            events,
            self.output_dir.clone(),
            verified_request,
            params,
            self.path_isolation,
            tx_attachment,
            stop,
        ));
    }

    pub fn job_stop(&mut self, job_id: &JobId) {
        if let Some(stop) = self.stop.remove(job_id) {
            stop.cancel();
        }
    }

    pub fn job_stopped(&mut self, job_id: &JobId) {
        let _ = self.stop.remove(job_id);
    }

    pub fn output_dir(&self) -> &JobOutputDir {
        &self.output_dir
    }
}

/// Spawn a process for a job and return an attachment point if it is
/// interactive. Assumes the job request has already been validated,
/// e.g., as by [`crate::JobManager::job_start`].
#[allow(clippy::too_many_arguments)]
async fn job_spawn(
    log: Logger,
    events: mpsc::Sender<Event>,
    output_dir: JobOutputDir,
    request: VerifiedJob,
    params: JobStartParams,
    path_isolation: PathIsolation,
    tx_attachment: watch::Sender<Option<SocketSender>>,
    stop: CancellationToken,
) {
    use JobOutputStream::*;
    let JobStartRequest {
        job_id,
        command,
        interactive,
        target: _,
    } = request.payload().clone();
    let JobStartParams {
        limits: requested,
        term,
        rows,
        cols,
        wait: _,
    } = params;
    let mut limits = requested.clone().clamp();
    if limits != requested {
        warn!(
            log, "clamped requested job limits";
            "requested" => ?requested, "limits" => ?limits,
        );
    }

    // Ensure consistent output dirs.
    let dirs = output_dir.current();

    // Clamp max file size to output requirements.
    if limits.max_fsize > dirs.max_fsize() {
        warn!(
            log, "clamping requested job output size limit";
            "requested" => limits.max_fsize,
            "max_fsize" => dirs.max_fsize(),
        );
        limits.max_fsize = dirs.max_fsize();
    }

    // Report all I/O errors as job events.
    let io_err = |what| move |err: io::Error| ProcessError::io(what, err);
    macro_rules! with_io_err {
        ($expr:expr, $err:expr) => {
            match $expr.map_err(io_err($err)) {
                Ok(value) => value,
                Err(error) => {
                    send_error(&log, &job_id, &events, error).await;
                    return;
                }
            }
        };
    }

    // Set up output directories and files.
    let dir_mode = 0o700;
    let file_mode = 0o600;
    let job_dir = dirs.job_output_dir(&job_id);
    with_io_err!(
        DirBuilder::new()
            .recursive(true)
            .mode(dir_mode)
            .create(&job_dir)
            .await,
        format!("creating job output directory `{}`", job_dir.display())
    );
    let stdout_path = dirs.job_output_path(&job_id, Stdout);
    let stderr_path = dirs.job_output_path(&job_id, Stderr);
    let stdout_file = with_io_err!(
        OpenOptions::new()
            .create_new(true)
            .read(true) // needed for interactive job output playback
            .write(true)
            .mode(file_mode)
            .open(&stdout_path)
            .await,
        format!("creating job stdout file `{}`", stdout_path.display())
    );
    let stderr_file = with_io_err!(
        OpenOptions::new()
            .create_new(true)
            .read(false) // not needed since interactive jobs have no stderr
            .write(true)
            .mode(file_mode)
            .open(&stderr_path)
            .await,
        format!("creating job stderr file `{}`", stderr_path.display())
    );

    // Set up the job command.
    let mut cmd = Command::new("bash");
    cmd.kill_on_drop(true);
    cmd.arg("-c").arg(&command);

    // Set up basic environment.
    cmd.env_clear();
    match path_isolation {
        PathIsolation::Enable => {
            cmd.env("PATH", DEFAULT_PATH);
        }
        PathIsolation::InsecureDisable => {
            if let Some(path) = std::env::var_os("PATH") {
                cmd.env("PATH", path);
            }
        }
    }
    if let Some(pwd) = Passwd::current_user() {
        cmd.current_dir(&pwd.dir)
            .env("HOME", &pwd.dir)
            .env("LOGNAME", &pwd.name)
            .env("USER", &pwd.name);
    }
    cmd.env("SSH_CLIENT", "sush") // read bashrc
        .env("SUSH_JOB_ID", job_id.to_string())
        .env("SUSH_COMMAND", &command);

    // Set process limits.
    unsafe {
        let limits = limits.clone();
        cmd.pre_exec(move || limits.apply());
    }

    // Always create a new process session and group.
    // Job stop kills the whole group.
    unsafe {
        cmd.pre_exec(move || {
            setsid()?;
            Ok(())
        });
    }

    let job = if interactive {
        // Create a pseudoterminal and wire the child up to it.
        let (pty, writer, pts, pts_path) =
            with_io_err!(open_pty(), "opening pseudoterminal".to_string());
        macro_rules! pts_clone {
            () => {
                with_io_err!(pts.try_clone(), "cloning pseudoterminal".to_string())
            };
        }
        cmd.env("SUSH_TTY", &pts_path)
            .stdin(pts_clone!())
            .stdout(pts_clone!())
            .stderr(pts_clone!());

        unsafe {
            let pty = pty.as_raw_fd();
            cmd.pre_exec(move || {
                close(pty); // not needed in the child
                ioctl_tiocsctty(&pts)?; // set controlling terminal
                Ok(())
            });
        }

        // Initialize the pseudoterminal.
        cmd.env("TERM", term.unwrap_or_else(|| DEFAULT_TERM.to_string()));
        if let (Some(rows), Some(cols)) = (rows, cols) {
            with_io_err!(
                pty.set_window_size(WindowSize { rows, cols }),
                "resizing pseudoterminal window".to_string()
            );
        }

        // Start the interactive job.
        let child = with_io_err!(cmd.spawn(), "spawning interactive job".to_string());
        let io = JobIo::interactive(pty, writer, stop.child_token());
        Job::start(
            log.new(o!("interactive" => interactive)),
            limits,
            child,
            io,
            stdout_file,
            stderr_file,
            stop,
        )
    } else {
        // For batch jobs, close stdin and send output to pipes.
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Start the batch job.
        let mut child = with_io_err!(cmd.spawn(), "spawning batch job".to_string());
        let io = JobIo::batch(
            child.stdout.take().expect("batch job should have stdout"),
            child.stderr.take().expect("batch job should have stderr"),
        );
        Job::start(
            log.new(o!("interactive" => interactive)),
            limits,
            child,
            io,
            stdout_file,
            stderr_file,
            stop,
        )
    };

    // Send the attachment point.
    if tx_attachment.send(Some(job.attachment())).is_err() {
        error!(log, "can't send attachment point");
    }

    // Announce the birth of our new job!
    let _ = events
        .send(Event::Job(JobEvent::Start(job_id, Utc::now())))
        .await;

    // Wait for the job to die and send an event when it does.
    spawn(async move {
        match job.wait().await {
            Ok((result, state)) => {
                let _ = events
                    .send(Event::Job(JobEvent::Stop(
                        job_id,
                        Utc::now(),
                        result,
                        state,
                    )))
                    .await;
            }
            Err(error) => {
                let _ = events
                    .send(Event::Job(JobEvent::Error(
                        job_id,
                        Utc::now(),
                        ProcessError::Join(error.to_string()),
                    )))
                    .await;
            }
        }
    });
}

async fn send_error(
    log: &Logger,
    job_id: &JobId,
    events: &mpsc::Sender<Event>,
    error: ProcessError,
) {
    if let Err(send_error) = events
        .send(Event::Job(JobEvent::Error(
            job_id.to_owned(),
            Utc::now(),
            error,
        )))
        .await
    {
        error!(log, "can't send error event"; "error" => %send_error);
    }
}

/// Kill a job's whole process group, of which `child` should be the leader.
///
/// TODO: 2-stage stop with `SIGTERM` and a grace period.
pub fn kill_job(log: &Logger, child: &Child) {
    if let Some(pid) = child.id()
        && let Ok(pid) = pid.try_into()
        && let Some(pid) = Pid::from_raw(pid)
    {
        match kill_process_group(pid, Signal::KILL) {
            Ok(()) => debug!(log, "killed job processes"),
            Err(error) => error!(log, "unable to kill job"; "error" => %error),
        }
    } else {
        debug!(log, "process is already dead or has an invalid PID");
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PathIsolation {
    Enable,
    InsecureDisable,
}
