//! Job execution engine.
//!
//! Start, stop, and watch job processes. Driven by the session state
//! machine, but session agnostic.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::AsRawFd as _;
use std::process::Stdio;

use chrono::Utc;
use futures::Stream;
use pwd::Passwd;
use rustix::io::close;
use rustix::process::{Pid, Signal, ioctl_tiocsctty, kill_process_group, setsid};
use slog::{Logger, debug, error, o};
use tokio::fs::{DirBuilder, File};
use tokio::process::{Child, Command};
use tokio::spawn;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use sush_api::JobStartParams;
use sush_common::interactive::WindowSize;
use sush_common::jobs::{JobId, JobOutputStream, JobStartRequest, ProcessError};

use crate::io::JobIo;
use crate::job::{Job, SocketSender};
use crate::messages::{Event, JobEvent};
use crate::output::JobOutputDir;
use crate::pty::Pty;

pub const DEFAULT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
pub const DEFAULT_TERM: &str = "vt100";

pub struct Executor {
    log: Logger,
    events: mpsc::Sender<Event>,
    output_dir: JobOutputDir,
    shutdown: CancellationToken,
    stop: BTreeMap<JobId, CancellationToken>,
}

/// Executor methods should be infallible; errors are reported via events.
impl Executor {
    pub fn new(
        log: Logger,
        output_dir: JobOutputDir,
        shutdown: CancellationToken,
    ) -> (Self, impl Stream<Item = Event> + Send + 'static) {
        // This queue size is an arbitrary choice. We expect to consume
        // messages from the channel very rapidly, so should not
        // experience backpressure; if we do, something is wrong.
        let (tx, rx) = mpsc::channel(16);
        (
            Self {
                log,
                events: tx,
                output_dir,
                shutdown,
                stop: BTreeMap::new(),
            },
            ReceiverStream::new(rx),
        )
    }

    pub fn job_start(
        &mut self,
        request: JobStartRequest,
        params: JobStartParams,
        tx_attachment: watch::Sender<Option<SocketSender>>,
    ) {
        let stop = self.shutdown.child_token();
        self.stop.insert(request.job_id().clone(), stop.clone());
        spawn(job_spawn(
            self.log.new(o!("job_id" => request.job_id().clone())),
            self.events.clone(),
            self.output_dir.clone(),
            request,
            params,
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
async fn job_spawn(
    log: Logger,
    events: mpsc::Sender<Event>,
    output_dir: JobOutputDir,
    request: JobStartRequest,
    params: JobStartParams,
    tx_attachment: watch::Sender<Option<SocketSender>>,
    stop: CancellationToken,
) {
    use JobOutputStream::*;
    let JobStartRequest {
        job_id,
        command,
        interactive,
    } = request;
    let JobStartParams {
        limits,
        term,
        rows,
        cols,
        wait: _,
    } = params;

    // Report I/O errors as job events.
    let io_err = |what| move |err: io::Error| ProcessError::io(what, err);
    macro_rules! with_io_err {
        ($expr:expr, $err:expr) => {
            match $expr.map_err(io_err($err)) {
                Ok(value) => value,
                Err(err) => {
                    if tx_attachment.send(None).is_err() {
                        error!(log, "can't clear attachment point");
                    }
                    send_error(&log, &job_id, &events, err).await;
                    return;
                }
            }
        };
    }

    // Set up output files.
    let job_dir = output_dir.job_output_dir(&job_id);
    with_io_err!(
        DirBuilder::new().recursive(true).create(&job_dir).await,
        format!("creating job output directory `{}`", job_dir.display())
    );
    let stdout_path = output_dir.job_output_path(&job_id, Stdout);
    let stderr_path = output_dir.job_output_path(&job_id, Stderr);
    let stdout_file = with_io_err!(
        File::create_new(&stdout_path).await,
        format!("creating job stdout file `{}`", stdout_path.display())
    );
    let stderr_file = with_io_err!(
        File::create_new(&stderr_path).await,
        format!("creating job stderr file `{}`", stderr_path.display())
    );

    // Set up the job command.
    let mut cmd = Command::new("bash");
    cmd.kill_on_drop(true);
    cmd.arg("-c").arg(&command);

    // Set up basic environment.
    cmd.env_clear();
    cmd.env("PATH", DEFAULT_PATH);
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
        let (pty, pts, pts_path) = with_io_err!(Pty::open(), "opening pseudoterminal".to_string());
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
        let io = with_io_err!(
            JobIo::interactive(pty, stop.child_token()),
            "creating pty I/O wrapper".to_string()
        );
        Job::start(
            log.new(o!("interactive" => interactive)),
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
        .send(Event::Job(JobEvent::Start(job_id.clone(), Utc::now())))
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
            Err(err) => error!(log, "unable to kill job"; "error" => %err),
        }
    } else {
        debug!(log, "process is already dead or has an invalid PID");
    }
}
