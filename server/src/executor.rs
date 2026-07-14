//! Job execution engine.
//!
//! Start, stop, and watch job processes. Driven by the session state
//! machine, but session agnostic.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{ExitStatus, Stdio};

use chrono::Utc;
use futures::Stream;
use pwd::Passwd;
use rustix::io::close;
use rustix::process::{ioctl_tiocsctty, setsid};
use slog::{Logger, o};
use terminfo::Database as Terminfo;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::{select, spawn};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use sush_api::JobStartParams;
use sush_common::interactive::WindowSize;
use sush_common::jobs::{JobId, JobOutputStream, JobStartRequest, ProcessError};

use crate::interactive::{InteractiveJob, SocketSender};
use crate::messages::{Event, JobEvent};
use crate::output::JobOutputDir;
use crate::pty::Pty;

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

    /// Spawn a process for a job, and return an attachment point if it is
    /// interactive. Assumes the job request has already been validated,
    /// e.g., as by [`crate::JobManager::job_start`].
    pub async fn job_start(
        &mut self,
        request: JobStartRequest,
        params: JobStartParams,
    ) -> Option<SocketSender> {
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
        } = params;

        // Report I/O errors as job events.
        let io_err = |what| move |err: io::Error| ProcessError::io(what, err);
        macro_rules! with_io_err {
            ($expr:expr, $err:expr) => {
                match $expr.map_err(io_err($err)) {
                    Ok(value) => value,
                    Err(err) => {
                        let _ = self
                            .events
                            .send(Event::Job(JobEvent::JobError(job_id, err)))
                            .await;
                        return None;
                    }
                }
            };
        }

        // Set up output files.
        let job_dir = self.output_dir.job_output_dir(&job_id);
        with_io_err!(
            DirBuilder::new().recursive(true).create(&job_dir),
            format!("creating job output directory `{}`", job_dir.display())
        );
        let stdout_path = self.output_dir.job_output_path(&job_id, Stdout);
        let stderr_path = self.output_dir.job_output_path(&job_id, Stderr);
        let stdout_file = with_io_err!(
            File::create_new(&stdout_path),
            format!("creating job stdout file `{}`", stdout_path.display())
        );
        let stderr_file = with_io_err!(
            File::create_new(&stderr_path),
            format!("creating job stderr file `{}`", stderr_path.display())
        );

        // Set up the job command.
        let mut cmd = Command::new("bash");
        assert!(!command.starts_with('-'), "should have validated command");
        cmd.arg("-c").arg(&command);

        // Set up basic environment.
        cmd.env_clear();
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

        // Prepare to stop the job on request or shutdown.
        let stop = self.shutdown.child_token();
        self.stop.insert(job_id.clone(), stop.clone());

        let attachment = if interactive {
            // Create a pseudoterminal and wire the child up to it.
            let (pty, pts, pts_path) =
                with_io_err!(Pty::open(), "opening pseudoterminal".to_string());
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
                    setsid()?; // create new process session
                    ioctl_tiocsctty(&pts)?; // set controlling terminal
                    Ok(())
                });
            }

            // If it has a valid terminfo database, set `TERM` and the
            // initial pseudoterminal window size.
            if let Some(term) = term
                && Terminfo::from_name(&term).is_ok()
            {
                cmd.env("TERM", term);
                if let Some(rows) = rows
                    && let Some(cols) = cols
                {
                    with_io_err!(
                        pty.set_window_size(WindowSize { rows, cols }),
                        "resizing pseudoterminal window".to_string()
                    );
                }
            };

            // Spawn the interactive job.
            let child = with_io_err!(cmd.spawn(), "spawning job process".to_string());
            let log = self
                .log
                .new(o!("interactive" => true, "job_id" => job_id.clone()));
            let job = InteractiveJob::start(log, child, pty, stdout_file.into(), stop);
            let attachment = job.attachment();

            // Wait for the interactive job to end, and send an event when it does.
            spawn({
                let events = self.events.clone();
                let job_id = job_id.clone();
                async move {
                    let exit_status = match job.wait().await {
                        Ok(exit_status) => process_exit(exit_status),
                        Err(err) => Err(ProcessError::Interactive(err.to_string())),
                    };
                    let _ = events
                        .send(Event::Job(JobEvent::JobEnd(job_id, exit_status)))
                        .await;
                }
            });

            Some(attachment)
        } else {
            // For batch jobs, close stdin and send output directly to files.
            cmd.stdin(Stdio::null())
                .stdout(stdout_file)
                .stderr(stderr_file);

            // Execute!
            let mut child = with_io_err!(cmd.spawn(), "spawning job process".to_string());

            // Wait for or induce death, and send an event when that happens.
            spawn({
                let events = self.events.clone();
                let job_id = job_id.clone();
                let mut stopped = false;
                async move {
                    loop {
                        select! {
                            _ = stop.cancelled(), if !stopped => {
                                match child.kill().await {
                                    Ok(()) => {
                                        stopped = true;
                                        continue;
                                    }
                                    Err(err) => {
                                        let _ = events
                                            .send(Event::Job(JobEvent::JobEnd(
                                                job_id,
                                                Err(ProcessError::io("stopping job", err)),
                                            )))
                                            .await;
                                        break;
                                    }
                                }
                            }
                            exit_status = child.wait() => {
                                let _ = events
                                    .send(Event::Job(JobEvent::JobEnd(
                                        job_id,
                                        match exit_status {
                                            Ok(exit_status) => process_exit(exit_status),
                                            Err(err) => Err(ProcessError::io("waiting", err)),
                                        },
                                    )))
                                    .await;
                                break;
                            }
                        }
                    }
                }
            });

            None
        };

        // Notify interested parties of birth.
        let _ = self
            .events
            .send(Event::Job(JobEvent::JobStart(job_id.clone(), Utc::now())))
            .await;

        attachment
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

fn process_exit(exit_status: ExitStatus) -> Result<i32, ProcessError> {
    if let Some(code) = exit_status.code() {
        Ok(code)
    } else if let Some(signal) = exit_status.signal() {
        Err(ProcessError::Killed(signal))
    } else {
        // Processes should either exit with a code or
        // be killed by a signal; there is no third option
        // on Unix. But since the type system does not
        // guarantee that, this branch is technically
        // reachable, but impossible in practice.
        Err(ProcessError::Unknown)
    }
}
