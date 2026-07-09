//! Job execution engine.
//!
//! Executes, monitors, and halts jobs. Driven by the session state machine,
//! and session agnostic.

use std::collections::BTreeMap;
use std::fs::{DirBuilder, File};
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::Stdio;

use chrono::Utc;
use futures::Stream;
use pwd::Passwd;
use rustix::io::close;
use rustix::process::{ioctl_tiocsctty, setsid};
use terminfo::Database as Terminfo;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::{select, spawn};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use sush_api::JobStartParams;
use sush_common::interactive::WindowSize;
use sush_common::jobs::{JobId, JobOutputStream, JobStartRequest, ProcessError};

use crate::messages::{Event, JobEvent};
use crate::output::JobOutputDir;
use crate::pty::Pty;

pub struct Executor {
    events: mpsc::Sender<Event>,
    output_dir: JobOutputDir,
    shutdown: CancellationToken,
    kill: BTreeMap<JobId, CancellationToken>,
    ptys: BTreeMap<JobId, Pty>,
}

/// Executor methods should be infallible; errors are reported via events.
impl Executor {
    pub fn new(
        output_dir: JobOutputDir,
        shutdown: CancellationToken,
    ) -> (Self, impl Stream<Item = Event> + Send + 'static) {
        // This queue size is an arbitrary choice. We expect to consume
        // messages from the channel very rapidly, so should not
        // experience backpressure; if we do, something is wrong.
        let (tx, rx) = mpsc::channel(16);
        (
            Self {
                events: tx,
                output_dir,
                shutdown,
                kill: BTreeMap::new(),
                ptys: BTreeMap::new(),
            },
            ReceiverStream::new(rx),
        )
    }

    pub async fn job_start(&mut self, request: JobStartRequest, params: JobStartParams) {
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
                        return;
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

        // Set up the job child process.
        let mut child = Command::new("bash");
        child
            .arg("-c")
            .arg(&command)
            .env_clear()
            .env("SSH_CLIENT", "sush") // read bashrc
            .env("SUSH_JOB_ID", job_id.to_string())
            .env("SUSH_COMMAND", &command);

        // Set basic user environment.
        if let Some(pwd) = Passwd::current_user() {
            child
                .current_dir(&pwd.dir)
                .env("HOME", &pwd.dir)
                .env("LOGNAME", &pwd.name)
                .env("USER", &pwd.name);
        }

        if interactive {
            // Create a pseudoterminal for interactive jobs and wire
            // the child up to it.
            let (pty, pts, pts_path) =
                with_io_err!(Pty::open(), "opening pseudoterminal".to_string());
            macro_rules! pts_clone {
                () => {
                    with_io_err!(pts.try_clone(), "cloning pseudoterminal".to_string())
                };
            }
            child
                .env("SUSH_TTY", &pts_path)
                .stdin(pts_clone!())
                .stdout(pts_clone!())
                .stderr(pts_clone!());

            unsafe {
                let pty = pty.as_raw_fd();
                child.pre_exec(move || {
                    close(pty); // not needed in the child
                    setsid()?; // create new process session
                    ioctl_tiocsctty(&pts)?; // set controlling terminal
                    limits.apply() // set process limits
                });
            }

            // If it has a valid terminfo database, set `TERM` and the
            // initial pseudoterminal window size.
            if let Some(term) = term
                && Terminfo::from_name(&term).is_ok()
            {
                child.env("TERM", term);
                if let Some(rows) = rows
                    && let Some(cols) = cols
                {
                    with_io_err!(
                        pty.set_window_size(WindowSize { rows, cols }),
                        "resizing pseudoterminal window".to_string()
                    );
                }
            };

            self.ptys.insert(job_id.clone(), pty);
        } else {
            // For batch jobs, close stdin and send output directly to files.
            child
                .stdin(Stdio::null())
                .stdout(stdout_file)
                .stderr(stderr_file);
            unsafe {
                child.pre_exec(move || limits.apply());
            }
        };

        // Execute!
        let mut child = with_io_err!(child.spawn(), "spawning job process".to_string());

        // Notify interested parties of birth.
        let _ = self
            .events
            .send(Event::Job(JobEvent::JobStart(job_id.clone(), Utc::now())))
            .await;

        // Wait for or induce death, and notify interested parties.
        let events = self.events.clone();
        let shutdown = self.shutdown.child_token();
        self.kill.insert(job_id.clone(), shutdown.clone());
        let mut killed = false;
        spawn(async move {
            loop {
                select! {
                    _kill = shutdown.cancelled(), if !killed => {
                        match child.kill().await {
                            Ok(()) => {
                                killed = true;
                                continue;
                            }
                            Err(err) => {
                                let _ = events
                                    .send(Event::Job(JobEvent::JobEnd(
                                        job_id,
                                        Err(ProcessError::io("killing job", err)),
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
                                    Ok(exit_status) => {
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
                                    Err(err) => Err(ProcessError::io("waiting", err)),
                                },
                            )))
                            .await;
                        break;
                    }
                }
            }
        });
    }

    pub fn job_attach(&self, _job_id: &JobId) {
        todo!()
    }

    pub fn job_status(&self, _job_id: &JobId) {
        todo!()
    }

    pub fn job_stop(&self, job_id: &JobId) {
        if let Some(kill) = self.kill.get(job_id) {
            kill.cancel();
        }
    }

    pub fn output_dir(&self) -> &JobOutputDir {
        &self.output_dir
    }
}
