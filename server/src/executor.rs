//! Job execution engine.
//!
//! Executes, monitors, and halts jobs. Driven by the session state machine.

use std::fs::{DirBuilder, File};
use std::io;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
use std::process::Stdio;

use blake3::Hasher;
use futures::Stream;
use pwd::Passwd;
use rustix::io::close;
use rustix::process::{ioctl_tiocsctty, setsid};
use terminfo::Database as Terminfo;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use sush_api::JobStartParams;
use sush_common::interactive::WindowSize;
use sush_common::jobs::{ExecutionError, JobId, JobOutputHash, JobOutputStream, JobStartRequest};

use crate::messages::Event;
use crate::pty::Pty;

pub struct Executor {
    events: mpsc::Sender<Event>,
    output_dir: PathBuf,
}

impl Executor {
    pub fn new(
        output_dir: PathBuf,
        _shutdown: CancellationToken,
    ) -> (Self, impl Stream<Item = Event> + Send + 'static) {
        // This queue size is an arbitrary choice. We expect to consume
        // messages from the channel very rapidly, so should not
        // experience backpressure; if we do, something is wrong.
        let (tx, rx) = mpsc::channel(16);
        (
            Self {
                events: tx,
                output_dir,
            },
            ReceiverStream::new(rx),
        )
    }

    pub fn job_start(
        &self,
        request: JobStartRequest,
        params: JobStartParams,
    ) -> Result<(), ExecutionError> {
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

        // Report I/O errors.
        let io_err = {
            let job_id = job_id.to_owned();
            |what: String| move |err| ExecutionError::io(job_id.to_owned(), &what, err)
        };

        // Set up output files.
        let job_dir = self.job_output_dir(&job_id);
        DirBuilder::new()
            .recursive(true)
            .create(&job_dir)
            .map_err(io_err.clone()(format!(
                "creating job output directory `{}`",
                job_dir.display()
            )))?;
        let stdout_path = self.job_output_path(&job_id, JobOutputStream::Stdout);
        let stderr_path = self.job_output_path(&job_id, JobOutputStream::Stderr);
        let stdout_file = File::create_new(&stdout_path).map_err(io_err.clone()(format!(
            "creating job stdout file `{}`",
            stdout_path.display()
        )))?;
        let stderr_file = File::create_new(&stderr_path).map_err(io_err.clone()(format!(
            "creating job stderr file `{}`",
            stderr_path.display()
        )))?;

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

        let pty = if interactive {
            // Create a pseudoterminal for interactive jobs and wire
            // the child up to it.
            let (pty, pts, pts_path) =
                Pty::open().map_err(io_err.clone()("opening pseudoterminal".to_string()))?;
            let pts_clone = || {
                pts.try_clone()
                    .map_err(io_err.clone()("cloning pseudoterminal".to_string()))
            };
            child
                .env("SUSH_TTY", &pts_path)
                .stdin(pts_clone()?)
                .stdout(pts_clone()?)
                .stderr(pts_clone()?);

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
                    pty.set_window_size(WindowSize { rows, cols })
                        .map_err(io_err.clone()("resizing pseudoterminal window".to_string()))?;
                }
            };

            Some(pty)
        } else {
            // For batch jobs, close stdin and send output directly to files.
            child
                .stdin(Stdio::null())
                .stdout(stdout_file)
                .stderr(stderr_file);
            unsafe {
                child.pre_exec(move || limits.apply());
            }
            None
        };

        // Execute!
        let child = child
            .spawn()
            .map_err(io_err("spawning job process".to_string()))?;
        Ok(())
    }

    pub fn job_attach(&self, _job_id: &JobId) {
        todo!()
    }

    pub fn job_status(&self, _job_id: &JobId) {
        todo!()
    }

    pub fn job_stop(&self, _job_id: &JobId) {
        todo!()
    }

    fn job_output_dir(&self, job_id: &JobId) -> PathBuf {
        self.output_dir.join("jobs").join(job_id.to_string())
    }

    fn job_output_path(&self, job_id: &JobId, stream: JobOutputStream) -> PathBuf {
        self.job_output_dir(job_id).join(stream.as_str())
    }

    fn job_output_len(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
    ) -> Result<u64, ExecutionError> {
        let path = self.job_output_path(job_id, stream);
        match path.metadata().map(|m| m.len()) {
            Ok(len) => Ok(len),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0),
            Err(err) => Err(ExecutionError::io(
                job_id.clone(),
                &format!("getting length of {}", path.display()),
                err,
            )),
        }
    }

    fn job_output_hash(
        &self,
        job_id: &JobId,
        stream: JobOutputStream,
    ) -> Result<JobOutputHash, ExecutionError> {
        let mut hasher = Hasher::new();
        let path = self.job_output_path(job_id, stream);
        match hasher.update_mmap_rayon(&path) {
            Ok(_) => (),
            Err(err) if err.kind() == io::ErrorKind::NotFound => (),
            Err(err) => {
                return Err(ExecutionError::io(
                    job_id.clone(),
                    &format!("getting length of {}", path.display()),
                    err,
                ));
            }
        }
        Ok(hasher.finalize().into())
    }

    pub fn job_output_state(&self, job_id: &JobId) -> Result<JobOutputState, ExecutionError> {
        Ok(JobOutputState {
            stdout_len: self.job_output_len(job_id, JobOutputStream::Stdout)?,
            stderr_len: self.job_output_len(job_id, JobOutputStream::Stderr)?,
            stdout_hash: self.job_output_hash(job_id, JobOutputStream::Stdout)?,
            stderr_hash: self.job_output_hash(job_id, JobOutputStream::Stderr)?,
        })
    }
}

#[derive(Debug, Default)]
pub struct JobOutputState {
    pub stdout_len: u64,
    pub stderr_len: u64,
    pub stdout_hash: JobOutputHash,
    pub stderr_hash: JobOutputHash,
}
