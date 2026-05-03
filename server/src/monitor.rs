//! Monitor a set of running jobs and sessions, and report state changes
//! to the job manager.
//!
//! The monitor is not completely passive: it is also responsible for
//! maintaining and, when requested, using the shutdown switches for jobs.
//! It also maintains the interactive job sessions.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::ExitStatus;

use chrono::{DateTime, Utc};
use futures::FutureExt;
use slog::{Logger, error, info, o};
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::{select, spawn};

use sush_common::jobs::JobOutputStream::{Stderr, Stdout};
use sush_common::jobs::{JobId, JobOutputHash, JobStatus, VerifiedJob};
use sush_common::keys::KeyId;
use sush_common::session::SessionError;

use crate::error::{ExecutionError, JobError};
use crate::manager::{job_output_hash, job_output_len, job_output_path};
use crate::pty::Pty;
use crate::session::{Session, SocketSender};

/// The monitor runs as a tokio task that communicates with the manager
/// via message passing. It does not have a connection to the database.
#[derive(Debug)]
pub struct JobMonitor {
    log: Logger,
    output_dir: PathBuf,
    tasks: JoinSet<Result<JobEnded, ExecutionError>>,
    sessions: BTreeMap<JobId, SocketSender>,
    shutdown: BTreeMap<JobId, Shutdown>,
    watchers: BTreeMap<JobId, Watcher>,
}

impl JobMonitor {
    pub fn start(
        log: Logger,
        output_dir: PathBuf,
    ) -> (
        mpsc::Sender<MonitorRequest>,
        mpsc::Receiver<ExecutionResult>,
    ) {
        let mut monitor = JobMonitor {
            log: log.clone(),
            output_dir,
            tasks: JoinSet::new(),
            shutdown: BTreeMap::new(),
            sessions: BTreeMap::new(),
            watchers: BTreeMap::new(),
        };
        let (tx_req, mut rx_req) = mpsc::channel(1);
        let (tx_end, rx_end) = mpsc::channel(1);
        spawn({
            async move {
                loop {
                    select! {
                        Some(req) = rx_req.recv() => {
                            macro_rules! watch {
                                ($job_id:expr, $monitor:expr, $expr:expr) => {{
                                    let job_id = $job_id.to_owned();
                                    match $expr {
                                        Ok(()) => (),
                                        Err(err) => {
                                            if let Some(watcher) = $monitor.watchers.remove(&job_id) {
                                                let _ = monitor.shutdown.remove(&job_id);
                                                let _ = monitor.sessions.remove(&job_id);
                                                let _ = watcher.send(Err(ExecutionError::new(job_id, err)));
                                            }
                                        }
                                    }
                                }};
                            }
                            match req {
                                MonitorRequest::Session(job_id, sender) => {
                                    watch!(job_id, monitor, monitor.session(&job_id, sender))
                                }
                                MonitorRequest::Started(event, watcher) => {
                                    let job_id = event.job_id().to_owned();
                                    monitor.watchers.insert(job_id.clone(), watcher);
                                    watch!(job_id, monitor, monitor.job_started(*event))
                                }
                                MonitorRequest::Stop(job_id) => {
                                    watch!(job_id, monitor, monitor.stop_job(&log, &job_id))
                                }
                            }
                        }
                        Some(Ok(end)) = monitor.tasks.join_next() => {
                            let job_id = match &end {
                                Ok(end) => {
                                    let job_id = end.job_id();
                                    info!(log, "job ended"; "job_id" => %job_id);
                                    job_id.to_owned()
                                }
                                Err(ExecutionError { job_id, time, error } ) => {
                                    error!(log, "job failed"; "error" => %error, "job_id" => %job_id, "time" => %time);
                                    job_id.to_owned()
                                }
                            };
                            let _ = monitor.shutdown.remove(&job_id);
                            let _ = monitor.sessions.remove(&job_id);
                            if let Some(watcher) = monitor.watchers.remove(&job_id) {
                                 let _ = watcher.send(end.clone());
                            }
                            tx_end.send(end).await.map_err(JobError::closed)?;
                        },
                        else => break,
                    }
                }
                info!(log, "job monitor loop ended");
                Ok::<_, JobError>(())
            }
        });
        (tx_req, rx_end)
    }

    fn session(&mut self, job_id: &JobId, sender: SocketSenderSender) -> Result<(), JobError> {
        if let Some(session) = self.sessions.get(job_id) {
            info!(self.log, "started interactive session"; "job_id" => %job_id);
            let _ = sender.send(Ok(session.clone()));
            Ok(())
        } else {
            error!(self.log, "failed to start session, job ended"; "job_id" => %job_id);
            let _ = sender.send(Err(JobError::Session(SessionError::JobEnded)));
            Err(JobError::Session(SessionError::JobEnded))
        }
    }

    fn job_started(
        &mut self,
        JobStarted {
            job,
            time_started,
            child,
            interactive,
        }: JobStarted,
    ) -> Result<(), JobError> {
        let job_id = job.job_id().to_owned();
        let (session, shutdown) = if let Some((key_id, pty)) = interactive {
            self.interactive_job(&job_id, &key_id, pty, child)?
        } else {
            self.batch_job(child)
        };
        assert!(
            self.shutdown.insert(job_id.clone(), shutdown).is_none(),
            "should not already have a shutdown channel for a new job"
        );

        let output_dir = self.output_dir.to_owned();
        self.tasks.spawn(async move {
            let exe = |err| ExecutionError::new(job_id.clone(), err);
            let status = session.await.map_err(exe)?;
            let end = JobEnded {
                job,
                time_started,
                time_ended: Utc::now(),
                status,
                stdout_len: job_output_len(&output_dir, &job_id, Stdout),
                stderr_len: job_output_len(&output_dir, &job_id, Stderr),
                stdout_hash: job_output_hash(&output_dir, &job_id, Stdout).map_err(exe)?,
                stderr_hash: job_output_hash(&output_dir, &job_id, Stderr).map_err(exe)?,
            };
            Ok(end)
        });

        Ok(())
    }

    fn stop_job(&mut self, log: &Logger, job_id: &JobId) -> Result<(), JobError> {
        if let Some(shutdown) = self.shutdown.remove(job_id)
            && let Ok(()) = shutdown.send(())
        {
            info!(log, "job stopped"; "job_id" => %job_id);
            Ok(())
        } else {
            error!(log, "failed to stop job"; "job_id" => %job_id);
            Err(JobError::Shutdown(job_id.to_owned()))
        }
    }

    fn interactive_job(
        &mut self,
        job_id: &JobId,
        key_id: &KeyId,
        pty: Pty,
        child: Child,
    ) -> Result<(PinnedSession, Shutdown), JobError> {
        let path = job_output_path(&self.output_dir, job_id, Stdout);
        let io_error = JobError::file_io_for(path.clone());
        let output_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(&io_error)?;
        let log = self.log.new(o!("interactive" => key_id.to_string()));
        let (session, shutdown) = Session::start(log, child, pty, output_file.into());
        assert!(
            self.sessions
                .insert(job_id.to_owned(), session.clients())
                .is_none(),
            "should not already have a session for a new job"
        );
        let future = async { session.wait().await.map_err(|err| err.into()) };
        Ok((future.boxed(), shutdown))
    }

    fn batch_job(&mut self, mut child: Child) -> (PinnedSession, Shutdown) {
        let (kill, die) = oneshot::channel();
        let future = async move {
            select! {
                status = child.wait() => status.map_err(|err| JobError::io("wait", err)),
                _ = die => {
                    child.start_kill().map_err(|err| JobError::io("kill", err))?;
                    child.wait().await.map_err(|err| JobError::io("wait", err))
                }
            }
        };
        (future.boxed(), kill)
    }
}

/// A pinned interactive session.
type PinnedSession = Pin<Box<dyn Future<Output = Result<ExitStatus, JobError>> + Send>>;

/// An asynchronous kill signal, delivered by the `Stop` request.
type Shutdown = oneshot::Sender<()>;

/// Channels carrying channels? What's next, factory factories?
/// Seriously, though, we need this because the manager needs
/// a [`SocketSender`] to support async WebSocket upgrade, and
/// so must supply a channel through which we can pass one back.
/// But if the job has ended, we pass back an error.
type SocketSenderSender = oneshot::Sender<Result<SocketSender, JobError>>;

/// “We observe, we record, but we never interfere…”
type Watcher = oneshot::Sender<ExecutionResult>;

/// Request sent from the manager to the monitor.
pub enum MonitorRequest {
    Session(JobId, SocketSenderSender),
    Started(Box<JobStarted>, Watcher),
    Stop(JobId),
}

impl MonitorRequest {
    pub fn session(job_id: JobId, sender: SocketSenderSender) -> Self {
        Self::Session(job_id, sender)
    }

    pub fn started(job_started: JobStarted, watcher: Watcher) -> Self {
        Self::Started(Box::new(job_started), watcher)
    }

    pub fn stop(job_id: JobId) -> Self {
        Self::Stop(job_id)
    }
}

/// Event representing the beginning of a job. The manager spawns the child,
/// then passses one of these to the monitor.
#[derive(Debug)]
pub struct JobStarted {
    pub job: VerifiedJob,
    pub time_started: DateTime<Utc>,
    pub child: Child,
    pub interactive: Option<(KeyId, Pty)>,
}

impl JobStarted {
    pub fn job_id(&self) -> &JobId {
        self.job.job_id()
    }
}

impl From<&JobStarted> for JobStatus {
    fn from(start: &JobStarted) -> Self {
        let JobStarted {
            job,
            time_started,
            child: _,
            interactive: _,
        } = start;
        Self::Started {
            job: job.to_owned(),
            time_started: time_started.to_owned(),
            stdout_len: 0,
            stderr_len: 0,
        }
    }
}

/// Event representing the end of a job.
#[derive(Clone, Debug)]
pub struct JobEnded {
    pub job: VerifiedJob,
    pub time_started: DateTime<Utc>,
    pub time_ended: DateTime<Utc>,
    pub status: ExitStatus,
    pub stdout_len: u64,
    pub stderr_len: u64,
    pub stdout_hash: JobOutputHash,
    pub stderr_hash: JobOutputHash,
}

impl JobEnded {
    pub fn job_id(&self) -> &JobId {
        self.job.job_id()
    }
}

impl From<JobEnded> for JobStatus {
    fn from(end: JobEnded) -> Self {
        let JobEnded {
            job,
            time_started,
            time_ended,
            status,
            stdout_len,
            stderr_len,
            stdout_hash,
            stderr_hash,
        } = end;
        Self::Ended {
            job,
            time_started,
            time_ended,
            status: status.code(),
            stdout_len,
            stderr_len,
            stdout_hash,
            stderr_hash,
        }
    }
}

/// The end of a job, one way or another.
pub type ExecutionResult = Result<JobEnded, ExecutionError>;
