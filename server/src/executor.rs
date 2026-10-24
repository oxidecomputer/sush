// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Job execution engine.
//!
//! Start, stop, and watch job processes. Driven by the session state
//! machine, but session agnostic.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::sync::{Arc, RwLock};

use chrono::Utc;
use futures::Stream;
use pwd::Passwd;
#[cfg(target_os = "illumos")]
use slog::debug;
use slog::{Logger, error, o, warn};
use tokio::fs::{DirBuilder, OpenOptions};
use tokio::io::AsyncWriteExt as _;
use tokio::spawn;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;

use sush_api::JobStartParams;
use sush_common::interactive::WindowSize;
use sush_common::jobs::{
    JobId, JobMode, JobOutputStream, JobStartRequest, ProcessError, VerifiedJob,
};

#[cfg(target_os = "illumos")]
use crate::contract::spawn_in_contract;
use crate::io::JobIo;
use crate::job::{Job, SocketSender};
use crate::locker::boundary::{Boundary, BoundaryStore};
use crate::messages::v0::{Event, JobEvent};
use crate::output::JobOutputDir;
use crate::spawn::{JobChild, PosixSpawn, SpawnStdio};

pub const DEFAULT_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
pub const DEFAULT_TERM: &str = "vt100";

const BASH: &str = "/usr/bin/bash";

/// A bash script that sets a job's soft limits and then execs the job
/// in `$BASH`, the bash running the script. posix_spawn cannot set
/// resource limits on the child, so the child must set its own before
/// it execs the job. The script's arguments are the maximum CPU seconds,
/// address space (in KiB), file size (in KiB), and the job command.
///
/// For compatibility with `ssh`, we set `SSH_CLIENT` so that bash reads
/// `/root/.bashrc`. We set it only for the exec'd job, so that bash reads
/// it only once.
const LIMITS_SHIM: &str =
    r#"ulimit -S -t "$1" -v "$2" -f "$3" && SSH_CLIENT=sush exec "$BASH" -c "$4""#;

/// This queue size is an arbitrary choice. We expect to consume
/// messages from the channel very rapidly, so should not
/// experience backpressure; if we do, something is wrong.
const EVENTS_CHANNEL_CAPACITY: usize = 16;

/// Each queued launch waits on one small fsync, so the queue drains in
/// milliseconds. A burst of concurrent jobs can still fill it, and a
/// full queue refuses the job with an error event rather than block
/// the state machine.
const LAUNCH_CHANNEL_CAPACITY: usize = 16;

pub struct Executor {
    log: Logger,
    events: Arc<RwLock<Option<mpsc::Sender<Event>>>>,
    path_isolation: PathIsolation,
    output_dir: JobOutputDir,
    launch: mpsc::Sender<Launch>,
    shutdown: CancellationToken,
    stop: BTreeMap<JobId, CancellationToken>,
}

/// One validated job on its way to the launcher.
struct Launch {
    log: Logger,
    boundary: Boundary,
    events: mpsc::Sender<Event>,
    output_dir: JobOutputDir,
    request: VerifiedJob,
    params: JobStartParams,
    path_isolation: PathIsolation,
    tx_attachment: watch::Sender<Option<SocketSender>>,
    stop: CancellationToken,
}

/// Executor methods should be infallible; errors are reported via events.
impl Executor {
    pub fn new(
        log: Logger,
        path_isolation: PathIsolation,
        output_dir: JobOutputDir,
        boundary: Arc<BoundaryStore>,
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

        // The queue keeps boundary writes in release order. If each job
        // advanced the boundary from its own task, two writes could land
        // out of order, and the record would name an older job than one
        // that already spawned.
        let (launch, mut queued) = mpsc::channel::<Launch>(LAUNCH_CHANNEL_CAPACITY);
        spawn(async move {
            while let Some(launch) = queued.recv().await {
                if let Err(error) = boundary.advance(&launch.boundary).await {
                    let error = ProcessError::Io {
                        what: "recording the execution boundary".to_string(),
                        error: error.to_string(),
                    };
                    send_error(
                        &launch.log,
                        launch.request.payload().job_id(),
                        &launch.events,
                        error,
                    )
                    .await;
                    continue;
                }
                spawn(job_spawn(launch));
            }
        });

        // Return the executor and event stream.
        (
            Self {
                log,
                events,
                path_isolation,
                output_dir,
                launch,
                shutdown,
                stop: BTreeMap::new(),
            },
            ReceiverStream::new(rx_events),
        )
    }

    /// Whether the executor can launch this command. The rule lives
    /// here because it comes from how the launch builds its argv.
    pub fn check_command(request: &JobStartRequest) -> Result<(), ProcessError> {
        if request.command.starts_with('-') {
            return Err(ProcessError::InvalidCommand);
        }
        Ok(())
    }

    /// Queue a job for launch. The caller has screened the request:
    /// the signature is verified and the command passed
    /// [`Executor::check_command`].
    pub fn job_start(
        &mut self,
        request: VerifiedJob,
        params: JobStartParams,
        tx_attachment: watch::Sender<Option<SocketSender>>,
        boundary: Boundary,
    ) {
        let Some(events) = self.events.read().unwrap().as_ref().cloned() else {
            // No more events ⇒ shutting down ⇒ no new jobs allowed.
            return;
        };

        let job_id = request.payload().job_id().to_owned();
        let stop = self.shutdown.child_token();
        self.stop.insert(job_id, stop.clone());
        let refused = self.launch.try_send(Launch {
            log: self.log.new(o!("job_id" => job_id)),
            boundary,
            events,
            output_dir: self.output_dir.clone(),
            request,
            params,
            path_isolation: self.path_isolation,
            tx_attachment,
            stop,
        });
        if let Err(error) = refused {
            self.stop.remove(&job_id);
            self.job_refused(
                job_id,
                ProcessError::Io {
                    what: "queueing the job for launch".to_string(),
                    error: error.to_string(),
                },
            );
        }
    }

    pub fn job_stop(&mut self, job_id: &JobId) {
        if let Some(stop) = self.stop.remove(job_id) {
            stop.cancel();
        }
    }

    pub fn job_stopped(&mut self, job_id: &JobId) {
        let _ = self.stop.remove(job_id);
    }

    /// Every job accepted for launch whose stop token is still held:
    /// queued, spawning, or running.
    pub fn in_flight(&self) -> BTreeSet<JobId> {
        self.stop.keys().copied().collect()
    }

    /// Announce a job that will never run here.
    pub fn job_refused(&self, job_id: JobId, error: ProcessError) {
        let Some(events) = self.events.read().unwrap().as_ref().cloned() else {
            return;
        };
        let log = self.log.clone();
        spawn(async move {
            send_error(&log, &job_id, &events, error).await;
        });
    }

    pub fn output_dir(&self) -> &JobOutputDir {
        &self.output_dir
    }
}

/// Spawn a process for a job and return an attachment point if it is
/// interactive. Assumes [`Executor::job_start`] validated the request
/// and the launcher committed its boundary.
async fn job_spawn(launch: Launch) {
    use JobOutputStream::*;
    let Launch {
        log,
        boundary: _,
        events,
        output_dir,
        request,
        params,
        path_isolation,
        tx_attachment,
        stop,
    } = launch;
    let JobStartRequest {
        job_id,
        session_id: _,
        command,
        mode,
        target,
    } = request.payload().clone();
    let JobStartParams {
        limits: requested,
        term,
        rows,
        cols,
        wait: _,
    } = params;
    let mut limits = match requested.clone().clamp() {
        Ok(limits) => limits,
        Err(error) => {
            let error = ProcessError::io("reading resource limits", error);
            send_error(&log, &job_id, &events, error).await;
            return;
        }
    };
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

    if matches!(mode, JobMode::StreamInput) {
        let error = ProcessError::InvalidJob("streaming input is not implemented".to_string());
        send_error(&log, &job_id, &events, error).await;
        return;
    }
    if mode.is_streaming() && target.single_baseboard().is_none() {
        let error = ProcessError::InvalidJob("streaming jobs must target one sled".to_string());
        send_error(&log, &job_id, &events, error).await;
        return;
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
    let stdout_file = if matches!(mode, JobMode::StreamOutput) {
        with_io_err!(
            OpenOptions::new().write(true).open("/dev/null").await,
            "opening /dev/null for streamed output".to_string()
        )
    } else {
        with_io_err!(
            OpenOptions::new()
                .create_new(true)
                .read(true) // needed for interactive job output playback
                .write(true)
                .mode(file_mode)
                .open(&stdout_path)
                .await,
            format!("creating job stdout file `{}`", stdout_path.display())
        )
    };
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

    // Record the signed request beside the output it produces, so
    // the job directory attests what ran even after gossip forgets.
    let job_path = job_dir.join("job.json");
    let json = with_io_err!(
        serde_json::to_vec_pretty(&*request).map_err(io::Error::other),
        format!("encoding job request file `{}`", job_path.display())
    );
    let mut job_file = with_io_err!(
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(file_mode)
            .open(&job_path)
            .await,
        format!("creating job request file `{}`", job_path.display())
    );
    with_io_err!(
        job_file.write_all(&json).await,
        format!("writing job request file `{}`", job_path.display())
    );

    // Set up the job's environment.
    let mut env = Vec::new();
    match path_isolation {
        PathIsolation::Enable => env.push(("PATH", OsString::from(DEFAULT_PATH))),
        PathIsolation::InsecureDisable => {
            if let Some(path) = std::env::var_os("PATH") {
                env.push(("PATH", path));
            }
        }
    }
    let pwd = Passwd::current_user();
    if let Some(pwd) = &pwd {
        env.push(("HOME", pwd.dir.clone().into()));
        env.push(("LOGNAME", pwd.name.clone().into()));
        env.push(("USER", pwd.name.clone().into()));
    }
    env.push(("SUSH_JOB_ID", job_id.to_string().into()));
    env.push(("SUSH_COMMAND", command.clone().into()));
    env.push(("SUSH_JOB_OUTPUT_DIR", job_dir.clone().into()));

    let args = [
        BASH.to_string(),
        "-c".to_string(),
        LIMITS_SHIM.to_string(),
        "sush".to_string(),
        limits.max_cpu.to_string(),
        limits.max_mem.div_ceil(1024).to_string(),
        limits.max_fsize.div_ceil(1024).to_string(),
        command,
    ];

    let (mut io, stdio) = with_io_err!(
        JobIo::open(mode, stop.child_token()),
        "opening job I/O".to_string()
    );
    if let SpawnStdio::Terminal { path, .. } = &stdio {
        env.push(("SUSH_TTY", path.clone().into()));
        env.push((
            "TERM",
            term.unwrap_or_else(|| DEFAULT_TERM.to_string()).into(),
        ));
        if let (Some(rows), Some(cols)) = (rows, cols) {
            with_io_err!(
                io.set_window_size(WindowSize { rows, cols }),
                "resizing pseudoterminal window".to_string()
            );
        }
    }

    // Start the job in $HOME.
    let home = pwd.as_ref().map(|pwd| pwd.dir.as_str());
    let child = with_io_err!(
        spawn_job(&log, &job_id, home, stdio, &args, &env),
        format!("spawning {} job", mode.as_str())
    );
    let job = Job::start(
        log.new(o!("mode" => mode.as_str())),
        limits,
        child,
        io,
        stdout_file,
        stderr_file,
        mode,
        stop,
    );

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

/// Spawn a job's shell in `dir`, on illumos into a contract of its own.
fn spawn_job(
    log: &Logger,
    job_id: &JobId,
    dir: Option<&str>,
    stdio: SpawnStdio,
    args: &[String],
    env: &[(&str, OsString)],
) -> io::Result<JobChild> {
    let mut posix_spawn = PosixSpawn::new()?;
    if let Some(dir) = dir {
        posix_spawn.chdir(dir)?;
    }
    posix_spawn.stdio(stdio)?;
    let spawn = || posix_spawn.spawn(BASH, args, env);
    #[cfg(target_os = "illumos")]
    {
        let (child, ctid) = spawn_in_contract(job_id, spawn)?;
        debug!(log, "spawned job"; "ctid" => ctid);
        Ok(child.in_contract(ctid))
    }
    #[cfg(not(target_os = "illumos"))]
    {
        let _ = (log, job_id);
        spawn()
    }
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

#[derive(Debug, Clone, Copy)]
pub enum PathIsolation {
    Enable,
    InsecureDisable,
}
