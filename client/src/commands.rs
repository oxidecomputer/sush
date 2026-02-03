//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _, stdin, stdout};
use std::num::{NonZeroU8, NonZeroU64};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use async_recursion::async_recursion;
use blake3::{Hasher, hash};
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use futures::stream;
use futures::{FutureExt as _, StreamExt as _};
use http::status::StatusCode;
use libc::{FIONREAD, ioctl};
use memmap2::Mmap;
use reqwest::Upgraded;
use thiserror::Error;
use tokio::signal::ctrl_c;
use tokio::time::{MissedTickBehavior, interval};
use tokio::{pin, select};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::error::Error as WebSocketError;
use tokio_tungstenite::tungstenite::protocol::Role;

use sush_common::certs::{CertError, KeyId, Signer as _};
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobLimits, JobOutputHash, JobStartRequest, JobStatus, JobsReserved, SignedJob,
};
use sush_common::session::SessionError;

use crate::ByteStream;
use crate::permslip::PermslipError;
use crate::permslip::{DEFAULT_PERMSLIP_URL, PermslipSigner};
use crate::repl::Repl;
use crate::session::session;
use crate::types::Error as ApiError;
use crate::{Client, Error as ClientError};
use futures::TryStreamExt as _;

// Names of environment variables for argument defaults.
pub const PERMSLIP_URL: &str = "PERMSLIP_URL";
pub const SUSH_JOB_ID: &str = "SUSH_JOB_ID";
pub const SUSH_MAX_CPU: &str = "SUSH_MAX_CPU";
pub const SUSH_MAX_MEM: &str = "SUSH_MAX_MEM";
pub const SUSH_MAX_FSIZE: &str = "SUSH_MAX_FSIZE";
pub const SUSH_PERMSLIP_KEY: &str = "SUSH_PERMSLIP_KEY";
pub const SUSH_OUTPUT_FORMAT: &str = "SUSH_OUTPUT_FORMAT";
pub const SUSH_URL: &str = "SUSH_URL";

/// Default chunk size for parallel downloads of large output.
const DEFAULT_CHUNK_SIZE: ByteSize = ByteSize::mib(32);

/// Default number of simultaneous downloads for large output.
const PARALLEL_CHUNKS: NonZeroU8 = NonZeroU8::new(8).unwrap();

/// What kind of output to emit.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl OutputFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Process limits for job execution.
#[derive(Clone, Debug, Parser)]
pub struct LimitArgs {
    /// Maximum CPU use in seconds.
    #[arg(long, env = SUSH_MAX_CPU)]
    pub max_cpu: Option<u64>,

    /// Maximum size of address space in bytes.
    #[arg(long, env = SUSH_MAX_MEM)]
    pub max_mem: Option<u64>,

    /// Maximum file size in bytes.
    #[arg(long, env = SUSH_MAX_FSIZE)]
    pub max_fsize: Option<u64>,
}

impl LimitArgs {
    pub fn into_limits(self) -> JobLimits {
        let Self {
            max_cpu,
            max_mem,
            max_fsize,
        } = self;
        let defaults = JobLimits::default();
        JobLimits {
            max_cpu: max_cpu.unwrap_or(defaults.max_cpu),
            max_mem: max_mem.unwrap_or(defaults.max_mem),
            max_fsize: max_fsize.unwrap_or(defaults.max_fsize),
        }
    }
}

/// Optional global arguments, i.e., ones that apply to every command.
#[derive(Clone, Debug, Parser)]
pub struct GlobalArgs {
    /// Output format
    #[arg(long,
          env = SUSH_OUTPUT_FORMAT,
          default_value = "text",
          default_value_if("json", "true", "json"),
          default_value_if("text", "true", "text"),
          name = "FORMAT",
          value_enum)]
    #[clap(global = true)]
    pub output: Option<OutputFormat>,

    /// Shortcut for `--output=json`
    #[arg(short, long, default_value_t = false, conflicts_with = "text")]
    #[clap(global = true)]
    pub json: bool,

    /// Shortcut for `--output=text`
    #[arg(short, long, default_value_t = false, conflicts_with = "json")]
    #[clap(global = true)]
    pub text: bool,

    /// Support Shell HTTP API address for online mode
    #[arg(short, long, env = SUSH_URL)]
    #[clap(global = true)]
    pub url: Option<String>,

    /// Offline mode, i.e., signing only
    #[arg(long, default_value_t = false, conflicts_with = "url")]
    #[clap(global = true)]
    pub offline: bool,
}

#[derive(Debug, Parser)]
#[clap(name = "Oxide Support Shell")]
#[clap(author = "Oxide Computer Company")]
#[clap(about, version)]
pub struct ClientArgs {
    #[clap(flatten)]
    globals: GlobalArgs,

    #[clap(subcommand)]
    command: ClientCommand,
}

impl ClientArgs {
    pub async fn execute(&mut self, ctx: &mut impl CommandContext) -> Result<(), CommandError> {
        self.command.clone().execute(&mut self.globals, ctx).await
    }
}

/// Arguments for `job-stdout` and `job-stderr`.
#[derive(Clone, Debug, Parser)]
pub struct JobOutput {
    /// The job whose output should be fetched.
    #[clap(env = SUSH_JOB_ID)]
    job_id: JobId,

    /// Job output is binary, not UTF-8 encoded text.
    #[arg(short, long, default_value_t = false, conflicts_with = "file")]
    binary: bool,

    /// File that output should be written to.
    #[arg(short, long)]
    file: Option<PathBuf>,

    /// Overwrite output file if it exists.
    #[arg(long, requires = "file")]
    force: bool,

    /// Chunk size for parallel downloads of large output.
    #[arg(short, long, default_value_t = DEFAULT_CHUNK_SIZE, requires = "file")]
    chunk_size: ByteSize,

    /// Number of simultaneous downloads for large output [max: 255].
    #[arg(short, long, default_value_t = PARALLEL_CHUNKS, requires = "file")]
    parallel: NonZeroU8,

    /// Size to which output should be truncated *on the server*.
    ///
    /// WARNING: Destructive and irreversible! Subsequent downloads of this
    /// output will show a hash mismatch to warn that this has taken place.
    #[arg(long, conflicts_with = "file")]
    truncate: Option<ByteSize>,
}

/// Support Shell job management command
#[derive(Clone, Debug, Subcommand)]
pub enum ClientCommand {
    /// Import a certificate, verify its signature, and return a key ID for it.
    ImportCert { path: PathBuf },

    /// Get the certificate chain that validates a key, in root-to-leaf order.
    CertChain { key_id: KeyId },

    /// Reserve zero job slots and display the returned reservation time.
    Ping,

    /// Reserve some job slots with fresh, globally unique IDs.
    #[clap(alias = "reserve")]
    ReserveJobs {
        /// How many job slots to reserve.
        number: u8,
    },

    /// Get reserved but unused job slots.
    #[clap(alias = "reserved")]
    GetReserved,

    /// Revoke a set of reserved but unused job slots.
    #[clap(alias = "revoke")]
    RevokeReserved { job_ids: Vec<JobId> },

    /// Sign and start a job.
    #[clap(alias = "start")]
    JobStart {
        #[clap(flatten)]
        limits: LimitArgs,

        /// The command for the job to run. Passed as an argument to
        /// `bash -c`, so may be an arbitrary bash(1) command or pipeline.
        /// Be sure to quote spaces and characters special to your shell!
        command: Option<String>,

        /// Previously reserved but unused job ID.
        #[clap(env = SUSH_JOB_ID)]
        job_id: Option<JobId>,

        /// The job should be run interactively. Implies `--wait`.
        #[arg(short, long, default_value_t = false)]
        interactive: bool,

        /// Use `permslip` to sign requests with this key name.
        #[arg(short, long, env = SUSH_PERMSLIP_KEY, name = "KEY_NAME")]
        permslip: Option<String>,

        /// The `permslip` server to contact for signing.
        #[arg(long, env = PERMSLIP_URL, default_value = DEFAULT_PERMSLIP_URL)]
        permslip_url: String,

        /// Wait for the job to end and display its output.
        #[arg(short, long, default_value_if("interactive", "true", "true"))]
        wait: bool,

        /// Job output is binary, not UTF-8 encoded text.
        #[arg(short, long, default_value_t = false, requires = "wait")]
        binary: bool,
    },

    /// Get the status of a started job.
    #[clap(alias = "status")]
    JobStatus {
        /// The job whose status should be fetched.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Get the standard output of a job.
    #[clap(alias = "stdout", alias = "output")]
    JobStdout {
        #[clap(flatten)]
        output: JobOutput,
    },

    /// Get the standard error of a job.
    #[clap(alias = "stderr", alias = "error")]
    JobStderr {
        #[clap(flatten)]
        output: JobOutput,
    },

    /// Connect to a running interactive job.
    #[clap(alias = "session")]
    JobSession {
        /// The job to connect to.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Abort a running job.
    #[clap(alias = "abort")]
    JobAbort {
        /// The job to abort.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Show status of previously started jobs.
    History {
        /// How many history entries to fetch in total, or 0 for all.
        #[arg(short, long, default_value_t = 0)]
        limit: usize,
    },

    /// Arguments for subsequent interactive commands.
    Set {
        #[clap(flatten)]
        args: GlobalArgs,
    },

    /// Start an interactive REPL.
    #[clap(alias = "repl")]
    Shell,

    /// Leave the interactive REPL.
    #[clap(alias = "exit")]
    Quit,
}

/// Behavior in response to command execution, e.g., printing output,
/// maintaining (ephemeral) state.
pub trait CommandContext: Send + Sync {
    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);
    fn set_globals(&mut self, _args: &mut GlobalArgs, _values: GlobalArgs) {}
    fn pre_parse_hook(&mut self, _command: &str) {}

    fn ack(&mut self, url: &str, time: DateTime<Utc>) -> Result<(), CommandError>;
    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<(), CommandError>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError>;
    fn job_aborted(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_error(&mut self, error: CommandError) -> Result<(), CommandError>;
    fn job_output(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    ) -> Result<(), CommandError>;
    fn job_output_started(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total_length: u64,
    ) -> Result<(), CommandError>;
    fn job_output_update(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        bytes: u64,
    ) -> Result<(), CommandError>;
    fn job_output_finished(
        &mut self,
        id: &JobId,
        stream: JobOutputStream,
        stage: Option<&str>,
    ) -> Result<(), CommandError>;
    fn job_polling_started(&mut self, id: &JobId, duration: Duration) -> Result<(), CommandError>;
    fn job_polling_update(&mut self, id: &JobId, status: &JobStatus) -> Result<(), CommandError>;
    fn job_polling_finished(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_status(&mut self, id: &JobId, status: &JobStatus) -> Result<(), CommandError>;
    fn job_signed(&mut self, job: &SignedJob) -> Result<(), CommandError>;
    fn jobs_reserved(&mut self, reserved: &JobsReserved) -> Result<(), CommandError>;
    fn reserved_read(&mut self, reserved: &JobsReserved) -> Result<(), CommandError>;
    fn reserved_map(
        &mut self,
        reserved: &HashMap<String, DateTime<Utc>>,
    ) -> Result<(), CommandError>;
    fn revoked(&mut self, revoked: &[JobId]) -> Result<(), CommandError>;
}

impl ClientCommand {
    #[async_recursion]
    pub async fn execute(
        self,
        args: &mut GlobalArgs,
        ctx: &mut impl CommandContext,
    ) -> Result<(), CommandError> {
        if let Some(output) = args.output {
            ctx.set_output_format(output);
        }
        let client = args.url.as_ref().map(|url| Client::new(url));
        match (self, client) {
            (ClientCommand::ImportCert { path }, Some(client)) => {
                let io_error = |error| CommandError::io(&path, error);
                let mut file = File::open(&path).map_err(io_error)?;
                let mut cert = Vec::new();
                file.read_to_end(&mut cert).map_err(io_error)?;
                let key_id = client.import_cert().body(cert).send().await?.into_inner();
                ctx.cert_imported(&path, key_id)
            }
            (ClientCommand::CertChain { key_id }, Some(client)) => {
                let certs = client
                    .cert_chain()
                    .key_id(&key_id)
                    .send()
                    .await?
                    .into_inner();
                ctx.cert_chain(key_id, &certs)
            }
            (ClientCommand::Ping, Some(client)) => {
                let reserved = client.reserve_jobs().body(0).send().await?.into_inner();
                ctx.ack(&client.baseurl, reserved.time_reserved)
            }
            (ClientCommand::ReserveJobs { number: n }, Some(client)) => {
                let reserved = client.reserve_jobs().body(n).send().await?.into_inner();
                ctx.jobs_reserved(&reserved)
            }
            (ClientCommand::GetReserved, None) => match read_reserved()? {
                Reserved::Batch(reserved) => ctx.reserved_read(&reserved),
                Reserved::Map(map) => ctx.reserved_map(&map),
            },
            (ClientCommand::GetReserved, Some(client)) => {
                let map = client.get_reserved().send().await?.into_inner();
                ctx.reserved_map(&map)
            }
            (ClientCommand::RevokeReserved { job_ids }, Some(client)) => {
                let revoked = client
                    .revoke_reserved()
                    .body(job_ids)
                    .send()
                    .await?
                    .into_inner();
                ctx.revoked(&revoked)
            }
            (
                ClientCommand::JobStart {
                    command: None,
                    permslip: None,
                    wait,
                    binary,
                    limits,
                    ..
                },
                Some(client),
            ) => {
                let job = read_signed_job()?;
                job_start(&client, ctx, job, limits.into_limits(), wait, binary).await?;
                Ok(())
            }
            (ClientCommand::JobStart { command: None, .. }, Some(_)) => {
                Err(CommandError::MissingCommand)
            }
            (ClientCommand::JobStart { permslip: None, .. }, Some(_)) => {
                Err(CommandError::MissingKeyName)
            }
            (ClientCommand::JobStart { job_id: None, .. }, _client) => {
                Err(CommandError::MissingJobId)
            }
            (
                ClientCommand::JobStart {
                    command: Some(command),
                    job_id: Some(job_id),
                    permslip: Some(key_name),
                    permslip_url,
                    limits,
                    wait,
                    binary,
                    interactive,
                },
                client,
            ) => {
                let signer = PermslipSigner::new(key_name, &permslip_url).await?;
                let job = signer
                    .sign(JobStartRequest::new(job_id, command, interactive))
                    .await?;
                if let Some(client) = client {
                    job_start(&client, ctx, job, limits.into_limits(), wait, binary).await?;
                } else {
                    ctx.job_signed(&job)?;
                }
                Ok(())
            }
            (ClientCommand::JobStatus { job_id }, Some(client)) => {
                let status = client
                    .job_status()
                    .job_id(&job_id)
                    .send()
                    .await?
                    .into_inner();
                ctx.job_status(&job_id, &status)
            }
            (ClientCommand::JobStdout { output }, Some(client)) => {
                job_output(&client, ctx, Stdout, output).await
            }
            (ClientCommand::JobStderr { output }, Some(client)) => {
                job_output(&client, ctx, Stderr, output).await
            }
            (ClientCommand::JobSession { job_id }, Some(client)) => {
                job_session(&client, ctx, &job_id).await?;
                Ok(())
            }
            (ClientCommand::JobAbort { job_id }, Some(client)) => {
                client.job_abort().job_id(&job_id).send().await?;
                ctx.job_aborted(&job_id)
            }
            (ClientCommand::History { limit }, Some(client)) => {
                let mut stream = client.history().stream().boxed();
                if limit > 0 {
                    stream = stream.take(limit).boxed();
                }
                loop {
                    match stream.try_next().await {
                        Ok(Some(status)) => ctx.job_status(status.job_id(), &status)?,
                        Ok(None) => return Ok(()),
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            (ClientCommand::Set { args: values }, _) => {
                ctx.set_globals(args, values);
                Ok(())
            }
            (ClientCommand::Shell, client) => {
                Repl::default().run(args, client).await?;
                Ok(())
            }
            (ClientCommand::Quit, _) => Err(CommandError::Quit),
            (_, None) => Err(CommandError::Offline),
        }
    }
}

async fn job_start(
    client: &Client,
    ctx: &mut impl CommandContext,
    job: SignedJob,
    limits: JobLimits,
    wait: bool,
    binary: bool,
) -> Result<(), CommandError> {
    let interactive = job.is_interactive();
    let job_id = job.job_id().to_owned();
    let JobLimits {
        max_cpu,
        max_mem,
        max_fsize,
    } = limits;
    let start = client
        .job_start()
        .job_id(&job_id)
        .max_cpu(max_cpu)
        .max_mem(max_mem)
        .max_fsize(max_fsize)
        .wait(wait && !interactive)
        .body(job)
        .send();
    pin!(start);

    if interactive {
        start.as_mut().await?;
        job_session(client, ctx, &job_id).await?;
        let status = client
            .job_status()
            .job_id(&job_id)
            .send()
            .await?
            .into_inner();
        ctx.job_status(&job_id, &status)?;
        Ok(())
    } else {
        let mut interval = interval(Duration::from_millis(250));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let status = loop {
            select! {
                status = &mut start => {
                    ctx.job_polling_finished(&job_id)?;
                    break status?.into_inner();
                }
                _ = interval.tick() => {
                    let status = client.job_status().job_id(&job_id).send().await?.into_inner();
                    ctx.job_polling_started(&job_id, interval.period())?;
                    ctx.job_polling_update(&job_id, &status)?;
                }
                _ = ctrl_c() => {
                    client.job_abort().job_id(&job_id).send().await?;
                    ctx.job_polling_finished(&job_id)?;
                    ctx.job_aborted(&job_id)?;
                    break client.job_status().job_id(&job_id).send().await?.into_inner();
                }
            }
        };
        ctx.job_status(&job_id, &status)?;
        if wait {
            for stream in [Stdout, Stderr] {
                match client
                    .job_output()
                    .job_id(&job_id)
                    .stream(stream)
                    .send()
                    .await
                {
                    Ok(byte_stream) => {
                        let output = byte_stream_to_vec(byte_stream.into_inner()).await?;
                        ctx.job_output(&job_id, stream, &output, binary)?;
                    }
                    Err(error) => ctx.job_error(error.into())?,
                }
            }
        }
        Ok(())
    }
}

/// Read stdin until EOF, prompting unless there's already input available.
fn read_input(prompt: &str) -> Result<String, CommandError> {
    let mut avail: i32 = 0;
    let rc = unsafe { ioctl(stdin().as_raw_fd(), FIONREAD, &mut avail) };
    if rc >= 0 && avail == 0 {
        let io_error = |error| CommandError::io("stdout", error);
        stdout().write_all(prompt.as_bytes()).map_err(io_error)?;
        stdout().flush().map_err(io_error)?;
    }

    let io_error = |error| CommandError::io("stdin", error);
    let mut input = String::new();
    stdin().read_to_string(&mut input).map_err(io_error)?;
    Ok(input)
}

enum Reserved {
    Batch(JobsReserved),
    Map(HashMap<String, DateTime<Utc>>),
}

/// Read reserved job IDs from stdin, relayed from an online client.
fn read_reserved() -> Result<Reserved, CommandError> {
    let input = read_input("✅ Enter reserved job IDs, terminated with Ctrl-D:\n")?;
    if input.trim_start().starts_with('{') {
        if let Ok(jobs) = serde_json::from_str(&input) {
            Ok(Reserved::Batch(jobs))
        } else if let Ok(map) = serde_json::from_str(&input) {
            Ok(Reserved::Map(map))
        } else {
            Err(CommandError::InvalidReservedJobs)
        }
    } else {
        Ok(Reserved::Batch(JobsReserved {
            job_ids: input
                .split('\n')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(JobId::from)
                .collect::<Vec<JobId>>(),
            time_reserved: Utc::now(),
        }))
    }
}

/// Read a signed job request from stdin, relayed from an offline client
/// with signing authorization.
fn read_signed_job() -> Result<SignedJob, CommandError> {
    let input = read_input("✅ Enter signed job request, terminated with Ctrl-D:\n")?;
    Ok(serde_json::from_str(&input)?)
}

/// Stream some bytes into a vector.
async fn byte_stream_to_vec(mut stream: ByteStream) -> Result<Vec<u8>, CommandError> {
    let mut output = Vec::new();
    while let Some(bytes) = stream.next().await {
        output.extend(bytes?);
    }
    Ok(output)
}

/// Inclusive byte range for requesting job output.
#[derive(Debug)]
struct Range {
    start: u64,
    end: u64,
}

impl Range {
    fn bytes(&self) -> String {
        format!("bytes={}-{}", self.start, self.end)
    }

    fn len(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// Some bytes for a range of job output.
struct Chunk(Range, ByteStream);

/// A promise of some bytes for a range of output.
type FutureChunk<'a> = dyn Future<Output = Result<Chunk, CommandError>> + Send + 'a;

/// Download or truncate job output.
async fn job_output(
    client: &Client,
    ctx: &mut impl CommandContext,
    stream: JobOutputStream,
    JobOutput {
        job_id,
        binary,
        file,
        force,
        chunk_size,
        parallel,
        truncate,
    }: JobOutput,
) -> Result<(), CommandError> {
    // Maybe truncate instead of fetching output.
    if let Some(n) = truncate.map(|n| n.as_u64()) {
        client
            .job_output_delete()
            .job_id(job_id)
            .stream(stream)
            .range(format!("bytes={n}-"))
            .send()
            .await?;
        return Ok(());
    }

    // Fetch job status for output length and hash.
    let JobStatus::Ended {
        stdout_len,
        stderr_len,
        stdout_hash,
        stderr_hash,
        ..
    } = client
        .job_status()
        .job_id(&job_id)
        .send()
        .await?
        .into_inner()
    else {
        // TODO: emulate `tail -f` for running jobs
        return Err(CommandError::JobStillRunning(job_id.to_owned()));
    };
    let len = match stream {
        Stdout => stdout_len,
        Stderr => stderr_len,
    };
    let expected_hash = match stream {
        Stdout => stdout_hash,
        Stderr => stderr_hash,
    };

    macro_rules! check_hash {
        ($hash:expr, $stage:expr) => {{
            let expected = expected_hash;
            let received = $hash.into();
            if received == expected {
                ctx.job_output_finished(&job_id, stream, $stage)
            } else {
                let _ = ctx.job_output_finished(&job_id, stream, None);
                Err(CommandError::OutputHashMismatch { expected, received })
            }
        }};
    }

    if let Some(path) = file {
        // Save the output to a file, downloading in chunks.
        let Some(chunk_size) = NonZeroU64::new(chunk_size.as_u64()) else {
            return Err(CommandError::ChunkSizeZero);
        };

        // Open the output file.
        let io_error = |error| CommandError::io(&path, error);
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        if force {
            options.create(true).truncate(true);
        } else {
            options.create_new(true);
        }
        let mut file = options.open(&path).map_err(io_error)?;

        // Download and write the output in parallel (unordered) chunks.
        ctx.job_output_started(&job_id, stream, "Downloading", len)?;
        let chunks = job_output_chunks(client, &job_id, stream, len, chunk_size);
        let par = parallel.get() as usize;
        let mut chunks_par = stream::iter(chunks).buffer_unordered(par);
        while let Some(chunk) = chunks_par.next().await {
            let Chunk(range, bytes) = chunk?;
            ctx.job_output_update(&job_id, stream, range.len())?;
            byte_stream_to_file(&mut file, &path, bytes, range).await?;
        }
        file.flush().map_err(io_error)?;
        ctx.job_output_finished(&job_id, stream, Some("✅ Downloaded"))?;

        // Verify the output hash. Note that even if this verification fails,
        // we will leave the file as written. This provides a way of fetching
        // truncated outputs (with an error).
        let output = unsafe { Mmap::map(&file) }.map_err(io_error)?;
        if len < chunk_size.get() {
            check_hash!(hash(&output), None)
        } else {
            // Multi-threaded BLAKE3 is very, very fast, but still takes
            // perceptible time on multi-GB outputs. So if there's more
            // than one chunk, hash in chunks with a progress bar.
            ctx.job_output_started(&job_id, stream, "Verifying", len)?;
            let mut hasher = Hasher::new();
            for chunk in output.chunks(chunk_size.get() as usize) {
                hasher.update_rayon(chunk);
                ctx.job_output_update(&job_id, stream, chunk.len() as u64)?;
            }
            check_hash!(hasher.finalize(), Some("✅ Verified"))
        }
    } else {
        // Download and print the output all at once. If hash verification
        // fails here, do not print any output.
        let byte_stream = client
            .job_output()
            .job_id(&job_id)
            .stream(stream)
            .send()
            .await?
            .into_inner();
        let bytes = byte_stream_to_vec(byte_stream).await?;
        check_hash!(hash(&bytes), None)?;
        ctx.job_output(&job_id, stream, &bytes, binary)
    }
}

/// Prepare a vector of futures that fetch chunks of output.
fn job_output_chunks<'a>(
    client: &'a Client,
    job_id: &'a JobId,
    stream: JobOutputStream,
    len: u64,
    chunk_size: NonZeroU64,
) -> Vec<Pin<Box<FutureChunk<'a>>>> {
    let mut chunks = Vec::new();
    let mut start = 0;
    while start < len {
        let end = (start + chunk_size.get() - 1).min(len - 1);
        let range = Range { start, end };
        chunks.push(
            async move {
                let bytes = range.bytes();
                let stream = client
                    .job_output()
                    .job_id(job_id)
                    .stream(stream)
                    .range(&bytes)
                    .send()
                    .await?
                    .into_inner();
                Ok(Chunk(range, stream))
            }
            .boxed(),
        );
        start = end + 1;
    }
    chunks
}

/// Stream a range of bytes into an open file.
async fn byte_stream_to_file(
    file: &mut File,
    path: &Path,
    mut bytes: ByteStream,
    range: Range,
) -> Result<u64, CommandError> {
    let io_error = |error| CommandError::io(path, error);
    let Range { start, end: _ } = range;
    file.seek(SeekFrom::Start(start)).map_err(io_error)?;

    let mut n = 0;
    while let Some(bytes) = bytes.next().await {
        let bytes = bytes?;
        n += bytes.len() as u64;
        file.write_all(&bytes).map_err(io_error)?;
    }

    if n == range.len() {
        Ok(n)
    } else {
        Err(CommandError::LengthMismatch {
            expected: range.len(),
            received: n,
        })
    }
}

/// Connect via WebSockets to a running interactive job.
async fn job_session(
    client: &Client,
    ctx: &mut impl CommandContext,
    job_id: &JobId,
) -> Result<(), CommandError> {
    match client.job_session().job_id(job_id).send().await {
        Err(error) => ctx.job_error(error.into())?,
        Ok(socket) => {
            let socket = socket.into_inner();
            let stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
            if let Err(error) = session(stream).await {
                ctx.job_error(CommandError::from(error))?;
            }
        }
    }
    Ok(())
}

/// What went wrong parsing, preparing, or executing a client command.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("❌ {0}")]
    Cert(#[from] CertError),
    #[error("❌ Chunk size must be positive")]
    ChunkSizeZero,
    #[error("🛈 {0}")]
    Clap(#[from] clap::Error),
    #[error("❌ {0}")]
    Client(String),
    #[error("❌ {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("❌ {0}")]
    DurationOutOfRange(#[from] chrono::OutOfRangeError),
    #[error("❌ Empty certificate chain")]
    EmptyCertChain,
    #[error("❌ I/O error accessing `{path}`: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("❌ Leaf certificate does not match key `{0}`")]
    InvalidLeafCert(KeyId),
    #[error("❌ Unable to read reserved job IDs")]
    InvalidReservedJobs,
    #[error("❌ Root certificate is not self-signed")]
    InvalidRootCert,
    #[error("❌ Job `{0}` is still running")]
    JobStillRunning(JobId),
    #[error("❌ JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("❌ Length mismatch: expected {expected} bytes, received {received}")]
    LengthMismatch { expected: u64, received: u64 },
    #[error("❌ Missing job command, try `--help`")]
    MissingCommand,
    #[error("❌ Missing job ID, try `reserve-jobs` or `get-reserved`")]
    MissingJobId,
    #[error("❌ Missing signing key name, try `--permslip`")]
    MissingKeyName,
    #[error("❌ Command not supported in offline mode, try `--url`")]
    Offline,
    #[error(
        "❌ Hash mismatch, output may be truncated or corrupted\n   \
            Expected: {expected}\n   \
            Received: {received}"
    )]
    OutputHashMismatch {
        expected: JobOutputHash,
        received: JobOutputHash,
    },
    #[error("❌ permslip error: {0}")]
    Permslip(#[from] PermslipError),
    #[error("👋 Goodbye!")]
    Quit,
    #[error("❌ {0}")]
    Readline(#[from] rustyline::error::ReadlineError),
    #[error(transparent)]
    Recursive(#[from] Box<Self>),
    #[error("❌ Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("❌ Interactive session error: {0}")]
    Session(#[from] SessionError),
    #[error("❌ Too much output to display on terminal, try `--file`")]
    TooMuchOutput,
    #[error("❌ Can't start interactive session: {0}")]
    Upgrade(String),
    #[error("❌ UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("❌ WebSocket error: {0}")]
    WebSocket(#[from] WebSocketError),
}

impl CommandError {
    /// Report I/O errors with the corresponding path or stream name.
    pub fn io(path: impl AsRef<Path>, error: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_owned(),
            error,
        }
    }
}

impl From<ClientError<ApiError>> for CommandError {
    fn from(error: ClientError<ApiError>) -> Self {
        use ClientError::*;
        match error {
            InvalidRequest(e) => CommandError::Client(format!("Invalid request: {e}")),
            CommunicationError(e) => CommandError::Client(format!("Communication error: {e}")),
            InvalidUpgrade(e) => CommandError::Client(e.to_string()),
            ErrorResponse(e) => CommandError::Client(e.message.to_owned()),
            ResponseBodyError(e) => CommandError::Client(e.to_string()),
            InvalidResponsePayload(_b, e) => CommandError::Client(e.to_string()),
            UnexpectedResponse(e) if e.status().is_redirection() => {
                if let Some(l) = e.headers().get("location") {
                    CommandError::Client(format!(
                        "Got {} to {}",
                        e.status(),
                        l.to_str().unwrap_or("?")
                    ))
                } else {
                    CommandError::Client(format!("Got {}", e.status()))
                }
            }
            UnexpectedResponse(e) => CommandError::Client(format!("Unexpected response: {e:?}")),
            Custom(e) => CommandError::Client(e.to_string()),
        }
    }
}

impl From<ClientError<ByteStream>> for CommandError {
    fn from(error: ClientError<ByteStream>) -> Self {
        match error.status() {
            Some(StatusCode::PAYLOAD_TOO_LARGE) => Self::TooMuchOutput,
            Some(status) => Self::Client(status.to_string()),
            None => Self::Client(error.to_string()),
        }
    }
}

impl From<ClientError<Upgraded>> for CommandError {
    fn from(error: ClientError<Upgraded>) -> Self {
        match error.status() {
            Some(status) => Self::Client(status.to_string()),
            None => Self::Client(error.to_string()),
        }
    }
}
