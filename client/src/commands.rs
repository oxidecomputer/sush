//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _, stdin};
use std::num::{NonZeroU8, NonZeroU64};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::Duration;

use async_recursion::async_recursion;
use blake3::{Hasher, hash};
use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use futures::{FutureExt as _, StreamExt as _};
use futures::{TryStreamExt as _, stream};
use http::status::StatusCode;
use memmap2::Mmap;
use reqwest::Upgraded;
use rustix::termios::tcgetwinsize;
use thiserror::Error;
use tokio::signal::ctrl_c;
use tokio::time::{MissedTickBehavior, interval};
use tokio::{pin, select};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::error::Error as WebSocketError;
use tokio_tungstenite::tungstenite::protocol::Role;

use sush_common::authn::{AuthnError, Challenge, ChallengeResponse, Credentials, Identity};
use sush_common::jobs::JobOutputStream::{self, Stderr, Stdout};
use sush_common::jobs::{
    JobId, JobLimits, JobOutputHash, JobStartRequest, JobStatus, JobsReserved, SignedJob,
};
use sush_common::keys::{KeyError, KeyId, Signer as _, SshPublicKey};
use sush_common::session::SessionError;

use crate::ByteStream;
use crate::identity::{IdentityError, SshAgentConnection};
use crate::permslip::PermslipError;
use crate::permslip::{DEFAULT_PERMSLIP_URL, PermslipSigner};
use crate::repl::Repl;
use crate::session::session;
use crate::types::Error as ApiError;
use crate::{Client, Error as ClientError};

// Names of environment variables for argument defaults
// (to prevent mispellings).
pub const PERMSLIP_URL: &str = "PERMSLIP_URL";
pub const SSH_AUTH_SOCK: &str = "SSH_AUTH_SOCK";
pub const SUSH_JOB_ID: &str = "SUSH_JOB_ID";
pub const SUSH_KEY_ID: &str = "SUSH_KEY_ID";
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
    pub fn as_limits(&self) -> JobLimits {
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

    /// Offline mode, i.e., job signing only
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

    /// Identity and access management.
    #[clap(alias = "whoami")]
    Iam {
        #[clap(flatten)]
        identity_args: IdentityArgs,

        #[clap(subcommand)]
        command: Option<IdentityCommand>,

        /// Shortcut for `iam register --list-available`
        #[arg(short, long)]
        list_available: bool,

        /// Shortcut for `iam revoke <KEY_ID>`
        #[arg(short, long, name = "KEY_ID", conflicts_with = "list_available")]
        revoke: Option<KeyId>,
    },

    /// Reserve zero job slots and display the reservation time.
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
        start_args: JobStartArgs,

        #[clap(flatten)]
        identity_args: IdentityArgs,
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

        /// SSH identity to authenticate as.
        #[clap(flatten)]
        identity: IdentityArgs,
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

#[derive(Clone, Debug, Parser)]
pub struct IdentityArgs {
    /// Path to the SSH authentication agent Unix-domain socket.
    #[arg(long, env = SSH_AUTH_SOCK)]
    ssh_auth_sock: PathBuf,

    /// Authenticate as this SSH identity (try `iam -l` for a list).
    #[arg(short, long, env = SUSH_KEY_ID)]
    key_id: Option<KeyId>,
}

#[derive(Clone, Debug, Subcommand)]
pub enum IdentityCommand {
    /// List SSH identities registered with the server.
    List {
        /// The number of identities to include, or 0 for all.
        #[arg(short, long, default_value_t = 0)]
        limit: usize,
    },

    /// Register an SSH identity with the server.
    Register {
        /// List available (local) SSH agent identities,
        /// but do not register any.
        #[arg(short, long)]
        list_available: bool,
    },

    /// Revoke an SSH identity previously registered with the server.
    Revoke {
        /// The identity to revoke. Defaults to the current identity.
        revoke: Option<KeyId>,
    },
}

impl Default for IdentityCommand {
    fn default() -> Self {
        Self::Register {
            list_available: false,
        }
    }
}

#[derive(Clone, Debug, Parser)]
pub struct JobStartArgs {
    #[clap(flatten)]
    limits: LimitArgs,

    /// The command for the job to run. Passed as an argument to
    /// `bash -c`, so may be an arbitrary bash(1) command or pipeline.
    /// Be sure to quote spaces and characters special to your shell!
    command: Option<String>,

    /// Previously reserved but unused job ID.
    #[clap(env = SUSH_JOB_ID)]
    job_id: Option<JobId>,

    /// Job output is binary, not UTF-8 encoded text.
    #[arg(short, long, default_value_t = false, requires = "wait")]
    binary: bool,

    /// Run the job with a pseudoterminal and allow interactive sessions.
    #[arg(short, long, env = SUSH_KEY_ID, name = "KEY_ID")]
    interactive: bool,

    /// Use `permslip` to sign job requests with this key name.
    #[arg(short, long, env = SUSH_PERMSLIP_KEY, name = "KEY_NAME")]
    permslip: Option<String>,

    /// The `permslip` server to contact for signing.
    #[arg(long, env = PERMSLIP_URL, default_value = DEFAULT_PERMSLIP_URL)]
    permslip_url: String,

    /// Terminal type for interactive jobs.
    #[arg(long, env = "TERM")]
    term: Option<String>,

    /// Wait for the job to end and display its output.
    #[arg(short, long, default_value_if("interactive", "true", "true"))]
    wait: bool,
}

pub enum Reserved {
    Batch(JobsReserved),
    Map(HashMap<String, DateTime<Utc>>),
}

/// Behavior in response to command execution, e.g., printing output,
/// maintaining (ephemeral) state.
pub trait CommandContext: Send + Sync {
    // Context management
    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);
    fn set_globals(&mut self, _args: &mut GlobalArgs, _values: GlobalArgs) {}
    fn pre_parse_hook(&mut self, _command: &str) {}

    // Job signing certificates
    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<(), CommandError>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError>;

    // Job management
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
    fn job_session_connected(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_session_disconnected(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signing_started(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signing_update(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signing_finished(&mut self, id: &JobId) -> Result<(), CommandError>;
    fn job_signed(&mut self, job: &SignedJob) -> Result<(), CommandError>;
    fn job_status(&mut self, id: &JobId, status: &JobStatus) -> Result<(), CommandError>;

    // Job reservations
    fn ack(&mut self, url: &str, time: DateTime<Utc>) -> Result<(), CommandError>;
    fn jobs_reserved(&mut self, reserved: &JobsReserved) -> Result<(), CommandError>;
    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError>;
    fn read_reserved(&mut self) -> Result<Reserved, CommandError>;
    fn reserved_read(&mut self, reserved: &JobsReserved) -> Result<(), CommandError>;
    fn reserved_map(
        &mut self,
        reserved: &HashMap<String, DateTime<Utc>>,
    ) -> Result<(), CommandError>;
    fn revoked(&mut self, revoked: &[JobId]) -> Result<(), CommandError>;

    // SSH agent and identity
    fn iam(&mut self, identity: &Identity) -> Result<(), CommandError>;
    fn identities(&mut self, identities: &[SshPublicKey]) -> Result<(), CommandError>;
    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError>;
    fn really_revoke(&mut self, key_id: KeyId) -> Result<KeyId, CommandError>;
    fn identity_revoked(&mut self, key_id: KeyId) -> Result<(), CommandError>;
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

            (
                ClientCommand::Iam {
                    identity_args,
                    command,
                    list_available,
                    revoke,
                },
                Some(client),
            ) => {
                iam(
                    &client,
                    ctx,
                    identity_args,
                    command.unwrap_or_else(|| {
                        if revoke.is_some() {
                            IdentityCommand::Revoke { revoke }
                        } else {
                            IdentityCommand::Register { list_available }
                        }
                    }),
                )
                .await
            }

            (ClientCommand::Ping, Some(client)) => {
                let reserved = client.reserve_jobs().body(0).send().await?.into_inner();
                ctx.ack(&client.baseurl, reserved.time_reserved)
            }

            (ClientCommand::ReserveJobs { number: n }, Some(client)) => {
                let reserved = client.reserve_jobs().body(n).send().await?.into_inner();
                ctx.jobs_reserved(&reserved)
            }

            (ClientCommand::GetReserved, None) => match ctx.read_reserved()? {
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
                    start_args,
                    identity_args,
                },
                Some(client),
            ) if start_args.command.is_none() && start_args.permslip.is_none() => {
                let job = ctx.read_signed_job()?;
                job_start(&client, ctx, job, start_args, &identity_args).await?;
                Ok(())
            }

            (
                ClientCommand::JobStart {
                    start_args: JobStartArgs { command: None, .. },
                    ..
                },
                Some(_),
            ) => Err(CommandError::MissingCommand),

            (
                ClientCommand::JobStart {
                    start_args: JobStartArgs { permslip: None, .. },
                    ..
                },
                Some(_),
            ) => Err(CommandError::MissingKeyName),

            (
                ClientCommand::JobStart {
                    start_args: JobStartArgs { job_id: None, .. },
                    ..
                },
                _client,
            ) => Err(CommandError::MissingJobId),

            (
                ClientCommand::JobStart {
                    start_args:
                        ref start_args @ JobStartArgs {
                            command: Some(ref command),
                            job_id: Some(ref job_id),
                            permslip: Some(ref key_name),
                            ref permslip_url,
                            ref interactive,
                            ..
                        },
                    identity_args:
                        ref identity_args @ IdentityArgs {
                            ref ssh_auth_sock,
                            ref key_id,
                        },
                },
                client,
            ) => {
                let mut signer = PermslipSigner::new(key_name, permslip_url).await?;
                let mut interval = interval(Duration::from_millis(100));
                interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
                let sign = signer.sign(JobStartRequest::new(
                    job_id.to_owned(),
                    command,
                    if *interactive {
                        let mut agent = SshAgentConnection::connect(ssh_auth_sock).await?;
                        let public_key = agent.identity(key_id.as_ref()).await?;
                        Some(public_key.key_id()?)
                    } else {
                        None
                    },
                ));
                pin!(sign);
                ctx.job_signing_started(job_id)?;
                let job = loop {
                    select! {
                        job = &mut sign => {
                            ctx.job_signing_finished(job_id)?;
                            break job?;
                        }
                        _ = interval.tick() => ctx.job_signing_update(job_id)?,
                        _ = ctrl_c() => return ctx.job_signing_finished(job_id),
                    }
                };
                if let Some(client) = client {
                    job_start(&client, ctx, job, start_args.clone(), identity_args).await
                } else {
                    ctx.job_signed(&job)
                }
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

            (
                ClientCommand::JobSession {
                    job_id,
                    identity:
                        IdentityArgs {
                            ssh_auth_sock,
                            key_id,
                        },
                },
                Some(client),
            ) => {
                let mut agent = SshAgentConnection::connect(&ssh_auth_sock).await?;
                let (credentials, _public_key) = authn(&client, ctx, &mut agent, &key_id).await?;
                job_session(&client, ctx, &job_id, &credentials).await?;
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
    start_args: JobStartArgs,
    IdentityArgs {
        ssh_auth_sock,
        key_id,
    }: &IdentityArgs,
) -> Result<(), CommandError> {
    let interactive = job.interactive().cloned();
    let job_id = job.job_id().to_owned();
    let JobStartArgs {
        limits,
        binary,
        term,
        wait,
        ..
    } = start_args;
    let JobLimits {
        max_cpu,
        max_mem,
        max_fsize,
    } = limits.as_limits();
    let mut start = client
        .job_start()
        .job_id(&job_id)
        .max_cpu(max_cpu)
        .max_mem(max_mem)
        .max_fsize(max_fsize)
        .wait(wait && interactive.is_none())
        .body(job);
    let credentials = if let Some(interactive_key_id) = &interactive {
        if let Some(key_id) = key_id
            && key_id != interactive_key_id
        {
            return Err(CommandError::IdentityMismatch {
                interactive: interactive_key_id.to_owned(),
                key_id: key_id.to_owned(),
            });
        }
        let mut agent = SshAgentConnection::connect(ssh_auth_sock).await?;
        let (credentials, _public_key) = authn(client, ctx, &mut agent, &interactive).await?;
        start = start.authorization(credentials.to_string());
        Some(credentials)
    } else {
        None
    };
    if let Some(term) = term {
        start = start.term(term);
        if let Ok(winsize) = tcgetwinsize(stdin()) {
            start = start.rows(winsize.ws_row);
            start = start.cols(winsize.ws_col);
        }
    }
    let start = start.send();
    pin!(start);

    if let Some(credentials) = credentials {
        start.as_mut().await?;
        job_session(client, ctx, &job_id, &credentials).await?;
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

async fn iam(
    client: &Client,
    ctx: &mut impl CommandContext,
    args: IdentityArgs,
    command: IdentityCommand,
) -> Result<(), CommandError> {
    let IdentityArgs {
        ssh_auth_sock,
        key_id,
    } = &args;
    let mut agent = SshAgentConnection::connect(ssh_auth_sock).await?;
    match command {
        IdentityCommand::List { limit } => {
            let (credentials, _public_key) = authn(client, ctx, &mut agent, key_id).await?;
            let mut stream = client
                .identities()
                .authorization(credentials.to_string())
                .stream()
                .boxed();
            if limit > 0 {
                stream = stream.take(limit).boxed();
            }
            loop {
                match stream.try_next().await {
                    Ok(Some(identity)) => ctx.iam(&identity)?,
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
            }
        }

        IdentityCommand::Register {
            list_available: false,
        } => {
            let (credentials, public_key) = authn(client, ctx, &mut agent, key_id).await?;
            let identity = client
                .iam()
                .authorization(credentials.to_string())
                .body(public_key.to_string())
                .send()
                .await?
                .into_inner();
            ctx.iam(&identity)
        }

        IdentityCommand::Register {
            list_available: true,
        } => {
            let mut keys = Vec::new();
            for key in agent.list_identities().await? {
                if let Some(key_id) = key_id
                    && key.key_id()? != *key_id
                {
                    continue;
                }
                keys.push(key);
            }
            ctx.identities(&keys)
        }

        IdentityCommand::Revoke { revoke } => {
            let revoke = ctx.really_revoke(match revoke {
                Some(revoke) => revoke,
                None => agent.identity(key_id.as_ref()).await?.key_id()?,
            })?;
            let (credentials, _public_key) = authn(client, ctx, &mut agent, key_id).await?;
            client
                .revoke_identity()
                .authorization(credentials.to_string())
                .key_id(&revoke)
                .send()
                .await?;
            ctx.identity_revoked(revoke)
        }
    }
}

async fn authn(
    client: &Client,
    ctx: &mut impl CommandContext,
    agent: &mut SshAgentConnection,
    key_id: &Option<KeyId>,
) -> Result<(Credentials, SshPublicKey), CommandError> {
    let public_key = agent.identity(key_id.as_ref()).await?;
    let challenge: Challenge = match client.iam().body(None).send().await {
        Ok(_) => return Err(CommandError::InvalidAuthorization),
        Err(ClientError::ErrorResponse(err)) if err.status() == StatusCode::UNAUTHORIZED => err
            .headers()
            .get("www-authenticate")
            .ok_or(CommandError::InvalidAuthorization)?
            .to_str()
            .map_err(|_| CommandError::InvalidAuthorization)?
            .parse()?,
        Err(err) => return Err(err.into()),
    };

    let response = ChallengeResponse::new(challenge);
    ctx.please_touch(&public_key)?;
    let signed = select! {
        s = agent.sign(response) => s?,
        _ = ctrl_c() => return Err(CommandError::Canceled),
    };
    let verified = signed.verify_with_ssh_public_key(&public_key)?;
    let credentials = Credentials::new(verified);
    Ok((credentials, public_key))
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

/// Connect via WebSockets to a running interactive job,
/// providing authentication via an SSH agent.
async fn job_session(
    client: &Client,
    ctx: &mut impl CommandContext,
    job_id: &JobId,
    creds: &Credentials,
) -> Result<(), CommandError> {
    match client
        .job_session()
        .job_id(job_id)
        .authorization(creds.to_string())
        .send()
        .await
    {
        Err(error) => ctx.job_error(error.into()),
        Ok(socket) => {
            ctx.job_session_connected(job_id)?;
            let socket = socket.into_inner();
            let stream = WebSocketStream::from_raw_socket(socket, Role::Client, None).await;
            if let Err(error) = session(stream).await {
                return ctx.job_error(CommandError::from(error));
            }
            ctx.job_session_disconnected(job_id)
        }
    }
}

/// What went wrong parsing, preparing, or executing a client command.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("❌ Authentication error")]
    Authn(#[from] AuthnError),
    #[error("❌ Canceled")]
    Canceled,
    #[error("❌ Chunk size must be positive")]
    ChunkSizeZero,
    #[error("❓ {0}")]
    Clap(#[from] clap::Error),
    #[error("❌ {0}")]
    Client(String),
    #[error("❌ {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("❌ {0}")]
    DurationOutOfRange(#[from] chrono::OutOfRangeError),
    #[error("❌ Empty certificate chain")]
    EmptyCertChain,
    #[error("❌ Identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error(
        "❌ Identity mismatch,  tried to start an interactive job\n   \
            for `{interactive}`\n    \
             as `{key_id}`"
    )]
    IdentityMismatch { interactive: KeyId, key_id: KeyId },
    #[error("❌ I/O error accessing `{path}`: {error}")]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("❌ Authentication challenge malformed or missing")]
    InvalidAuthorization,
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
    #[error("❌ Key error: {0}")]
    Key(#[from] KeyError),
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
    #[error("❌ SSH signature error on key ID `{0}`")]
    Signature(KeyId),
    #[error("❌ SSH key error: {0}")]
    SshKey(#[from] kms_agent_lib::ssh_key::Error),
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
