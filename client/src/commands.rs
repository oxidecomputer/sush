//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _, stdin, stdout};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use async_recursion::async_recursion;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use libc::{FIONREAD, ioctl};
use thiserror::Error;
use tokio::select;
use tokio::signal::ctrl_c;

use sush_common::certs::{CertError, KeyId, Signer as _};
use sush_common::jobs::{JobId, JobStartRequest, JobStatus, JobsReserved, SignedJob};

use crate::permslip::PermslipError;
use crate::permslip::{DEFAULT_PERMSLIP_URL, PermslipSigner};
use crate::repl::Repl;
use crate::types::Error as ApiError;
use crate::{Client, Error as ClientError};

// Names of environment variables for argument defaults.
pub const PERMSLIP_URL: &str = "PERMSLIP_URL";
pub const SUSH_JOB_ID: &str = "SUSH_JOB_ID";
pub const SUSH_PERMSLIP_KEY: &str = "SUSH_PERMSLIP_KEY";
pub const SUSH_OUTPUT_FORMAT: &str = "SUSH_OUTPUT_FORMAT";
pub const SUSH_URL: &str = "SUSH_URL";

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

/// Optional global arguments.
#[derive(Clone, Debug, Parser)]
pub struct GlobalArgs {
    /// Output type
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
    pub async fn execute<C>(&mut self, ctx: &mut C) -> Result<(), CommandError>
    where
        C: CommandContext + Send + Sync,
    {
        self.command.clone().execute(&mut self.globals, ctx).await
    }
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
        /// The command for the job to run. Passed as an argument to
        /// `bash -c`, so may be an arbitrary bash(1) command or pipeline.
        /// Be sure to quote spaces and characters special to your shell!
        command: Option<String>,

        /// Previously reserved but unused job ID.
        #[clap(env = SUSH_JOB_ID)]
        job_id: Option<JobId>,

        /// Use `permslip` to sign requests with this key name.
        #[arg(short, long, env = SUSH_PERMSLIP_KEY, name = "KEY_NAME")]
        permslip: Option<String>,

        /// The `permslip` server to contact for signing.
        #[arg(long, env = PERMSLIP_URL, default_value = DEFAULT_PERMSLIP_URL)]
        permslip_url: String,

        /// Wait for the job to end and display its output.
        #[arg(short, long, default_value_t = false)]
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
    #[clap(alias = "stdout")]
    JobStdout {
        /// The job whose output should be fetched.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,

        /// Job output is binary, not UTF-8 encoded text.
        #[arg(short, long, default_value_t = false)]
        binary: bool,
    },

    /// Get the standard error of a job.
    #[clap(alias = "stderr")]
    JobStderr {
        /// The job whose error output should be fetched.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,

        /// Job error output is binary, not UTF-8 encoded text.
        #[arg(short, long, default_value_t = false)]
        binary: bool,
    },

    /// Abort a started job.
    #[clap(alias = "abort")]
    JobAbort {
        /// The job to abort.
        #[clap(env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Arguments for subsequent interactive commands.
    Set {
        #[clap(flatten)]
        args: GlobalArgs,
    },

    /// Start an interactive REPL.
    #[clap(alias = "repl")]
    Shell,
}

/// Behavior in response to command execution, e.g., printing output,
/// maintaining (ephemeral) state.
pub trait CommandContext {
    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);
    fn set_globals(&mut self, _args: &mut GlobalArgs, _values: GlobalArgs) {}
    fn pre_parse_hook(&mut self, _command: &str) {}

    fn ack(&mut self, reserved: JobsReserved) -> Result<(), CommandError>;
    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<(), CommandError>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError>;
    fn job_aborted(&mut self, id: JobId) -> Result<(), CommandError>;
    fn job_stdout(&mut self, id: JobId, output: &[u8], binary: bool) -> Result<(), CommandError>;
    fn job_stderr(&mut self, id: JobId, errors: &[u8], binary: bool) -> Result<(), CommandError>;
    fn job_status(&mut self, id: JobId, status: &JobStatus) -> Result<(), CommandError>;
    fn job_signed(&mut self, job: &SignedJob) -> Result<(), CommandError>;
    fn jobs_reserved(&mut self, reserved: &JobsReserved) -> Result<(), CommandError>;
    fn reserved_map(
        &mut self,
        reserved: &HashMap<String, DateTime<Utc>>,
    ) -> Result<(), CommandError>;
    fn revoked(&mut self, revoked: &[JobId]) -> Result<(), CommandError>;
}

impl ClientCommand {
    #[async_recursion]
    pub async fn execute<C>(self, args: &mut GlobalArgs, ctx: &mut C) -> Result<(), CommandError>
    where
        C: CommandContext + Send + Sync,
    {
        if let Some(output) = args.output {
            ctx.set_output_format(output);
        }
        let client = args.url.as_ref().map(|url| Client::new(url));
        match (self, client) {
            (ClientCommand::ImportCert { path }, Some(client)) => {
                let mut file = File::open(&path)?;
                let mut cert = Vec::new();
                file.read_to_end(&mut cert)?;
                let key_id = client.import_cert(&cert).await?.into_inner();
                ctx.cert_imported(&path, key_id)
            }
            (ClientCommand::CertChain { key_id }, Some(client)) => {
                let certs = client.cert_chain(&key_id).await?.into_inner();
                ctx.cert_chain(key_id, &certs)
            }
            (ClientCommand::Ping, Some(client)) => {
                let reserved = client.reserve_jobs(0).await?.into_inner();
                ctx.ack(reserved)
            }
            (ClientCommand::ReserveJobs { number }, Some(client)) => {
                let reserved = client.reserve_jobs(number).await?.into_inner();
                ctx.jobs_reserved(&reserved)
            }
            (ClientCommand::GetReserved, None) => match read_reserved()? {
                Reserved::Batch(reserved) => ctx.jobs_reserved(&reserved),
                Reserved::Map(map) => ctx.reserved_map(&map),
            },
            (ClientCommand::GetReserved, Some(client)) => {
                let map = client.get_reserved().await?.into_inner();
                ctx.reserved_map(&map)
            }
            (ClientCommand::RevokeReserved { job_ids }, Some(client)) => {
                let revoked = client.revoke_reserved(&job_ids).await?.into_inner();
                ctx.revoked(&revoked)
            }
            (
                ClientCommand::JobStart {
                    command: None,
                    permslip: None,
                    wait,
                    binary,
                    ..
                },
                Some(client),
            ) => {
                let job = read_signed_job()?;
                job_start(&client, ctx, job, wait, binary).await?;
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
                    wait,
                    binary,
                },
                client,
            ) => {
                let signer = PermslipSigner::new(key_name, &permslip_url).await?;
                let job = signer.sign(JobStartRequest::new(job_id, command)).await?;
                if let Some(client) = client {
                    job_start(&client, ctx, job, wait, binary).await?;
                } else {
                    ctx.job_signed(&job)?;
                }
                Ok(())
            }
            (ClientCommand::JobStatus { job_id }, Some(client)) => {
                let status = client.job_status(&job_id).await?.into_inner();
                ctx.job_status(job_id, &status)
            }
            (ClientCommand::JobStdout { job_id, binary }, Some(client)) => {
                let stdout = client.job_stdout(&job_id).await?.into_inner();
                ctx.job_stdout(job_id, &stdout, binary)
            }
            (ClientCommand::JobStderr { job_id, binary }, Some(client)) => {
                let stderr = client.job_stderr(&job_id).await?.into_inner();
                ctx.job_stderr(job_id, &stderr, binary)
            }
            (ClientCommand::JobAbort { job_id }, Some(client)) => {
                client.job_abort(&job_id).await?;
                ctx.job_aborted(job_id)
            }
            (ClientCommand::Set { args: values }, _) => {
                ctx.set_globals(args, values);
                Ok(())
            }
            (ClientCommand::Shell, _) => {
                Repl::default().run(args).await?;
                Ok(())
            }
            (_, None) => Err(CommandError::Offline),
        }
    }
}

async fn job_start<C>(
    client: &Client,
    ctx: &mut C,
    job: SignedJob,
    wait: bool,
    binary: bool,
) -> Result<(), CommandError>
where
    C: CommandContext + Send + Sync,
{
    let job_id = job.job_id();
    let status = select! {
        status = client.job_start(&job_id, wait, &job) => status?.into_inner(),
        _ = ctrl_c() => {
            client.job_abort(&job_id).await?;
            client.job_status(&job_id).await?.into_inner()
        }
    };
    ctx.job_status(job_id, &status)?;
    if wait {
        let stdout = client.job_stdout(&job_id).await?.into_inner();
        let stderr = client.job_stderr(&job_id).await?.into_inner();
        ctx.job_stdout(job_id, &stdout, binary)?;
        ctx.job_stderr(job_id, &stderr, binary)?;
    }
    Ok(())
}

/// Read stdin until EOF, prompting unless there's already input available.
fn read_input(prompt: &str) -> Result<String, CommandError> {
    let mut avail: i32 = 0;
    let rc = unsafe { ioctl(stdin().as_raw_fd(), FIONREAD, &mut avail) };
    if rc >= 0 && avail == 0 {
        stdout().write_all(prompt.as_bytes())?;
        stdout().flush()?;
    }

    let mut input = String::new();
    stdin().read_to_string(&mut input)?;
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
                .filter(|s| !s.is_empty())
                .map(|s| s.split_whitespace().next().unwrap_or(s).parse())
                .collect::<Result<Vec<JobId>, _>>()?,
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

/// What went wrong parsing, preparing, or executing a client command.
#[derive(Debug, Error)]
pub enum CommandError {
    #[error("❌ {0}")]
    Cert(#[from] CertError),
    #[error("🛈 {0}")]
    Clap(#[from] clap::Error),
    #[error("❌ {0}")]
    Client(String),
    #[error("❌ {0}")]
    Der(#[from] x509_cert::der::Error),
    #[error("❌ Empty certificate chain")]
    EmptyCertChain,
    #[error("❌ {0}")]
    Io(#[from] std::io::Error),
    #[error("❌ Leaf certificate does not match key `{0}`")]
    InvalidLeafCert(KeyId),
    #[error("❌ Unable to read reserved job IDs")]
    InvalidReservedJobs,
    #[error("❌ Root certificate is not self-signed")]
    InvalidRootCert,
    #[error("❌ JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("❌ Missing job command, try `--help`")]
    MissingCommand,
    #[error("❌ Missing job ID, try `reserve-jobs` or `get-reserved`")]
    MissingJobId,
    #[error("❌ Missing signing key name, try `--permslip`")]
    MissingKeyName,
    #[error("❌ Command not supported in offline mode, try `--url`")]
    Offline,
    #[error("❌ `permslip` error: {0}")]
    Permslip(#[from] PermslipError),
    #[error("❌ {0}")]
    Readline(#[from] rustyline::error::ReadlineError),
    #[error(transparent)]
    Recursive(#[from] Box<Self>),
    #[error("❌ UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("❌ UUID error: {0}")]
    Uuid(#[from] uuid::Error),
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
