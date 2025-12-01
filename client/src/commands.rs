//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use async_recursion::async_recursion;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::select;
use tokio::signal::ctrl_c;

use sush_common::certs::{KeyId, Signer as _};
use sush_common::jobs::{JobId, JobStartRequest, JobStatus, JobsReserved};

use crate::Client;
use crate::Error as ClientError;
use crate::cli::CliError;
use crate::permslip::{DEFAULT_PERMSLIP_URL, PermslipError, PermslipSigner};
use crate::repl::Repl;
use crate::types::Error as ApiError;

/// Default Support Shell HTTP API address.
const DEFAULT_SUSH_URL: &str = "http://127.0.0.1:44444";

/// The name of the job ID environment variable.
pub const SUSH_JOB_ID: &str = "SUSH_JOB_ID";

/// What kind of output to emit.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[clap(name = "Oxide Support Shell")]
#[clap(author = "Oxide Computer Company")]
#[clap(about, version)]
pub struct ClientArgs {
    /// Output type.
    #[arg(short,
          long,
          default_value_t = OutputFormat::Text,
          default_value_if("json", "true", "json"),
          value_enum)]
    #[clap(global = true)]
    output: OutputFormat,

    /// Alias for `--output=json`
    #[arg(short, long, default_value_t = false)]
    #[clap(global = true)]
    json: bool,

    /// Support Shell HTTP API address
    #[arg(short, long, default_value = DEFAULT_SUSH_URL, env = "SUSH_URL")]
    #[clap(global = true)]
    url: String,

    /// Support shell job management command
    #[clap(subcommand)]
    command: ClientCommand,
}

impl ClientArgs {
    pub async fn execute<C>(&self, ctx: &mut C) -> Result<(), C::Error>
    where
        C: CommandContext + Send + Sync,
    {
        self.command.execute(self, ctx).await
    }
}

#[derive(Debug, Subcommand)]
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
        /// Previously reserved but unused job ID.
        #[arg(short = 'i', long, env = SUSH_JOB_ID)]
        job_id: JobId,

        /// Use `permslip` to sign requests with this key name.
        #[arg(short, long, env = "SUSH_PERMSLIP_KEY", name = "KEY_NAME")]
        permslip: String,

        /// The `permslip` server to contact for signing.
        #[arg(long, env = "PERMSLIP_URL", default_value = DEFAULT_PERMSLIP_URL)]
        permslip_url: String,

        /// If true, wait for the job to end before returning.
        #[arg(short, long, default_value_t = false)]
        wait: bool,

        /// The command for the job to run. Passed as an argument to
        /// `bash -c`, so may be an arbitrary bash(1) command or pipeline.
        /// Be sure to quote spaces and characters special to your shell!
        command: String,
    },

    /// Get the status of a started job.
    #[clap(alias = "status")]
    JobStatus {
        /// The job whose status should be fetched.
        #[arg(short = 'i', long, env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Get the standard output of a job.
    #[clap(alias = "stdout")]
    JobStdout {
        /// The job whose output should be fetched.
        #[arg(short = 'i', long, env = SUSH_JOB_ID)]
        job_id: JobId,

        /// Job output is binary, not UTF-8 encoded text.
        #[arg(short, long, default_value_t = false)]
        binary: bool,
    },

    /// Get the standard error of a job.
    #[clap(alias = "stderr")]
    JobStderr {
        /// The job whose error output should be fetched.
        #[arg(short = 'i', long, env = SUSH_JOB_ID)]
        job_id: JobId,

        /// Job error output is binary, not UTF-8 encoded text.
        #[arg(short, long, default_value_t = false)]
        binary: bool,
    },

    /// Abort a started job.
    #[clap(alias = "abort")]
    JobAbort {
        /// The job to abort.
        #[arg(short = 'i', long, env = SUSH_JOB_ID)]
        job_id: JobId,
    },

    /// Start an interactive REPL.
    #[clap(alias = "repl")]
    Shell,
}

pub trait CommandContext {
    type Error: From<CliError>
        + From<clap::Error>
        + From<ClientError<ApiError>>
        + From<std::io::Error>
        + From<PermslipError>;

    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);
    fn pre_parse_hook(&mut self, _command: &str) {}

    fn ack(&mut self, reserved: JobsReserved) -> Result<(), Self::Error>;
    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<(), Self::Error>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), Self::Error>;
    fn job_aborted(&mut self, id: JobId) -> Result<(), Self::Error>;
    fn job_stdout(&mut self, id: JobId, output: &[u8], binary: bool) -> Result<(), Self::Error>;
    fn job_stderr(&mut self, id: JobId, errors: &[u8], binary: bool) -> Result<(), Self::Error>;
    fn job_status(&mut self, id: JobId, status: &JobStatus) -> Result<(), Self::Error>;
    fn jobs_reserved(&mut self, reserved: &JobsReserved) -> Result<(), Self::Error>;
    fn reserved_map(
        &mut self,
        reserved: &HashMap<String, DateTime<Utc>>,
    ) -> Result<(), Self::Error>;
    fn revoked(&mut self, revoked: &[JobId]) -> Result<(), Self::Error>;
}

impl ClientCommand {
    #[async_recursion]
    pub async fn execute<C>(&self, args: &ClientArgs, ctx: &mut C) -> Result<(), C::Error>
    where
        C: CommandContext + Send + Sync,
    {
        ctx.set_output_format(args.output);
        let client = Client::new(&args.url);
        match self {
            ClientCommand::ImportCert { path } => {
                let mut file = File::open(path)?;
                let mut cert = Vec::new();
                file.read_to_end(&mut cert)?;
                let key_id = client.import_cert(&cert).await?.into_inner();
                ctx.cert_imported(path, key_id)
            }
            ClientCommand::CertChain { key_id } => {
                let certs = client.cert_chain(key_id).await?.into_inner();
                ctx.cert_chain(*key_id, &certs)
            }
            ClientCommand::Ping => {
                let reserved = client.reserve_jobs(0).await?.into_inner();
                ctx.ack(reserved)
            }
            ClientCommand::ReserveJobs { number } => {
                let reserved = client.reserve_jobs(*number).await?.into_inner();
                ctx.jobs_reserved(&reserved)
            }
            ClientCommand::GetReserved => {
                let map = client.get_reserved().await?.into_inner();
                ctx.reserved_map(&map)
            }
            ClientCommand::RevokeReserved { job_ids } => {
                let revoked = client.revoke_reserved(job_ids).await?.into_inner();
                ctx.revoked(&revoked)
            }
            ClientCommand::JobStart {
                job_id,
                permslip,
                permslip_url,
                wait,
                command,
            } => {
                let signer = PermslipSigner::new(permslip, permslip_url).await?;
                let job = signer.sign(JobStartRequest::new(*job_id, command)).await?;
                let status = select! {
                    status = client.job_start(job_id, *wait, &job) => status?.into_inner(),
                    _ = ctrl_c() => {
                        client.job_abort(job_id).await?;
                        client.job_status(job_id).await?.into_inner()
                    }
                };
                ctx.job_status(*job_id, &status)?;
                if *wait {
                    let stdout = client.job_stdout(job_id).await?.into_inner();
                    let stderr = client.job_stderr(job_id).await?.into_inner();
                    ctx.job_stdout(*job_id, &stdout, false)?;
                    ctx.job_stderr(*job_id, &stderr, false)?;
                }
                Ok(())
            }
            ClientCommand::JobStatus { job_id } => {
                let status = client.job_status(job_id).await?.into_inner();
                ctx.job_status(*job_id, &status)
            }
            ClientCommand::JobStdout { job_id, binary } => {
                let stdout = client.job_stdout(job_id).await?.into_inner();
                ctx.job_stdout(*job_id, &stdout, *binary)
            }
            ClientCommand::JobStderr { job_id, binary } => {
                let stderr = client.job_stderr(job_id).await?.into_inner();
                ctx.job_stderr(*job_id, &stderr, *binary)
            }
            ClientCommand::JobAbort { job_id } => {
                client.job_abort(job_id).await?;
                ctx.job_aborted(*job_id)
            }
            ClientCommand::Shell => {
                Repl::default().run(args).await?;
                Ok(())
            }
        }
    }
}
