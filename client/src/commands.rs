//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use async_recursion::async_recursion;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};

use sush_common::certs::{KeyId, Signer as _};
use sush_common::jobs::{JobId, JobStartRequest, JobStatus, JobsReserved};

use crate::Client;
use crate::permslip::{DEFAULT_PERMSLIP_URL, PermslipSigner};
use crate::repl::Repl;

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
    pub async fn execute<C>(&self, ctx: &mut C) -> Result<()>
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
    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);
    fn pre_parse_hook(&mut self, _command: &str) {}

    fn ack(&mut self, reserved: JobsReserved) -> Result<()>;
    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<()>;
    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<()>;
    fn job_aborted(&mut self, job_id: JobId) -> Result<()>;
    fn job_stdout(&mut self, job_id: JobId, output: &[u8], binary: bool) -> Result<()>;
    fn job_stderr(&mut self, job_id: JobId, errors: &[u8], binary: bool) -> Result<()>;
    fn job_status(&mut self, job_id: JobId, status: &JobStatus) -> Result<()>;
    fn jobs_reserved(&mut self, number: u8, reserved: &JobsReserved) -> Result<()>;
    fn reserved_map(&mut self, reserved: &HashMap<String, DateTime<Utc>>) -> Result<()>;
    fn revoked(&mut self, revoked: &[JobId]) -> Result<()>;
}

impl ClientCommand {
    #[async_recursion]
    pub async fn execute<C>(&self, args: &ClientArgs, ctx: &mut C) -> Result<()>
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
                ctx.cert_imported(path, client.import_cert(&cert).await?.into_inner())
            }
            ClientCommand::CertChain { key_id } => {
                ctx.cert_chain(*key_id, &client.cert_chain(key_id).await?.into_inner())
            }
            ClientCommand::Ping => ctx.ack(client.reserve_jobs(0).await?.into_inner()),
            ClientCommand::ReserveJobs { number } => {
                ctx.jobs_reserved(*number, &client.reserve_jobs(*number).await?.into_inner())
            }
            ClientCommand::GetReserved => {
                ctx.reserved_map(&client.get_reserved().await?.into_inner())
            }
            ClientCommand::RevokeReserved { job_ids } => {
                ctx.revoked(&client.revoke_reserved(job_ids).await?.into_inner())
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
                let status = client.job_start(job_id, *wait, &job).await?.into_inner();
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
                ctx.job_status(*job_id, &client.job_status(job_id).await?.into_inner())
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
