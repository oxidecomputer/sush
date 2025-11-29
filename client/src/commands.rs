//! Support Shell commands.
//!
//! May be executed via either the main CLI or the interactive REPL.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read as _, Write as _, stdout};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use async_recursion::async_recursion;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::json;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::certs::{KeyId, Signature, Signer as _};
use sush_common::jobs::{JobId, JobStartRequest, JobStatus, JobsReserved};

use crate::Client;
use crate::permslip::{DEFAULT_PERMSLIP_URL, PermslipSigner};
use crate::repl::repl;

/// Default Support Shell HTTP API address.
const DEFAULT_SUSH_URL: &str = "http://127.0.0.1:44444";

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
        #[arg(short = 'i', long, env = "SUSH_JOB_ID")]
        job_id: JobId,

        /// Use `permslip` to sign requests with this key name.
        #[arg(short, long, name = "KEY_NAME")]
        permslip: String,

        /// The `permslip` server to contact for signing.
        #[arg(long, env = "PERMSLIP_URL", default_value = DEFAULT_PERMSLIP_URL)]
        permslip_url: String,

        /// If true, wait for the job to end before returning.
        #[arg(short, long)]
        wait: Option<bool>,

        /// The command for the job to run. Passed as an argument to
        /// `bash -c`, so may be an arbitrary bash(1) command or pipeline.
        /// Be sure to quote spaces and characters special to your shell!
        command: String,
    },

    /// Get the status of a started job.
    #[clap(alias = "status")]
    JobStatus {
        /// The job whose status should be fetched.
        #[arg(short = 'i', long, env = "SUSH_JOB_ID")]
        job_id: JobId,
    },

    /// Get the standard output of a job.
    #[clap(alias = "stdout")]
    JobStdout {
        /// The job whose output should be fetched.
        #[arg(short = 'i', long, env = "SUSH_JOB_ID")]
        job_id: JobId,

        /// Job output is binary, not UTF-8 encoded text.
        #[arg(short, long, default_value_t = false)]
        binary: bool,
    },

    /// Get the standard error of a job.
    #[clap(alias = "stderr")]
    JobStderr {
        /// The job whose error output should be fetched.
        #[arg(short = 'i', long, env = "SUSH_JOB_ID")]
        job_id: JobId,

        /// Job error output is binary, not UTF-8 encoded text.
        #[arg(short, long, default_value_t = false)]
        binary: bool,
    },

    /// Abort a started job.
    #[clap(alias = "abort")]
    JobAbort {
        /// The job to abort.
        #[arg(short = 'i', long, env = "SUSH_JOB_ID")]
        job_id: JobId,
    },

    /// Start an interactive REPL.
    #[clap(alias = "repl")]
    Shell,
}

pub trait CommandContext {
    fn get_output_format(&self) -> OutputFormat;
    fn set_output_format(&mut self, output: OutputFormat);

    fn ack(&self, reserved: JobsReserved) -> Result<()>;
    fn cert_chain(&self, key_id: KeyId, certs: String) -> Result<()>;
    fn cert_imported(&self, path: &Path, key_id: KeyId) -> Result<()>;
    fn job_aborted(&self, job_id: JobId) -> Result<()>;
    fn job_output(&self, output: Vec<u8>, binary: bool) -> Result<()>;
    fn job_status(&self, job_id: JobId, status: JobStatus) -> Result<()>;
    fn jobs_reserved(&self, number: u8, reserved: JobsReserved) -> Result<()>;
    fn reserved_map(&self, reserved: HashMap<String, DateTime<Utc>>) -> Result<()>;
    fn revoked(&self, nrevoked: u64) -> Result<()>;
}

/// Command-line interface.
#[derive(Clone, Debug, Default)]
pub struct Cli {
    output: OutputFormat,
}

impl Cli {
    pub fn new(output: OutputFormat) -> Self {
        Self { output }
    }
}

impl CommandContext for Cli {
    fn get_output_format(&self) -> OutputFormat {
        self.output
    }

    fn set_output_format(&mut self, output: OutputFormat) {
        self.output = output;
    }

    fn ack(&self, reserved: JobsReserved) -> Result<()> {
        assert!(reserved.job_ids.is_empty());
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => println!("✅ {}", reserved.time_reserved),
        }
        Ok(())
    }

    fn cert_chain(&self, key_id: KeyId, certs: String) -> Result<()> {
        let chain = Certificate::load_pem_chain(certs.as_bytes())?;
        let Some((root, rest)) = chain.split_first() else {
            bail!("empty certificate chain");
        };
        if root.tbs_certificate.subject != root.tbs_certificate.issuer {
            bail!("root certificate is not self-signed");
        }
        Signature::new(root.signature.raw_bytes().to_vec())
            .verify(&root.tbs_certificate.to_der()?, root)?;
        if matches!(self.get_output_format(), OutputFormat::Text) {
            println!(
                "✅ Verified root certificate for subject `{}`",
                root.tbs_certificate.subject
            );
        }

        let mut prev = root;
        for cert in rest {
            Signature::new(cert.signature.raw_bytes().to_vec())
                .verify(&cert.tbs_certificate.to_der()?, prev)?;
            prev = cert;
            if matches!(self.get_output_format(), OutputFormat::Text) {
                println!(
                    "✅ Verified certificate for subject `{}`",
                    cert.tbs_certificate.subject
                );
            }
        }
        if KeyId::try_from(prev)? != key_id {
            bail!("expected leaf certificate for key `{key_id}`");
        }

        if matches!(self.get_output_format(), OutputFormat::Json) {
            println!("{}", json!(certs));
        }
        Ok(())
    }

    fn cert_imported(&self, path: &Path, key_id: KeyId) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(key_id)),
            OutputFormat::Text => println!(
                "✅ Imported certificate for key ID `{}` from `{}`",
                key_id,
                path.display(),
            ),
        }
        Ok(())
    }

    #[allow(clippy::print_literal)]
    fn reserved_map(&self, reserved: HashMap<String, DateTime<Utc>>) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => {
                if reserved.is_empty() {
                    println!("✅ No reserved jobs");
                } else {
                    println!("✅ {} reserved jobs", reserved.len());
                    println!("{:40}{}", "Job ID", "Time Reserved");
                    for (job_id, time) in reserved {
                        println!("{job_id:40}{time}");
                    }
                }
            }
        }
        Ok(())
    }

    fn jobs_reserved(&self, number: u8, reserved: JobsReserved) -> Result<()> {
        assert_eq!(reserved.job_ids.len(), number as usize);
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => {
                if reserved.job_ids.len() == 1 {
                    println!("✅ Reserved job ID: {}", reserved.job_ids[0]);
                } else {
                    println!("✅ Reserved job IDs:");
                    for job_id in reserved.job_ids {
                        println!("{job_id}");
                    }
                }
            }
        }
        Ok(())
    }

    fn job_aborted(&self, job_id: JobId) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{job_id}"),
            OutputFormat::Text => println!("✅ Aborted job `{job_id}`"),
        }
        Ok(())
    }

    fn job_output(&self, output: Vec<u8>, binary: bool) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json if binary => println!("{}", json!(output)),
            OutputFormat::Text if binary => stdout().write(&output).map(|_| ())?,
            OutputFormat::Json => println!("{}", json!(String::from_utf8(output)?)),
            OutputFormat::Text => print!("{}", String::from_utf8(output)?),
        }
        Ok(())
    }

    fn job_status(&self, job_id: JobId, status: JobStatus) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(status)),
            OutputFormat::Text => match status {
                JobStatus::NotFound => println!("❌ Job `{job_id}` not found"),
                JobStatus::Reserved {
                    job_id,
                    time_reserved,
                } => println!("✅ Job `{job_id}` reserved at {time_reserved}"),
                JobStatus::Started { time_started, .. } => {
                    println!("✅ Job `{job_id}` started at {time_started}")
                }
                JobStatus::Ended {
                    time_ended,
                    status: Some(status),
                    stdout_len: 0,
                    stderr_len: 0,
                    ..
                } => println!(
                    "✅ Job `{job_id}` ended at {time_ended}\n\
                     with status {status}, producing no output",
                ),
                JobStatus::Ended {
                    time_ended,
                    status: Some(status),
                    stdout_len,
                    stderr_len,
                    ..
                } => println!(
                    "✅ Job `{job_id}` ended at {time_ended}\n\
                     with status {status}, producing {stdout_len} bytes on standard output \
                     and {stderr_len} bytes on standard error",
                ),
                JobStatus::Ended {
                    time_started,
                    time_ended,
                    status: None,
                    ..
                } => println!(
                    "✅ Job `{job_id}` started at {time_started} and\
                     was aborted by a signal at {time_ended}",
                ),
            },
        }
        Ok(())
    }

    fn revoked(&self, nrevoked: u64) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(nrevoked)),
            OutputFormat::Text => println!("✅ Revoked {nrevoked} job reservations"),
        }
        Ok(())
    }
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
                ctx.cert_chain(*key_id, client.cert_chain(key_id).await?.into_inner())
            }
            ClientCommand::Ping => ctx.ack(client.reserve_jobs(0).await?.into_inner()),
            ClientCommand::ReserveJobs { number } => {
                ctx.jobs_reserved(*number, client.reserve_jobs(*number).await?.into_inner())
            }
            ClientCommand::GetReserved => {
                ctx.reserved_map(client.get_reserved().await?.into_inner())
            }
            ClientCommand::RevokeReserved { job_ids } => {
                ctx.revoked(client.revoke_reserved(job_ids).await?.into_inner())
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
                ctx.job_status(*job_id, status)
            }
            ClientCommand::JobStatus { job_id } => {
                ctx.job_status(*job_id, client.job_status(job_id).await?.into_inner())
            }
            ClientCommand::JobStdout { job_id, binary } => {
                ctx.job_output(client.job_stdout(job_id).await?.into_inner(), *binary)
            }
            ClientCommand::JobStderr { job_id, binary } => {
                ctx.job_output(client.job_stderr(job_id).await?.into_inner(), *binary)
            }
            ClientCommand::JobAbort { job_id } => {
                client.job_abort(job_id).await?;
                ctx.job_aborted(*job_id)
            }
            ClientCommand::Shell => {
                repl(args).await?;
                Ok(())
            }
        }
    }
}
