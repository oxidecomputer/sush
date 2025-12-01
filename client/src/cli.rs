//! Possibly-interactive command-line interface.

use std::collections::HashMap;
use std::io::{Write as _, stderr, stdout};
use std::path::Path;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde_json::json;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::certs::{KeyId, Signature};
use sush_common::jobs::{JobId, JobStatus, JobsReserved};

use crate::commands::{CommandContext, OutputFormat};

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

    fn ack(&mut self, reserved: JobsReserved) -> Result<()> {
        assert!(reserved.job_ids.is_empty());
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => println!("✅ {}", reserved.time_reserved),
        }
        Ok(())
    }

    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<()> {
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

    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<()> {
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
    fn reserved_map(&mut self, reserved: &HashMap<String, DateTime<Utc>>) -> Result<()> {
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

    fn jobs_reserved(&mut self, number: u8, reserved: &JobsReserved) -> Result<()> {
        assert_eq!(reserved.job_ids.len(), number as usize);
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => {
                let n = reserved.job_ids.len();
                match n {
                    0 => println!("✅ No jobs reserved"),
                    1 => println!("✅ Reserved job ID: {}", reserved.job_ids[0]),
                    _ => {
                        println!("✅ Reserved job IDs:");
                        for job_id in &reserved.job_ids {
                            println!("{job_id}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn job_aborted(&mut self, job_id: JobId) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{job_id}"),
            OutputFormat::Text => println!("✅ Aborted job {job_id}"),
        }
        Ok(())
    }

    fn job_stdout(&mut self, job_id: JobId, output: &[u8], binary: bool) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json if binary => println!("{}", json!(output)),
            OutputFormat::Json => println!("{}", json!(String::from_utf8(output.to_vec())?)),
            OutputFormat::Text if binary => stdout().write(output).map(|_| ())?,
            OutputFormat::Text if output.is_empty() => (),
            OutputFormat::Text => {
                println!("✅ Job {job_id} stdout:");
                print!("{}", String::from_utf8(output.to_vec())?);
            }
        }
        Ok(())
    }

    fn job_stderr(&mut self, job_id: JobId, errors: &[u8], binary: bool) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json if binary => println!("{}", json!(errors)),
            OutputFormat::Json => println!("{}", json!(String::from_utf8(errors.to_vec())?)),
            OutputFormat::Text if binary => stderr().write(errors).map(|_| ())?,
            OutputFormat::Text if errors.is_empty() => (),
            OutputFormat::Text => {
                eprintln!("❌ Job {job_id} stderr:");
                eprint!("{}", String::from_utf8(errors.to_vec())?);
            }
        }
        Ok(())
    }

    fn job_status(&mut self, job_id: JobId, status: &JobStatus) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(status)),
            OutputFormat::Text => match status {
                JobStatus::NotFound => eprintln!("❌ Job {job_id} not found"),
                JobStatus::Reserved {
                    job_id,
                    time_reserved,
                } => println!("✅ Job {job_id} reserved at {time_reserved}"),
                JobStatus::Started { time_started, .. } => {
                    println!("✅ Job {job_id} started at {time_started}")
                }
                JobStatus::Ended {
                    time_ended,
                    status: Some(status),
                    stdout_len: 0,
                    stderr_len: 0,
                    ..
                } => println!(
                    "✅ Job {job_id} ended at {time_ended}\n   \
                     with status {status}, producing no output",
                ),
                JobStatus::Ended {
                    time_ended,
                    status: Some(status),
                    stdout_len,
                    stderr_len,
                    ..
                } => println!(
                    "✅ Job {job_id} ended at {time_ended}\n   \
                     with status {status}, producing {stdout_len} bytes on stdout \
                     and {stderr_len} bytes on stderr",
                ),
                JobStatus::Ended {
                    time_started,
                    time_ended,
                    status: None,
                    ..
                } => println!(
                    "✅ Job {job_id} started at {time_started}\n   \
                     and was aborted by a signal at {time_ended}",
                ),
            },
        }
        Ok(())
    }

    fn revoked(&mut self, revoked: &[JobId]) -> Result<()> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(revoked)),
            OutputFormat::Text => {
                let n = revoked.len();
                match n {
                    0 => println!("✅ No job IDs revoked"),
                    1 => println!("✅ Reserved job ID: {}", revoked[0]),
                    _ => {
                        println!("✅ Revoked job IDs:");
                        for job_id in revoked {
                            println!("{job_id}");
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
