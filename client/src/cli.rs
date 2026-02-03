//! Possibly-interactive command-line interface.

use std::collections::HashMap;
use std::io::{Write as _, stdout};
use std::path::Path;
use std::time::Duration;

use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use humantime::format_duration;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::certs::{KeyId, Signature};
use sush_common::jobs::{JobId, JobOutputStream, JobStatus, JobsReserved, SignedJob};

use crate::commands::{CommandContext, CommandError, GlobalArgs, OutputFormat};

#[derive(Debug, Default)]
pub struct Cli {
    output: OutputFormat,
    progress: Option<ProgressBar>,
}

impl Cli {
    pub fn new(output: OutputFormat) -> Self {
        Self {
            output,
            progress: None,
        }
    }
}

fn byte_size(len: u64) -> bytesize::Display {
    ByteSize::b(len).display().si()
}

impl CommandContext for Cli {
    fn get_output_format(&self) -> OutputFormat {
        self.output
    }

    fn set_output_format(&mut self, output: OutputFormat) {
        self.output = output;
    }

    fn set_globals(&mut self, _args: &mut GlobalArgs, values: GlobalArgs) {
        match self.get_output_format() {
            OutputFormat::Json => {
                let GlobalArgs { output, url, .. } = values;
                let output = output.map(|o| o.as_str());
                println!("{}", json!({"output": output, "url": url}))
            }
            OutputFormat::Text => println!("❌ `set` is most useful interactively, try `shell`"),
        }
    }

    fn ack(&mut self, url: &str, time: DateTime<Utc>) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({url: time})),
            OutputFormat::Text => println!("✅ `{}` reports time {}", url, time),
        }
        Ok(())
    }

    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<(), CommandError> {
        let chain = Certificate::load_pem_chain(certs.as_bytes())?;
        let Some((root, rest)) = chain.split_first() else {
            return Err(CommandError::EmptyCertChain);
        };
        if root.tbs_certificate.subject != root.tbs_certificate.issuer {
            return Err(CommandError::InvalidRootCert);
        }
        let tbs = root.tbs_certificate.to_der()?;
        Signature::try_from(root)?.verify(&tbs, &root.tbs_certificate.subject_public_key_info)?;
        if matches!(self.get_output_format(), OutputFormat::Text) {
            println!(
                "✅ Verified root certificate for subject `{}`",
                root.tbs_certificate.subject
            );
        }

        let mut prev = root;
        for cert in rest {
            let tbs = cert.tbs_certificate.to_der()?;
            Signature::try_from(cert)?
                .verify(&tbs, &prev.tbs_certificate.subject_public_key_info)?;
            prev = cert;
            if matches!(self.get_output_format(), OutputFormat::Text) {
                println!(
                    "✅ Verified certificate for subject `{}`",
                    cert.tbs_certificate.subject
                );
            }
        }
        if KeyId::try_from(prev)? != key_id {
            return Err(CommandError::InvalidLeafCert(key_id));
        }

        if matches!(self.get_output_format(), OutputFormat::Json) {
            println!("{}", json!(certs));
        }
        Ok(())
    }

    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError> {
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
    fn reserved_map(
        &mut self,
        reserved: &HashMap<String, DateTime<Utc>>,
    ) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => {
                if reserved.is_empty() {
                    println!("✅ No reserved jobs");
                } else {
                    println!("✅ {} reserved jobs:", reserved.len());
                    for job_id in reserved.keys() {
                        println!("{job_id}");
                    }
                }
            }
        }
        Ok(())
    }

    fn reserved_read(&mut self, reserved: &JobsReserved) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => {
                println!("✅ Read {} reserved jobs", reserved.job_ids.len());
            }
        }
        Ok(())
    }

    fn jobs_reserved(&mut self, reserved: &JobsReserved) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(reserved)),
            OutputFormat::Text => {
                let JobsReserved {
                    job_ids,
                    time_reserved,
                } = reserved;
                let n = job_ids.len();
                match n {
                    0 => println!("✅ No jobs reserved"),
                    1 => println!("✅ Reserved job `{}` at {}", job_ids[0], time_reserved),
                    _ => {
                        println!("✅ Reserved {n} jobs at {time_reserved}:");
                        for job_id in &reserved.job_ids {
                            println!("{job_id}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn job_aborted(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{job_id}"),
            OutputFormat::Text => println!("✅ Aborted job `{job_id}`"),
        }
        Ok(())
    }

    fn job_error(&mut self, error: CommandError) -> Result<(), CommandError> {
        eprintln!("{error}");
        Ok(())
    }

    fn job_output(
        &mut self,
        _job_id: &JobId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    ) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json if binary => println!("{}", json!(output)),
            OutputFormat::Json => println!("{}", json!(String::from_utf8(output.to_vec())?)),
            OutputFormat::Text if binary => {
                stdout()
                    .write(output)
                    .map_err(|error| CommandError::io("stdout", error))?;
            }
            OutputFormat::Text if output.is_empty() => (),
            OutputFormat::Text => {
                match stream {
                    JobOutputStream::Stdout => println!("✅ Job stdout:"),
                    JobOutputStream::Stderr => println!("✅ Job stderr:"),
                };
                let output = String::from_utf8(output.to_vec())?;
                if output.ends_with('\n') {
                    print!("{output}");
                } else {
                    println!("{output}");
                }
            }
        }
        Ok(())
    }

    fn job_output_started(
        &mut self,
        _id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total_length: u64,
    ) -> Result<(), CommandError> {
        if self.progress.is_none() {
            let bar = ProgressBar::new(total_length);
            bar.set_prefix(format!("{stage} {stream}"));
            bar.set_style(
                ProgressStyle::with_template(
                    "{prefix} \
                     [{elapsed_precise}] \
                     {bar:40.cyan/blue} \
                     {decimal_bytes:>7}/{decimal_total_bytes:7} \
                     {msg}",
                )
                .unwrap(),
            );
            self.progress = Some(bar);
        }
        Ok(())
    }

    fn job_output_update(
        &mut self,
        _id: &JobId,
        _stream: JobOutputStream,
        length: u64,
    ) -> Result<(), CommandError> {
        if let Some(progress) = &mut self.progress {
            progress.inc(length);
        }
        Ok(())
    }

    fn job_output_finished(
        &mut self,
        _job_id: &JobId,
        stream: JobOutputStream,
        stage: Option<&str>,
    ) -> Result<(), CommandError> {
        if let Some(progress) = self.progress.take() {
            progress.finish_and_clear();
            if let Some(stage) = stage {
                let length = ByteSize::b(progress.length().unwrap_or(0));
                let elapsed = progress.elapsed();
                println!(
                    "{stage} {stream}:\t{} in {} ({:.0} MB/s)",
                    length.display().si(),
                    format_duration(progress.elapsed()),
                    length.as_mb() / elapsed.as_secs_f64(),
                );
            }
        }
        Ok(())
    }

    fn job_polling_started(
        &mut self,
        job_id: &JobId,
        elapsed: Duration,
    ) -> Result<(), CommandError> {
        if self.progress.is_none() {
            let bar = ProgressBar::new_spinner();
            bar.set_elapsed(elapsed);
            bar.set_prefix(format!("Waiting for `{job_id}`"));
            bar.set_style(
                ProgressStyle::with_template(
                    "{spinner}  \
                     {prefix} \
                     [{elapsed_precise}] \
                     {msg}",
                )
                .unwrap(),
            );
            self.progress = Some(bar);
        }
        Ok(())
    }

    fn job_polling_update(
        &mut self,
        _job_id: &JobId,
        status: &JobStatus,
    ) -> Result<(), CommandError> {
        if let Some(progress) = &mut self.progress {
            if let JobStatus::Started {
                stdout_len,
                stderr_len,
                ..
            }
            | JobStatus::Ended {
                stdout_len,
                stderr_len,
                ..
            } = status
            {
                let stdout_len = byte_size(*stdout_len);
                let stderr_len = byte_size(*stderr_len);
                progress.set_message(format!("stdout: {stdout_len}, stderr: {stderr_len}"));
            }
            progress.tick();
        }
        Ok(())
    }

    fn job_polling_finished(&mut self, _job_id: &JobId) -> Result<(), CommandError> {
        if let Some(progress) = self.progress.take() {
            progress.finish_and_clear();
        }
        Ok(())
    }

    fn job_session_connected(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => {
                println!("{}", json!({"connected": job_id}));
            }
            OutputFormat::Text => {
                println!("✅ Connected to interactive job `{job_id}`");
            }
        }
        Ok(())
    }

    fn job_session_disconnected(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => {
                println!("{}", json!({"disconnected": job_id}));
            }
            OutputFormat::Text => {
                println!("\r✅ Disconnected interactive job `{job_id}`");
            }
        }
        Ok(())
    }

    fn job_status(&mut self, job_id: &JobId, status: &JobStatus) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(status)),
            OutputFormat::Text => match status {
                JobStatus::Reserved {
                    job_id,
                    time_reserved,
                } => println!(
                    "✅ Job ID:\t{job_id}\n   \
                     Job status:\tReserved\n   \
                     Reserved at:\t{time_reserved}"
                ),
                JobStatus::Started {
                    time_reserved,
                    time_started,
                    stdout_len,
                    stderr_len,
                    ..
                } => {
                    let stdout_len = byte_size(*stdout_len);
                    let stderr_len = byte_size(*stderr_len);
                    println!(
                        "✅ Job ID:\t{job_id}\n   \
                         Job status:\tStarted\n   \
                         Reserved at:\t{time_reserved}\n   \
                         Started at:\t{time_started}\n   \
                         Stdout len:\t{stdout_len}\n   \
                         Stderr len:\t{stderr_len}"
                    )
                }
                JobStatus::Ended {
                    job: _,
                    time_reserved,
                    time_started,
                    time_ended,
                    status: Some(exit_status),
                    stdout_len,
                    stderr_len,
                    stdout_hash,
                    stderr_hash,
                } => {
                    let duration = format_duration(status.time_elapsed().unwrap().to_std()?);
                    let stdout_len = byte_size(*stdout_len);
                    let stderr_len = byte_size(*stderr_len);
                    println!(
                        "✅ Job ID:\t{job_id}\n   \
                         Job status:\tEnded\n   \
                         Reserved at:\t{time_reserved}\n   \
                         Started at:\t{time_started}\n   \
                         Ended at:\t{time_ended} ({duration})\n   \
                         Status:\t{exit_status}\n   \
                         Stdout len:\t{stdout_len}\n   \
                         Stderr len:\t{stderr_len}\n   \
                         Stdout hash:\t{stdout_hash}\n   \
                         Stderr hash:\t{stderr_hash}",
                    );
                }
                JobStatus::Ended {
                    job: _,
                    time_reserved,
                    time_started,
                    time_ended,
                    status: None,
                    stdout_len,
                    stderr_len,
                    stdout_hash,
                    stderr_hash,
                } => {
                    let duration = format_duration(status.time_elapsed().unwrap().to_std()?);
                    let stdout_len = byte_size(*stdout_len);
                    let stderr_len = byte_size(*stderr_len);
                    println!(
                        "✅ Job ID:\t{job_id}\n   \
                         Job status: Aborted\n   \
                         Reserved at:\t{time_reserved}\n   \
                         Started at:\t{time_started}\n   \
                         Aborted at:\t{time_ended} ({duration})\n   \
                         Stdout len:\t{stdout_len}\n   \
                         Stderr len:\t{stderr_len}\n   \
                         Stdout hash:\t{stdout_hash}\n   \
                         Stderr hash:\t{stderr_hash}",
                    );
                }
            },
        }
        Ok(())
    }

    fn revoked(&mut self, revoked: &[JobId]) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(revoked)),
            OutputFormat::Text => {
                let n = revoked.len();
                match n {
                    0 => println!("✅ No jobs revoked"),
                    1 => println!("✅ Revoked job `{}`", revoked[0]),
                    _ => {
                        println!("✅ Revoked {} jobs:", revoked.len());
                        for job_id in revoked {
                            println!("{job_id}");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn job_signed(&mut self, job: &SignedJob) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", serde_json::to_string(&job)?),
            OutputFormat::Text => println!(
                "✅ Signed request for job `{}`\n{}",
                job.job_id(),
                serde_json::to_string_pretty(&job)?
            ),
        }
        Ok(())
    }
}
