//! Possibly-interactive command-line interface.

use std::io::{self, BufRead as _, Read as _, Write as _, stderr, stdin, stdout};
use std::path::Path;
use std::time::Duration;

use bytesize::ByteSize;
use chrono::{DateTime, Utc};
use humantime::format_duration;
use indicatif::{ProgressBar, ProgressStyle};
use rustix::io::ioctl_fionread;
use serde_json::{json, to_string as to_json_string, to_string_pretty as to_json_string_pretty};
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::authn::Identity;
use sush_common::jobs::{JobId, JobOutputStream, JobStatus, SignedJob};
use sush_common::keys::{KeyId, Signature, SshPublicKey};

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
        Signature::try_from(root)?
            .verify_with_spki(&tbs, &root.tbs_certificate.subject_public_key_info)?;
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
                .verify_with_spki(&tbs, &prev.tbs_certificate.subject_public_key_info)?;
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

    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError> {
        let input = read_input(match self.get_output_format() {
            OutputFormat::Json => "",
            OutputFormat::Text => "✅ Enter signed job request, terminated with Ctrl-D:\n",
        })?;
        Ok(serde_json::from_str(&input)?)
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
        if matches!(self.get_output_format(), OutputFormat::Text) && self.progress.is_none() {
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
        if matches!(self.get_output_format(), OutputFormat::Text) && self.progress.is_none() {
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
            OutputFormat::Json => println!("{}", json!({"connected": job_id})),
            OutputFormat::Text => println!("✅ Connected to interactive job `{job_id}`"),
        }
        Ok(())
    }

    fn job_session_disconnected(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"disconnected": job_id})),
            OutputFormat::Text => println!("\r✅ Disconnected interactive job `{job_id}`"),
        }
        Ok(())
    }

    fn job_signing_started(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        if matches!(self.get_output_format(), OutputFormat::Text) && self.progress.is_none() {
            let bar = ProgressBar::new_spinner();
            bar.set_prefix(format!("Waiting for signature on `{job_id}`"));
            bar.set_style(
                ProgressStyle::with_template(
                    "{spinner}  \
                     {prefix} \
                     [{elapsed_precise}] \
                     {msg}",
                )
                .unwrap(),
            );
            bar.enable_steady_tick(Duration::from_millis(100));
            self.progress = Some(bar);
        }
        Ok(())
    }

    fn job_signing_update(&mut self, _job_id: &JobId) -> Result<(), CommandError> {
        if let Some(progress) = &mut self.progress {
            progress.tick();
        }
        Ok(())
    }

    fn job_signing_finished(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        if let Some(progress) = self.progress.take() {
            progress.finish_and_clear();
        }
        if matches!(self.get_output_format(), OutputFormat::Text) {
            println!("✅ Signed request for job `{job_id}`");
        }
        Ok(())
    }

    fn job_signed(&mut self, job: &SignedJob) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", to_json_string(&job)?),
            OutputFormat::Text => println!("{}", to_json_string_pretty(&job)?),
        }
        Ok(())
    }

    fn job_status(&mut self, job_id: &JobId, status: &JobStatus) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(status)),
            OutputFormat::Text => match status {
                JobStatus::Unknown {
                    job_id,
                } => println!(
                    "✅ Job ID:\t{job_id}\n   \
                     Job status:\tUnknown"
                ),
                JobStatus::Started {
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
                         Started at:\t{time_started}\n   \
                         Stdout len:\t{stdout_len}\n   \
                         Stderr len:\t{stderr_len}"
                    )
                }
                JobStatus::Ended {
                    job: _,
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
                         Job status:\tAborted\n   \
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

    fn iam(&mut self, identity: &Identity) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", to_json_string(identity)?),
            OutputFormat::Text => {
                let Identity {
                    key_id,
                    public_key,
                    nonce,
                    time_authenticated,
                    time_revoked,
                } = identity;
                let fingerprint = public_key.fingerprint(Default::default()).to_string();
                let algorithm = public_key.algorithm();
                let comment = public_key.comment();
                println!(
                    "✅ Key ID:\t{key_id}\n   \
                        Fingerprint:\t{fingerprint}\n   \
                        Algorithm:\t{algorithm}\n   \
                        Comment:\t{comment}\n   \
                        Nonce:\t{nonce}\n   \
                        Authn at:\t{time_authenticated}",
                );
                if let Some(time_revoked) = time_revoked {
                    println!("   Revoked at:\t{time_revoked}");
                }
            }
        }
        Ok(())
    }

    fn identities(&mut self, keys: &[SshPublicKey]) -> Result<(), CommandError> {
        let n = keys.len();
        if n == 0 {
            match self.get_output_format() {
                OutputFormat::Json => println!("[]"),
                OutputFormat::Text => println!("❌ No SSH identities found"),
            }
        } else {
            for key in keys {
                let key_id = key.key_id()?;
                let fingerprint = key.fingerprint(Default::default()).to_string();
                let algorithm = key.algorithm();
                let comment = key.comment();
                match self.get_output_format() {
                    OutputFormat::Json => println!(
                        "{}",
                        json!({
                            "key_id": key_id,
                            "fingerprint": fingerprint,
                            "algorithm": algorithm.to_string(),
                            "public_key": key.to_openssh()?,
                        })
                    ),
                    OutputFormat::Text => {
                        println!(
                            "✅ Key ID:\t{key_id}\n   \
                                Fingerprint:\t{fingerprint}\n   \
                                Algorithm:\t{algorithm}\n   \
                                Comment:\t{comment}",
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn really_revoke(&mut self, key_id: KeyId) -> Result<KeyId, CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => Ok(key_id),
            OutputFormat::Text => {
                let prompt = format!("❓ Really revoke identity `{key_id}` (yes/no)? ");
                if read_bool(&prompt)? {
                    Ok(key_id)
                } else {
                    Err(CommandError::Canceled)
                }
            }
        }
    }

    fn identity_revoked(&mut self, key_id: KeyId) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"revoked": key_id})),
            OutputFormat::Text => println!("✅ Revoked SSH identity `{key_id}`"),
        }
        Ok(())
    }

    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError> {
        if identity.is_sk_algorithm() {
            match self.get_output_format() {
                OutputFormat::Json => (),
                OutputFormat::Text => eprintln!(
                    "👋 Please confirm user presence to sign with key `{}`",
                    identity.key_id()?
                ),
            }
        }
        Ok(())
    }
}

/// Read stdin until EOF, prompting unless there's already input available.
fn read_input(prompt: &str) -> Result<String, CommandError> {
    let mut stderr = stderr().lock();
    let mut stdin = stdin().lock();
    let avail = ioctl_fionread(&stdin).map_err(stdin_err)?;
    if avail == 0 && !prompt.is_empty() {
        stderr.write_all(prompt.as_bytes()).map_err(stderr_err)?;
    }

    let mut input = String::new();
    stdin.read_to_string(&mut input).map_err(stdin_err)?;
    Ok(input)
}

/// Prompt with a question and read a boolean answer. The (case-insensitive)
/// strings `"y"` and `"yes"` denote true, anything else denotes false.
fn read_bool(prompt: &str) -> Result<bool, CommandError> {
    let mut stderr = stderr().lock();
    stderr.write_all(prompt.as_bytes()).map_err(stderr_err)?;

    let mut input = String::new();
    let mut stdin = stdin().lock();
    stdin.read_line(&mut input).map_err(stdin_err)?;
    Ok(["y", "yes"].contains(&input.trim().to_ascii_lowercase().as_ref()))
}

fn stderr_err<E: Into<io::Error>>(err: E) -> CommandError {
    CommandError::io("stderr", err.into())
}

fn stdin_err<E: Into<io::Error>>(err: E) -> CommandError {
    CommandError::io("stdin", err.into())
}
