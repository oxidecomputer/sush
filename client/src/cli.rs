// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Possibly-interactive command-line interface.

use std::io::{self, BufRead as _, Read as _, Write as _, stderr, stdin, stdout};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytesize::ByteSize;
use chrono::TimeDelta;
use humantime::format_duration;
use indicatif::{ProgressBar, ProgressStyle};
use rustix::io::ioctl_fionread;
use serde_json::{json, to_string as to_json_string, to_string_pretty as to_json_string_pretty};
use sled_hardware_types::BaseboardId;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::authn::Identity;
use sush_common::jobs::{
    Access, JobId, JobOutputState, JobOutputStream, JobStatus, JobStatusMap, Session, SessionId,
    SignedJob, job_status_to_json_map,
};
use sush_common::keys::{KeyId, Signature, SshPublicKey};

use crate::AuthzSigner;
use crate::commands::{CommandError, GlobalArgs};
use crate::context::{CommandContext, OutputFormat, StatusDisplayStyle};

#[derive(Clone, Debug, Default)]
pub struct Cli {
    globals: Arc<Mutex<GlobalArgs>>,
    output: Arc<Mutex<OutputFormat>>,
    progress: Arc<Mutex<Option<ProgressBar>>>,
    session: Arc<Mutex<Option<Session>>>,
    credentials: AuthzSigner,
}

fn byte_size(len: u64) -> bytesize::Display {
    ByteSize::b(len).display().si()
}

impl CommandContext for Cli {
    // Context management

    fn get_output_format(&self) -> OutputFormat {
        *self.output.lock().unwrap()
    }

    fn set_output_format(&mut self, output: OutputFormat) {
        *self.output.lock().unwrap() = output;
    }

    fn get_globals(&self) -> GlobalArgs {
        self.globals.lock().unwrap().clone()
    }

    fn set_globals(&mut self, args: GlobalArgs) {
        *self.globals.lock().unwrap() = args;
    }

    // Session management

    fn authz_signer(&self) -> AuthzSigner {
        self.credentials.clone()
    }

    fn session_id(&self) -> Option<SessionId> {
        self.session
            .lock()
            .unwrap()
            .as_ref()
            .map(|s| s.session_id().to_owned())
    }

    fn next_job_id(&self) -> Result<JobId, CommandError> {
        if let Some(session) = self.session.lock().unwrap().as_ref() {
            Ok(session.next_job_id())
        } else {
            Err(CommandError::MissingSession)
        }
    }

    fn session_started(&mut self, session: Session) -> Result<(), CommandError> {
        let session_id = session.session_id().to_owned();
        *self.session.lock().unwrap() = Some(session);
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"session_started": session_id})),
            OutputFormat::Text => println!("✅ Session is now `{session_id}`"),
        }
        Ok(())
    }

    fn session_stopped(&mut self, session_id: &SessionId) -> Result<(), CommandError> {
        let mut session_guard = self.session.lock().unwrap();
        if let Some(session) = session_guard.as_ref()
            && session.session_id() == *session_id
        {
            let _ = session_guard.take();
        }
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"session_ended": session_id})),
            OutputFormat::Text => println!("✅ Stopped session `{session_id}`"),
        }
        Ok(())
    }

    fn attach_allowed(&mut self, key_id: &KeyId, access: Access) {
        match self.get_output_format() {
            OutputFormat::Json => {
                println!("{}", json!({"attach_allowed": key_id, "access": access}))
            }
            OutputFormat::Text => {
                println!("✅ Allowed {} attach for `{key_id}`", access.as_str())
            }
        }
    }

    fn attach_denied(&mut self, key_id: &KeyId) {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"attach_denied": key_id})),
            OutputFormat::Text => println!("✅ Denied attach for `{key_id}`"),
        }
    }

    // Job signing certificates

    fn cert_chain(
        &mut self,
        key_id: KeyId,
        certs: &str,
        roots: &[Certificate],
    ) -> Result<Certificate, CommandError> {
        let mut chain = Certificate::load_pem_chain(certs.as_bytes())?;
        let Some((root, rest)) = chain.split_first() else {
            return Err(CommandError::EmptyCertChain);
        };
        if root.tbs_certificate.subject != root.tbs_certificate.issuer {
            return Err(CommandError::InvalidRootCert);
        }
        if !roots.is_empty() && !roots.contains(root) {
            return Err(CommandError::UntrustedRoot);
        }
        let tbs = root.tbs_certificate.to_der()?;
        Signature::try_from(root)?
            .verify_with_spki(&tbs, &root.tbs_certificate.subject_public_key_info)?;

        let now = SystemTime::now();
        let mut prev = root;
        for cert in &chain {
            let validity = &cert.tbs_certificate.validity;
            if now < validity.not_before.to_system_time()
                || now > validity.not_after.to_system_time()
            {
                return Err(CommandError::CertExpired(
                    cert.tbs_certificate.subject.to_string(),
                ));
            }
        }
        for cert in rest {
            let tbs = cert.tbs_certificate.to_der()?;
            Signature::try_from(cert)?
                .verify_with_spki(&tbs, &prev.tbs_certificate.subject_public_key_info)?;
            prev = cert;
        }
        if KeyId::try_from(prev)? != key_id {
            return Err(CommandError::InvalidLeafCert(key_id));
        }

        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(certs)),
            OutputFormat::Text => {
                if roots.is_empty() {
                    println!("✅ Verified chain consistency");
                } else {
                    println!("✅ Verified chain against supplied root");
                }
                for cert in &chain {
                    println!("   {}", cert.tbs_certificate.subject);
                }
            }
        }

        chain.pop().ok_or(CommandError::EmptyCertChain)
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

    // Job management

    fn job_started(&mut self, job: &SignedJob) {
        if let Some(session) = self.session.lock().unwrap().as_mut() {
            session.job_started(job.to_owned());
        }
    }

    fn job_stopped(&mut self, job_id: &JobId) {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(job_id)),
            OutputFormat::Text => println!("\r✅ Stopped job `{job_id}`"),
        }
    }

    fn job_error(&mut self, error: CommandError) -> CommandError {
        eprintln!("{error}");
        error
    }

    fn job_output_target(&mut self, target: &BaseboardId) {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({ "target": target.to_string() })),
            OutputFormat::Text => println!("⟹  {target}  ⟸"),
        }
    }

    fn job_output(
        &mut self,
        _job_id: &JobId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    ) {
        match self.get_output_format() {
            OutputFormat::Json if binary => println!("{}", json!(output)),
            OutputFormat::Json => println!("{}", json!(String::from_utf8_lossy(output))),
            OutputFormat::Text if binary => {
                if let Err(err) = stdout().write_all(output) {
                    eprintln!("{err}");
                }
            }
            OutputFormat::Text if output.is_empty() => (),
            OutputFormat::Text => {
                match stream {
                    JobOutputStream::Stdout => println!("✅ Job stdout:"),
                    JobOutputStream::Stderr => println!("✅ Job stderr:"),
                };
                let output = String::from_utf8_lossy(output);
                if output.ends_with('\n') {
                    print!("{output}");
                } else {
                    println!("{output}");
                }
            }
        }
    }

    fn job_output_started(
        &mut self,
        _id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total_length: u64,
    ) {
        let mut progress = self.progress.lock().unwrap();
        if matches!(self.get_output_format(), OutputFormat::Text) && progress.is_none() {
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
            *progress = Some(bar);
        }
    }

    fn job_output_update(&mut self, _id: &JobId, _stream: JobOutputStream, length: u64) {
        if let Some(progress) = self.progress.lock().unwrap().as_mut() {
            progress.inc(length);
        }
    }

    fn job_output_finished(
        &mut self,
        _job_id: &JobId,
        stream: JobOutputStream,
        stage: Option<&str>,
    ) {
        if let Some(progress) = self.progress.lock().unwrap().take() {
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
    }

    fn job_polling_started(&mut self, job_id: &JobId, elapsed: Duration) {
        let mut progress = self.progress.lock().unwrap();
        if matches!(self.get_output_format(), OutputFormat::Text) && progress.is_none() {
            let bar = ProgressBar::new_spinner();
            bar.set_elapsed(elapsed);
            bar.set_prefix(format!("Waiting for job `{job_id}`"));
            bar.set_style(
                ProgressStyle::with_template(
                    "{spinner}  \
                     {prefix} \
                     [{elapsed_precise}] \
                     {msg}",
                )
                .unwrap(),
            );
            *progress = Some(bar);
        }
    }

    fn job_polling_update(&mut self, _job_id: &JobId) {
        if let Some(progress) = self.progress.lock().unwrap().as_mut() {
            progress.tick();
        }
    }

    fn job_polling_finished(&mut self, _job_id: &JobId) {
        if let Some(progress) = self.progress.lock().unwrap().take() {
            progress.finish_and_clear();
        }
    }

    fn job_attached(&mut self, job_id: &JobId) {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"attached": job_id})),
            OutputFormat::Text => {
                println!("✅ Attached to interactive job `{job_id}`, detach with `^]`")
            }
        }
    }

    fn job_detached(&mut self, job_id: &JobId) {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"detached": job_id})),
            OutputFormat::Text => println!("\r✅ Detached from interactive job `{job_id}`"),
        }
    }

    fn job_signing_started(&mut self, job_id: &JobId) {
        let mut progress = self.progress.lock().unwrap();
        if matches!(self.get_output_format(), OutputFormat::Text) && progress.is_none() {
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
            *progress = Some(bar);
        }
    }

    fn job_signing_update(&mut self, _job_id: &JobId) {
        if let Some(progress) = self.progress.lock().unwrap().as_mut() {
            progress.tick();
        }
    }

    fn job_signing_finished(&mut self, job_id: &JobId) {
        if let Some(progress) = self.progress.lock().unwrap().take() {
            progress.finish_and_clear();
        }
        if matches!(self.get_output_format(), OutputFormat::Text) {
            println!("✅ Signed request for job `{job_id}`");
        }
    }

    fn job_signed(&mut self, job: &SignedJob, show: bool) {
        if show {
            match self.get_output_format() {
                OutputFormat::Json => println!(
                    "{}",
                    to_json_string(&job).expect("job should be JSON-serializable")
                ),
                OutputFormat::Text => println!(
                    "{}",
                    to_json_string_pretty(&job).expect("job should be JSON-serializable")
                ),
            }
        }
    }

    fn job_status(&mut self, job_id: &JobId, status: &JobStatusMap, style: StatusDisplayStyle) {
        fn format_elapsed_duration(duration: TimeDelta) -> String {
            if let Ok(duration) = duration.to_std() {
                format_duration(duration).to_string()
            } else {
                String::from("negative duration, times may be unreliable")
            }
        }

        // TODO: parallel status display
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!(job_status_to_json_map(status.clone()))),
            OutputFormat::Text if matches!(style, StatusDisplayStyle::Short) => {
                let icon = if status.values().any(|s| {
                    matches!(
                        s,
                        JobStatus::Error { .. }
                            | JobStatus::Cancelled { .. }
                            | JobStatus::Stopped { result: Err(_), .. }
                    )
                }) {
                    "❌"
                } else {
                    "✅"
                };
                let width = status
                    .keys()
                    .map(|b| b.to_string().len())
                    .max()
                    .unwrap_or(0);
                println!("{icon} Job ID:\t{job_id}");
                for (baseboard_id, status) in status {
                    let id = baseboard_id.to_string();
                    match status {
                        JobStatus::Cancelled {
                            time_cancelled,
                            actor,
                            ..
                        } => {
                            println!("   {id:<width$}  Cancelled at {time_cancelled} by {actor}")
                        }
                        JobStatus::Queued {
                            time_queued, actor, ..
                        } => println!("   {id:<width$}  Queued at {time_queued} by {actor}"),
                        JobStatus::Started { time_started, .. } => {
                            println!("   {id:<width$}  Started at {time_started}")
                        }
                        JobStatus::Stopped { result, output, .. } => {
                            let duration = format_elapsed_duration(status.time_elapsed());
                            let stdout_len = byte_size(output.stdout_len);
                            let stderr_len = byte_size(output.stderr_len);
                            let result = match result {
                                Ok(exit_status) => format!("exit {exit_status}"),
                                Err(err) => err.to_string(),
                            };
                            println!(
                                "   {id:<width$}  Stopped, {result} ({duration}), \
                                    {stdout_len} out, {stderr_len} err"
                            )
                        }
                        JobStatus::Error {
                            time_error, error, ..
                        } => println!("   {id:<width$}  Error at {time_error}: {error}"),
                    }
                }
            }
            OutputFormat::Text => {
                for (baseboard_id, status) in status {
                    match status {
                        JobStatus::Cancelled {
                            job_id,
                            time_cancelled,
                            actor,
                        } => {
                            println!(
                                "❌ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\tCancelled\n   \
                                    Cancelled at:\t{time_cancelled}\n   \
                                    Cancelled by:\t{actor}"
                            )
                        }
                        JobStatus::Queued {
                            job_id,
                            time_queued,
                            actor,
                        } => {
                            println!(
                                "⏳ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\tQueued\n   \
                                    Queued at:\t{time_queued}\n   \
                                    Queued by:\t{actor}"
                            )
                        }
                        JobStatus::Started {
                            job_id,
                            time_started,
                        } => {
                            println!(
                                "✅ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\tStarted\n   \
                                    Started at:\t{time_started}"
                            )
                        }
                        JobStatus::Stopped {
                            job_id,
                            time_started,
                            time_stopped,
                            result: Ok(exit_status),
                            output:
                                JobOutputState {
                                    stdout_len,
                                    stderr_len,
                                    stdout_hash,
                                    stderr_hash,
                                },
                        } => {
                            let duration = format_elapsed_duration(status.time_elapsed());
                            let stdout_len = byte_size(*stdout_len);
                            let stderr_len = byte_size(*stderr_len);
                            println!(
                                "✅ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\tStopped\n   \
                                    Started at:\t{time_started}\n   \
                                    Stopped at:\t{time_stopped} ({duration})\n   \
                                    Exit status:\t{exit_status}\n   \
                                    Stdout len:\t{stdout_len}\n   \
                                    Stderr len:\t{stderr_len}\n   \
                                    Stdout hash:\t{stdout_hash}\n   \
                                    Stderr hash:\t{stderr_hash}",
                            );
                        }
                        JobStatus::Stopped {
                            job_id,
                            time_started,
                            time_stopped,
                            result: Err(err),
                            output:
                                JobOutputState {
                                    stdout_len,
                                    stderr_len,
                                    stdout_hash,
                                    stderr_hash,
                                },
                        } => {
                            let duration = format_elapsed_duration(status.time_elapsed());
                            let stdout_len = byte_size(*stdout_len);
                            let stderr_len = byte_size(*stderr_len);
                            println!(
                                "✅ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\t{err}\n   \
                                    Started at:\t{time_started}\n   \
                                    Stopped at:\t{time_stopped} ({duration})\n   \
                                    Stdout len:\t{stdout_len}\n   \
                                    Stderr len:\t{stderr_len}\n   \
                                    Stdout hash:\t{stdout_hash}\n   \
                                    Stderr hash:\t{stderr_hash}",
                            );
                        }
                        JobStatus::Error {
                            job_id,
                            time_error,
                            error,
                        } => {
                            println!(
                                "❌ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\tError\n   \
                                    Error at:\t{time_error}\n   \
                                    Error:\t{error}"
                            )
                        }
                    }
                }
            }
        }
    }

    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError> {
        let input = read_input(match self.get_output_format() {
            OutputFormat::Json => "",
            OutputFormat::Text => "✅ Enter signed job request, terminated with Ctrl-D:\n",
        })?;
        Ok(serde_json::from_str(&input)?)
    }

    // SSH agent and identity

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

    fn really_revoke(&mut self, what: &str, key_id: KeyId) -> Result<KeyId, CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => Ok(key_id),
            OutputFormat::Text => {
                let prompt = format!("❓ Really revoke {what} `{key_id}` (yes/no)? ");
                if read_bool(&prompt)? {
                    Ok(key_id)
                } else {
                    Err(CommandError::Canceled)
                }
            }
        }
    }

    fn revoked(&mut self, what: &str, key_id: KeyId) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => println!("{}", json!({"revoked": key_id})),
            OutputFormat::Text => println!("✅ Revoked {what} `{key_id}`"),
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

#[cfg(test)]
mod test {
    use std::slice::from_ref;
    use std::time::Duration;

    use x509_cert::time::Validity;

    use sush_common::keys::{EphemeralKey, KeyType, pem_cert_chain};

    use super::*;

    async fn chain(validity: Validity) -> (KeyId, String, Certificate) {
        let subject = |name: &str| format!("CN={name},O=Test,C=US").parse().unwrap();
        let mut root = EphemeralKey::new_root(KeyType::P256, subject("root"), validity).unwrap();
        let issuer = root.subject();
        let algorithm = root.signature_algorithm();
        let child = EphemeralKey::new_child(
            KeyType::P256,
            subject("child"),
            issuer,
            validity,
            &mut root,
            algorithm,
        )
        .await
        .unwrap();
        let pem = pem_cert_chain(vec![root.cert().clone(), child.cert().clone()]).unwrap();
        (child.key_id().clone(), pem, root.cert().clone())
    }

    /// A chain verifies against a supplied root, or unanchored for
    /// consistency only. A different root or an expired certificate
    /// is refused.
    #[tokio::test]
    async fn cert_chains() {
        let validity = Validity::from_now(Duration::from_secs(600)).unwrap();
        let (key_id, pem, root) = chain(validity).await;
        let mut cli = Cli::default();
        cli.cert_chain(key_id.clone(), &pem, from_ref(&root))
            .unwrap();
        cli.cert_chain(key_id.clone(), &pem, &[]).unwrap();

        let (_, _, other_root) = chain(validity).await;
        assert!(matches!(
            cli.cert_chain(key_id, &pem, &[other_root]).unwrap_err(),
            CommandError::UntrustedRoot
        ));

        let brief = Validity::from_now(Duration::from_secs(1)).unwrap();
        let (key_id, pem, root) = chain(brief).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(matches!(
            cli.cert_chain(key_id, &pem, &[root]).unwrap_err(),
            CommandError::CertExpired(_)
        ));
    }
}
