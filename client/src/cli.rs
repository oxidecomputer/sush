// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Possibly-interactive command-line interface.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::{self, BufRead as _, ErrorKind, Read as _, Write as _, stderr, stdin};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anstyle::{AnsiColor, Style};
use atomicwrites::{AtomicFile, OverwriteBehavior};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytesize::ByteSize;
use chrono::TimeDelta;
use humantime::format_duration;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rustix::io::ioctl_fionread;
use rustix::termios::{LocalModes, OptionalActions, Termios, isatty, tcgetattr, tcsetattr};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_string as to_json_string, to_string_pretty as to_json_string_pretty};
use sled_hardware_types::BaseboardId;
use x509_cert::Certificate;
use x509_cert::der::Encode as _;

use sush_common::authn::Identity;
use sush_common::jobs::{
    Access, JobId, JobOutputState, JobOutputStream, JobStartRequest, JobStatus, JobStatusMap,
    Session, SessionClientNonce, SessionId, SessionSeq, SessionSignerNonce, SessionSushNonce,
    SignedJob, job_status_to_json_map,
};
use sush_common::keys::{KeyId, Signature, SshPublicKey};
use sush_common::targets::{MAX_CUBBY, SledHealth, SledId, SledVersion, Target};
use sush_common::version::VersionInfo;

use crate::commands::{CommandError, GlobalArgs};
use crate::context::{CommandContext, OutputFormat, StartedDisplay, StatusDisplayStyle};
use crate::{AuthzSigner, base_directories, quiet_write};

const SESSION_FILE_NAME: &str = "session.json";
const SESSION_FILE_VERSION: u32 = 1;
const CLIENT_NONCE_FILE_NAME: &str = "client-nonce.json";
const CLIENT_NONCE_FILE_VERSION: u32 = 1;

/// The persisted session, versioned for future migrations.
#[derive(Deserialize, Serialize)]
struct SavedSession {
    version: u32,
    session: Session,
}

/// The persisted client nonce of the pending session ceremony,
/// versioned for future migrations. One pending ceremony at a time,
/// mirroring the rack's one server nonce slot: `session start-params`
/// overwrites it just as the fetch it makes overwrites the slot.
#[derive(Deserialize, Serialize)]
struct SavedClientNonce {
    version: u32,
    client_nonce: SessionClientNonce,
}

#[derive(Clone, Debug, Default)]
pub struct Cli {
    globals: Arc<Mutex<GlobalArgs>>,
    output: Arc<Mutex<OutputFormat>>,
    progress: Arc<Mutex<Option<ProgressBar>>>,
    watch: Arc<Mutex<Option<Watch>>>,
    session: Arc<Mutex<Option<Session>>>,
    session_file: Option<PathBuf>,
    client_nonce_file: Option<PathBuf>,
    credentials: AuthzSigner,
}

impl Cli {
    /// Load the persisted session and persist its changes hereafter.
    /// Without persistence, every one-shot command would need a fresh
    /// `session attach`.
    pub fn load_session(&mut self) {
        let path = match base_directories().place_state_file(SESSION_FILE_NAME) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("❗ The session will not persist: {error}");
                return;
            }
        };
        match fs::read(&path) {
            Ok(json) => match serde_json::from_slice::<SavedSession>(&json) {
                Ok(SavedSession {
                    version: SESSION_FILE_VERSION,
                    session,
                }) => *self.session.lock().unwrap() = Some(session),
                Ok(SavedSession { version, .. }) => {
                    eprintln!("❗ Ignoring a version {version} saved session")
                }
                Err(error) => eprintln!("❗ Ignoring the saved session: {error}"),
            },
            Err(error) if error.kind() == ErrorKind::NotFound => (),
            Err(error) => eprintln!("❗ Ignoring the saved session: {error}"),
        }
        self.session_file = Some(path);
        match base_directories().place_state_file(CLIENT_NONCE_FILE_NAME) {
            Ok(path) => self.client_nonce_file = Some(path),
            Err(error) => eprintln!("❗ The client nonce will not persist: {error}"),
        }
    }

    fn note(&self, message: impl fmt::Display) {
        match self.watch.lock().unwrap().as_ref() {
            Some(watch) => watch.multi.suspend(|| eprintln!("{message}")),
            None => eprintln!("{message}"),
        }
    }

    /// Adopt `session` unless one with the same ID is already
    /// attached and `force` is unset.
    fn adopt_session(&mut self, session: Session, force: bool) -> SessionId {
        let session_id = session.session_id();
        let mut session_guard = self.session.lock().unwrap();
        if force
            || session_guard
                .as_ref()
                .is_none_or(|s| s.session_id() != session_id)
        {
            self.save_session(Some(&session));
            *session_guard = Some(session);
        }
        session_id
    }

    fn save_session(&self, session: Option<&Session>) {
        let Some(path) = &self.session_file else {
            return;
        };
        let result = match session {
            Some(session) => serde_json::to_vec_pretty(&SavedSession {
                version: SESSION_FILE_VERSION,
                session: session.clone(),
            })
            .map_err(io::Error::other)
            .and_then(|json| write_private(path, &json)),
            None => match fs::remove_file(path) {
                Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
                _ => Ok(()),
            },
        };
        if let Err(error) = result {
            eprintln!("❗ The session was not saved: {error}");
        }
    }
}

/// Atomically write a file only the user may read, born that way
/// rather than chmodded after opening.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true).mode(0o600);
    AtomicFile::new(path, OverwriteBehavior::AllowOverwrite)
        .write_with_options(|file| file.write_all(bytes), options)
        .map_err(|error| match error {
            atomicwrites::Error::Internal(error) | atomicwrites::Error::User(error) => error,
        })
}

fn byte_size(len: u64) -> bytesize::Display {
    ByteSize::b(len).display().si()
}

fn format_elapsed_duration(duration: TimeDelta) -> String {
    if let Ok(duration) = duration.to_std() {
        format_duration(duration).to_string()
    } else {
        String::from("negative duration, times may be unreliable")
    }
}

/// One sled's worth of job status, without the sled's name.
fn short_status_row(status: &JobStatus) -> String {
    match status {
        JobStatus::Cancelled {
            time_cancelled,
            actor,
            ..
        } => format!("Cancelled at {time_cancelled} by {actor}"),
        JobStatus::Queued {
            time_queued, actor, ..
        } => format!("Queued at {time_queued} by {actor}"),
        JobStatus::Started { time_started, .. } => format!("Started at {time_started}"),
        JobStatus::Stopped { result, output, .. } => {
            let duration = format_elapsed_duration(status.time_elapsed());
            let stdout_len = byte_size(output.stdout_len);
            let stderr_len = byte_size(output.stderr_len);
            let result = match result {
                Ok(exit_status) => format!("exit {exit_status}"),
                Err(err) => err.to_string(),
            };
            format!("Stopped, {result} ({duration}), {stdout_len} out, {stderr_len} err")
        }
        JobStatus::Error {
            time_error, error, ..
        } => format!("Error at {time_error}: {error}"),
        JobStatus::Skipped {
            time_skipped,
            reason,
            ..
        } => format!("Skipped at {time_skipped}: {reason}"),
    }
}

/// Live per-sled status lines for a watched job.
struct Watch {
    multi: MultiProgress,
    bars: BTreeMap<BaseboardId, ProgressBar>,
    width: usize,
    saved: Option<Termios>,
}

impl Watch {
    fn new() -> Self {
        Self {
            multi: MultiProgress::new(),
            bars: BTreeMap::new(),
            width: 0,
            saved: no_echo_control(),
        }
    }
}

/// Stop the terminal from echoing control sequences.
fn no_echo_control() -> Option<Termios> {
    let input = stdin();
    if !isatty(&input) {
        return None;
    }
    let old = tcgetattr(&input).ok()?;
    let mut new = old.clone();
    new.local_modes &= !LocalModes::ECHOCTL;
    tcsetattr(&input, OptionalActions::Now, &new).ok()?;
    Some(old)
}

impl fmt::Debug for Watch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Watch")
            .field("bars", &self.bars.keys())
            .finish_non_exhaustive()
    }
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

    // Errors

    fn command_error(&mut self, error: &CommandError) {
        let errors = error.errors();
        match self.get_output_format() {
            OutputFormat::Json => {
                let message = errors
                    .into_iter()
                    .map(|(_, message)| message)
                    .collect::<Vec<_>>()
                    .join("\n");
                qprintln!("{}", json!({"error": {"message": message}}))
            }
            OutputFormat::Text => {
                for (icon, message) in errors {
                    eprintln!("{icon} {message}");
                }
            }
        }
    }

    // Build provenance

    fn versions(
        &mut self,
        client: &VersionInfo,
        server: Option<&VersionInfo>,
        sleds: &[SledVersion],
    ) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!(
                "{}",
                json!({
                    "version": {
                        "client": client,
                        "server": server,
                        "sleds": sleds
                            .iter()
                            .map(|sled| {
                                json!({
                                    "cubby": sled.cubby,
                                    "baseboard": sled.baseboard.to_string(),
                                    "version": sled.version,
                                    "health": sled.health,
                                })
                            })
                            .collect::<Vec<_>>(),
                    }
                })
            ),
            OutputFormat::Text => {
                qprintln!("Client:\t{client}");
                if let Some(server) = server {
                    qprintln!("Server:\t{server}");
                }
                if !sleds.is_empty() {
                    qprint!("{}", draw_rack(sleds));
                }
            }
        }
    }

    // Session management

    fn authz_signer(&self) -> AuthzSigner {
        self.credentials.clone()
    }

    fn pending_client_nonce(&self) -> Option<SessionClientNonce> {
        let json = fs::read(self.client_nonce_file.as_ref()?).ok()?;
        match serde_json::from_slice::<SavedClientNonce>(&json) {
            Ok(SavedClientNonce {
                version: CLIENT_NONCE_FILE_VERSION,
                client_nonce,
            }) => Some(client_nonce),
            _ => None,
        }
    }

    fn save_client_nonce(&self, client_nonce: SessionClientNonce) {
        let Some(path) = &self.client_nonce_file else {
            return;
        };
        let result = serde_json::to_vec_pretty(&SavedClientNonce {
            version: CLIENT_NONCE_FILE_VERSION,
            client_nonce,
        })
        .map_err(io::Error::other)
        .and_then(|json| write_private(path, &json));
        if let Err(error) = result {
            eprintln!("❗ The client nonce was not saved: {error}");
        }
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

    fn session_start_params(
        &self,
        baseboard_id: BaseboardId,
        client_nonce: SessionClientNonce,
        sush_nonce: SessionSushNonce,
    ) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!(
                "{}",
                json!({
                    "session_start_params": {
                        "baseboard_id": &baseboard_id.to_string(),
                        "client_nonce": &client_nonce,
                        "sush_nonce": &sush_nonce,
                    }
                })
            ),
            OutputFormat::Text => {
                self.note("✅ Please relay these parameters to support:");
                qprintln!("   Baseboard ID: {baseboard_id}");
                qprintln!("   Sush nonce:   {sush_nonce}");
            }
        }
    }

    fn job_start_params(&self, request: &JobStartRequest) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!(
                "{}",
                json!({
                    "job_start_params": {
                        "job_id": &request.job_id,
                        "session_id": &request.session_id,
                        "command": &request.command,
                        "mode": &request.mode,
                        "target": &request.target.to_string(),
                    }
                })
            ),
            OutputFormat::Text => {
                self.note("✅ Please request a job with these parameters from support:");
                qprintln!("   Job ID:     {}", request.job_id);
                qprintln!("   Session ID: {}", request.session_id);
                qprintln!("   Command:    {}", request.command);
                qprintln!("   Mode:       {}", request.mode.as_str());
                qprintln!("   Target:     {}", request.target);
            }
        }
    }

    fn session_created(
        &mut self,
        session: Session,
        signer_nonce: SessionSignerNonce,
        seq: SessionSeq,
    ) {
        let session_id = self.adopt_session(session, true);
        match self.get_output_format() {
            OutputFormat::Json => qprintln!(
                "{}",
                json!({
                    "session_created": {
                        "session_id": session_id,
                        "signer_nonce": signer_nonce,
                        "seq": seq,
                    }
                })
            ),
            OutputFormat::Text => {
                self.note("✅ Created session");
                qprintln!("   Session ID:      {session_id}");
                qprintln!("   Signer nonce:    {signer_nonce}");
                qprintln!("   Sequence number: {seq}");
            }
        }
    }

    fn session_started(&mut self, session: Session, force: bool) {
        let session_id = self.adopt_session(session, force);
        match self.get_output_format() {
            OutputFormat::Json => qprintln!("{}", json!({"session_started": session_id})),
            OutputFormat::Text => {
                self.note("✅ Started session");
                qprintln!("   Session ID: {session_id}");
            }
        }
    }

    fn session_joined(&mut self, session: Session, force: bool) {
        let session_id = self.adopt_session(session, force);
        match self.get_output_format() {
            OutputFormat::Json => qprintln!("{}", json!({"session_joined": session_id})),
            OutputFormat::Text => {
                self.note("✅ Joined session");
                qprintln!("   Session ID: {session_id}");
            }
        }
    }

    fn session_stopped(&mut self, session_id: &SessionId) {
        let mut session_guard = self.session.lock().unwrap();
        if let Some(session) = session_guard.as_ref()
            && session.session_id() == *session_id
        {
            let _ = session_guard.take();
            self.save_session(None);
        }
        match self.get_output_format() {
            OutputFormat::Json => qprintln!("{}", json!({"session_stopped": session_id})),
            OutputFormat::Text => self.note(format!("✅ Stopped session `{session_id}`")),
        }
    }

    fn really_supersede(&mut self, session: &Session) -> Result<(), CommandError> {
        if read_bool(&format!(
            "❓ Session `{}`{} is active. Stop it and start a new session (yes/no)? ",
            session.session_id(),
            session
                .started_by()
                .map(|key_id| format!(", started by `{key_id}`,"))
                .unwrap_or_default(),
        ))? {
            Ok(())
        } else {
            Err(CommandError::Canceled)
        }
    }

    fn attach_allowed(&mut self, key_id: &KeyId, access: Access) {
        match self.get_output_format() {
            OutputFormat::Json => {
                qprintln!(
                    "{}",
                    json!({
                        "attach_allowed": {
                            "key_id": key_id,
                            "access": access,
                        }
                    })
                )
            }
            OutputFormat::Text => self.note(format!(
                "✅ Allowed {} attach for `{key_id}`",
                access.as_str()
            )),
        }
    }

    fn attach_denied(&mut self, key_id: &KeyId) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!("{}", json!({"attach_denied": key_id})),
            OutputFormat::Text => self.note(format!("✅ Denied attach for `{key_id}`")),
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
            OutputFormat::Json => qprintln!("{}", json!({"certs": certs})),
            OutputFormat::Text => {
                if roots.is_empty() {
                    self.note("✅ Verified chain consistency");
                } else {
                    self.note("✅ Verified chain against supplied root");
                }
                for cert in &chain {
                    qprintln!("   {}", cert.tbs_certificate.subject);
                }
            }
        }

        chain.pop().ok_or(CommandError::EmptyCertChain)
    }

    // Job management

    fn job_started(
        &mut self,
        job: &SignedJob,
        sleds: Option<&BTreeSet<BaseboardId>>,
        display: StartedDisplay,
    ) {
        if let Some(session) = self.session.lock().unwrap().as_mut() {
            session.job_started(job.to_owned());
            self.save_session(Some(session));
        }
        if matches!(display, StartedDisplay::None) {
            return;
        }
        let job_id = job.job_id();
        match self.get_output_format() {
            OutputFormat::Json => qprintln!(
                "{}",
                json!({
                    "job_started": {
                        "job_id": job_id,
                        "sleds": sleds.map(|sleds| {
                            sleds.iter().map(ToString::to_string).collect::<Vec<_>>()
                        }),
                    }
                })
            ),
            OutputFormat::Text => {
                self.note(format!("✅ Started job `{job_id}`"));
                if matches!(display, StartedDisplay::Full) {
                    qprintln!("   Job ID: {job_id}");
                }
                if let (Target::Sleds(named), Some(sleds)) = (job.payload().target(), sleds) {
                    for sled in named {
                        if let SledId::Baseboard(baseboard) = sled
                            && !sleds.contains(baseboard)
                        {
                            self.note(format!(
                                "❗ Job `{job_id}` will not run on unreachable sled `{baseboard}`"
                            ));
                        }
                    }
                }
            }
        }
    }

    fn job_stopped(&mut self, job_id: &JobId) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!("{}", json!({"job_stopped": job_id})),
            OutputFormat::Text => {
                self.note(format!("\r✅ Stopped job `{job_id}`"));
            }
        }
    }

    fn job_skipped(&mut self, job_id: &JobId) -> bool {
        let mut session_guard = self.session.lock().unwrap();
        let skipped = match session_guard.as_mut() {
            Some(session) => session.skip_job(*job_id),
            None => false,
        };
        if skipped {
            self.save_session(session_guard.as_ref());
            match self.get_output_format() {
                OutputFormat::Json => qprintln!("{}", json!({"job_skipped": job_id})),
                OutputFormat::Text => self.note(format!("✅ Skipped job `{job_id}`")),
            }
        }
        skipped
    }

    fn job_output(
        &mut self,
        job_id: &JobId,
        target: &BaseboardId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    ) {
        match self.get_output_format() {
            OutputFormat::Json => {
                let (output, encoding) = if binary {
                    (STANDARD.encode(output), "base64")
                } else {
                    (String::from_utf8_lossy(output).into_owned(), "utf-8")
                };
                qprintln!(
                    "{}",
                    json!({
                        "job_output": {
                            "job_id": job_id,
                            "target": target.to_string(),
                            "stream": stream,
                            "encoding": encoding,
                            "output": output,
                        }
                    })
                )
            }
            OutputFormat::Text if output.is_empty() => (),
            OutputFormat::Text => {
                self.note(format!(" » {target} {stream} «"));
                if binary {
                    if let Err(err) = quiet_write(output) {
                        eprintln!("{err}");
                    }
                } else {
                    let output = String::from_utf8_lossy(output);
                    if output.ends_with('\n') {
                        qprint!("{output}");
                    } else {
                        qprintln!("{output}");
                    }
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
            // With no known total, show a spinner and a running byte count.
            let bar = if total_length == 0 {
                let bar = ProgressBar::new_spinner();
                bar.set_style(
                    ProgressStyle::with_template(
                        "{spinner}  \
                         {prefix} \
                         [{elapsed_precise}] \
                         {decimal_bytes:>7} \
                         {msg}",
                    )
                    .unwrap(),
                );
                bar.enable_steady_tick(Duration::from_millis(100));
                bar
            } else {
                let bar = ProgressBar::new(total_length);
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
                bar
            };
            bar.set_prefix(format!("{stage} {stream}"));
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
                let length = ByteSize::b(progress.length().unwrap_or(progress.position()));
                let elapsed = progress.elapsed();
                self.note(format!(
                    "{stage} {stream}:\t{} in {} ({:.0} MB/s)",
                    length.display().si(),
                    format_duration(progress.elapsed()),
                    length.as_mb() / elapsed.as_secs_f64(),
                ));
            }
        }
    }

    fn job_watch_started(&mut self, _job_id: &JobId) {
        if matches!(self.get_output_format(), OutputFormat::Text) {
            *self.watch.lock().unwrap() = Some(Watch::new());
        }
    }

    fn job_watch_update(&mut self, status: &JobStatusMap) {
        let mut guard = self.watch.lock().unwrap();
        let Some(watch) = guard.as_mut() else { return };

        // Widen every name column if a longer baseboard ID appears.
        let width = status
            .keys()
            .map(|b| b.to_string().len())
            .max()
            .unwrap_or(0);
        if width > watch.width {
            watch.width = width;
            for (baseboard_id, bar) in &watch.bars {
                bar.set_prefix(format!("{:<width$}", baseboard_id.to_string()));
            }
        }
        let width = watch.width;

        for (baseboard_id, status) in status {
            if !watch.bars.contains_key(baseboard_id) {
                let index = watch.bars.range(..baseboard_id).count();
                let bar = watch.multi.insert(index, ProgressBar::new_spinner());
                bar.set_style(ProgressStyle::with_template("{spinner}  {prefix}  {msg}").unwrap());
                bar.set_prefix(format!("{:<width$}", baseboard_id.to_string()));
                bar.enable_steady_tick(Duration::from_millis(100));
                watch.bars.insert(baseboard_id.to_owned(), bar);
            }
            let bar = &watch.bars[baseboard_id];
            if bar.is_finished() {
                continue;
            }
            if status.is_terminal() {
                bar.finish_with_message(short_status_row(status));
            } else {
                bar.set_message(short_status_row(status));
            }
        }
    }

    fn job_watch_stalled(&mut self, job_id: &JobId) {
        if matches!(self.get_output_format(), OutputFormat::Text) {
            self.note(format!(
                "❗ No sled has reported a status for job `{job_id}`"
            ));
        }
    }

    fn job_watch_finished(&mut self, _job_id: &JobId) {
        if let Some(watch) = self.watch.lock().unwrap().take() {
            for bar in watch.bars.values() {
                bar.finish_and_clear();
            }
            let _ = watch.multi.clear();
            if let Some(saved) = watch.saved {
                let _ = tcsetattr(stdin(), OptionalActions::Now, &saved);
            }
        }
    }

    fn job_attached(&mut self, job_id: &JobId) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!("{}", json!({"attached": job_id})),
            OutputFormat::Text => {
                self.note(format!("✅ Attached to job `{job_id}`, detach with `^]`"))
            }
        }
    }

    fn job_detached(&mut self, job_id: &JobId) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!("{}", json!({"detached": job_id})),
            OutputFormat::Text => self.note(format!("\r✅ Detached from job `{job_id}`")),
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

    fn job_signing_finished(&mut self, job_id: &JobId, signed: bool) {
        if let Some(progress) = self.progress.lock().unwrap().take() {
            progress.finish_and_clear();
        }
        if signed && matches!(self.get_output_format(), OutputFormat::Text) {
            self.note(format!("✅ Signed request for job `{job_id}`"));
        }
    }

    fn job_signed(&mut self, job: &SignedJob, show: bool) {
        if show {
            match self.get_output_format() {
                OutputFormat::Json => qprintln!(
                    "{}",
                    to_json_string(&job).expect("job should be JSON-serializable")
                ),
                OutputFormat::Text => qprintln!(
                    "{}",
                    to_json_string_pretty(&job).expect("job should be JSON-serializable")
                ),
            }
        }
    }

    fn job_status(&mut self, job_id: &JobId, status: &JobStatusMap, style: StatusDisplayStyle) {
        match self.get_output_format() {
            OutputFormat::Json => qprintln!(
                "{}",
                json!({
                    "job_status": {
                        "job_id": job_id,
                        "sleds": job_status_to_json_map(status.clone()),
                    }
                })
            ),
            OutputFormat::Text if !matches!(style, StatusDisplayStyle::Full) => {
                if matches!(style, StatusDisplayStyle::Medium) {
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
                    qprintln!("{icon} Job ID:\t{job_id}");
                }
                let width = status
                    .keys()
                    .map(|b| b.to_string().len())
                    .max()
                    .unwrap_or(0);
                for (baseboard_id, status) in status {
                    let id = baseboard_id.to_string();
                    qprintln!("   {id:<width$}  {}", short_status_row(status));
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
                            qprintln!(
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
                            qprintln!(
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
                            qprintln!(
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
                            qprintln!(
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
                            qprintln!(
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
                            qprintln!(
                                "❌ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\tError\n   \
                                    Error at:\t{time_error}\n   \
                                    Error:\t{error}"
                            )
                        }
                        JobStatus::Skipped {
                            job_id,
                            time_skipped,
                            reason,
                        } => {
                            qprintln!(
                                "⏩ Job ID:\t{job_id}\n   \
                                    Target:\t{baseboard_id}\n   \
                                    Job status:\tSkipped\n   \
                                    Skipped at:\t{time_skipped}\n   \
                                    Reason:\t{reason}"
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
            OutputFormat::Json => qprintln!("{}", json!({"identity": identity})),
            OutputFormat::Text => {
                let Identity {
                    key_id,
                    public_key,
                    nonce,
                    time_authenticated,
                } = identity;
                let fingerprint = public_key.fingerprint();
                let algorithm = public_key.algorithm();
                let comment = public_key.comment();
                qprintln!(
                    "✅ Key ID:\t{key_id}\n   \
                        Fingerprint:\t{fingerprint}\n   \
                        Algorithm:\t{algorithm}\n   \
                        Comment:\t{comment}\n   \
                        Nonce:\t{nonce}\n   \
                        Authn at:\t{time_authenticated}",
                );
            }
        }
        Ok(())
    }

    fn identities(&mut self, keys: &[SshPublicKey]) -> Result<(), CommandError> {
        match self.get_output_format() {
            OutputFormat::Json => {
                let identities = keys
                    .iter()
                    .map(|key| {
                        Ok(json!({
                            "key_id": key.key_id()?,
                            "fingerprint": key.fingerprint(),
                            "algorithm": key.algorithm().to_string(),
                            "public_key": key.to_openssh()?,
                        }))
                    })
                    .collect::<Result<Vec<_>, CommandError>>()?;
                qprintln!("{}", json!({"identities": identities}));
            }
            OutputFormat::Text if keys.is_empty() => self.note("❌ No SSH identities found"),
            OutputFormat::Text => {
                for key in keys {
                    let key_id = key.key_id()?;
                    let fingerprint = key.fingerprint();
                    let algorithm = key.algorithm();
                    let comment = key.comment();
                    qprintln!(
                        "✅ Key ID:\t{key_id}\n   \
                            Fingerprint:\t{fingerprint}\n   \
                            Algorithm:\t{algorithm}\n   \
                            Comment:\t{comment}",
                    );
                }
            }
        }
        Ok(())
    }

    fn really_target(&mut self, sled: &SledId) -> Result<(), CommandError> {
        if read_bool(&format!(
            "❓ Sled `{sled}` is not in the rack inventory. Proceed (yes/no)? "
        ))? {
            Ok(())
        } else {
            Err(CommandError::Canceled)
        }
    }

    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError> {
        if identity.is_sk_algorithm() {
            eprintln!(
                "👋 Please confirm user presence to sign with key `{}`",
                identity.key_id()?
            );
        }
        Ok(())
    }

    #[cfg(feature = "permslip")]
    fn please_authn(&mut self, url: &str) {
        let message = if webbrowser::open(url).is_ok() {
            "🔑 Authenticate to the signing service in your browser, or open this URL:"
        } else {
            "🔑 Open this URL in your browser to authenticate to the signing service:"
        };
        let print = || eprintln!("{message}\n{url}");
        match self.progress.lock().unwrap().as_ref() {
            Some(bar) => bar.suspend(print),
            None => print(),
        }
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

/// Cell text width for one sled in the rack drawing.
const CELL: usize = 28;

/// One sled cell: serial on the left, build on the right, colored by
/// health.
fn rack_cell(sled: Option<&SledVersion>) -> String {
    match sled {
        Some(sled) => {
            let build = match &sled.version {
                Some(v) => {
                    let dirty = if v.commit.ends_with("-dirty") {
                        "+"
                    } else {
                        ""
                    };
                    format!("{} {:.7}{dirty}", v.version, v.commit)
                }
                None => String::new(),
            };
            let style = health_style(sled);
            format!(
                "{style} {:<12.12}{:>14.14} {style:#}",
                sled.baseboard.serial_number, build
            )
        }
        None => " ".repeat(CELL),
    }
}

/// Green gossips with the answering sled, yellow was once known but is
/// out of contact, and red is in the cubby map with no other sign of
/// life. Sleds without health (an old server, a newer state than this
/// build knows) stay unstyled, which renders as nothing.
fn health_style(sled: &SledVersion) -> Style {
    match sled.health {
        Some(SledHealth::Linked) => AnsiColor::Green.on_default(),
        Some(SledHealth::Unlinked) if sled.version.is_some() => AnsiColor::Yellow.on_default(),
        Some(SledHealth::Unlinked) => AnsiColor::Red.on_default(),
        Some(SledHealth::Unknown) | None => Style::new(),
    }
}

/// Draw the rack as wicket does: 16 rows of two cubbies, numbered
/// bottom-to-top and left-to-right per RFD 200, split where the
/// switches and power shelves sit. Sleds known only by build (no
/// cubby) are listed below the rack.
fn draw_rack(sleds: &[SledVersion]) -> String {
    let by_cubby: BTreeMap<u8, &SledVersion> = sleds
        .iter()
        .filter_map(|sled| sled.cubby.map(|cubby| (cubby, sled)))
        .collect();
    let row = |row: u8| {
        let (left, right) = (2 * row, 2 * row + 1);
        format!(
            "{left:>3} │{}│{}│ {right}\n",
            rack_cell(by_cubby.get(&left).copied()),
            rack_cell(by_cubby.get(&right).copied()),
        )
    };
    let bar = "─".repeat(CELL);
    let mut out = format!("    ┌{bar}┬{bar}┐\n");
    for r in (8..16).rev() {
        out.push_str(&row(r));
    }
    out.push_str(&format!("    ├{bar}┼{bar}┤\n"));
    for r in (0..8).rev() {
        out.push_str(&row(r));
    }
    out.push_str(&format!("    └{bar}┴{bar}┘\n"));
    for sled in sleds
        .iter()
        .filter(|sled| sled.cubby.is_none_or(|cubby| cubby > MAX_CUBBY))
    {
        out.push_str(&format!(" ?? │{}│\n", rack_cell(Some(sled))));
    }
    out
}

#[cfg(test)]
mod rack {
    use std::env;
    use std::fs::{read_to_string, write};

    use super::*;

    fn sled(cubby: u8, serial: &str) -> SledVersion {
        SledVersion {
            cubby: Some(cubby),
            baseboard: BaseboardId {
                part_number: "913-0000019".to_string(),
                serial_number: serial.to_string(),
            },
            version: Some(VersionInfo {
                version: "0.1.0".to_string(),
                commit: "f078e863b17359031de072222bb631270f2d5157".to_string(),
            }),
            health: None,
        }
    }

    #[test]
    fn rack_drawing() {
        let mut sleds = vec![
            sled(14, "BRM42220030"),
            sled(15, "BRM42220036"),
            sled(16, "2CN2M459"),
            sled(17, "2RGCFG10"),
        ];
        sleds.push(SledVersion {
            cubby: None,
            ..sled(0, "STRAGGLER")
        });
        sleds.push(sled(32, "MISCUBBIED"));
        sleds[2].version = None;
        if let Some(version) = &mut sleds[1].version {
            version.commit.push_str("-dirty");
        }
        check(&draw_rack(&sleds), "tests/output/rack.txt");
    }

    /// A healthy sled, a silent one, and one that is only a cubby
    /// number, pinning the color codes.
    #[test]
    fn rack_drawing_health() {
        let mut sleds = vec![
            sled(14, "BRM42220030"),
            sled(15, "BRM42220036"),
            sled(16, "2CN2M459"),
        ];
        sleds[0].health = Some(SledHealth::Linked);
        sleds[1].health = Some(SledHealth::Unlinked);
        sleds[2].health = Some(SledHealth::Unlinked);
        sleds[2].version = None;
        check(&draw_rack(&sleds), "tests/output/rack-health.txt");
    }

    /// Compare against the snapshot at `path`, or rewrite it under
    /// `EXPECTORATE=overwrite`.
    fn check(drawing: &str, path: &str) {
        if env::var("EXPECTORATE").as_deref() == Ok("overwrite") {
            write(path, drawing).unwrap();
        } else {
            let expected = read_to_string(path).expect("missing snapshot");
            assert_eq!(drawing, expected, "rack drawing changed:\n{drawing}");
        }
    }
}
