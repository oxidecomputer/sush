// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Read, evaluate, print, loop.
//!
//! Inherits most of its behavior from the (non-interactive) CLI.

use std::env;
use std::ffi::OsString;
use std::path::Path;

use clap::Parser;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use shlex::split as split_command;
use sled_hardware_types::BaseboardId;
use x509_cert::Certificate;
use xdg::BaseDirectories;

use sush_common::authn::Identity;
use sush_common::jobs::{
    Access, JobId, JobOutputStream, JobStatusMap, Session, SessionId, SignedJob,
};
use sush_common::keys::{KeyId, SshPublicKey};
use sush_common::targets::{SledId, SledVersion};
use sush_common::version::VersionInfo;

use crate::cli::Cli;
use crate::commands::{
    ClientCommand, CommandError, GlobalArgs, SSH_AUTH_SOCK, SUSH_JOB_ID, SUSH_KEY_ID,
    SUSH_OUTPUT_FORMAT, SUSH_URL,
};
use crate::context::{CommandContext, OutputFormat, StatusDisplayStyle};
use crate::types::SessionStartNonce;
use crate::{AuthzSigner, Client};

const PREFIX: &str = "sush";
const HISTORY_FILE: &str = "history.txt";

#[derive(Debug, Parser)]
#[command(multicall = true)]
struct ReplCommandParser {
    #[clap(subcommand)]
    command: ClientCommand,
}

impl ReplCommandParser {
    fn try_parse<I, T, C>(words: I, ctx: &mut C) -> Result<Self, CommandError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
        C: CommandContext,
    {
        let mut words = words.into_iter().peekable();
        if let Some(command) = words.peek()
            && let Ok(command) = command.clone().into().as_os_str().try_into()
        {
            ctx.pre_parse_hook(command);
        }
        Ok(Self::try_parse_from(words)?)
    }
}

/// Interactive REPL context.
#[derive(Clone, Debug, Default)]
pub struct Repl {
    cli: Cli,
}

impl Repl {
    pub async fn run(
        mut self,
        args: GlobalArgs,
        _client: Option<Client>,
    ) -> Result<(), CommandError> {
        self.set_globals(args.clone());
        let xdg = BaseDirectories::with_prefix(PREFIX);
        let history_file = xdg
            .place_state_file(HISTORY_FILE)
            .map_err(|error| CommandError::io(HISTORY_FILE, error))?;
        let mut rl = DefaultEditor::new()?;
        let _ = rl.load_history(&history_file);
        loop {
            macro_rules! perr {
                ($($arg:tt)*) => {{
                    eprintln!($($arg)*);
                    continue;
                }}
            }
            match rl.readline(&self.prompt(&self.get_globals())) {
                Ok(command) => {
                    if command.trim().is_empty() {
                        continue;
                    }
                    rl.add_history_entry(&command)?;
                    let Some(words) = split_command(&command) else {
                        perr!("❌ Invalid quoting in command");
                    };
                    let command = match ReplCommandParser::try_parse(&words, &mut self) {
                        Ok(ReplCommandParser { command }) => command,
                        Err(err) => perr!("{err}"),
                    };
                    match command.execute(&mut self).await {
                        Ok(()) => (),
                        Err(CommandError::Quit) => break,
                        Err(err) => perr!("{err}"),
                    }
                }
                Err(ReadlineError::Interrupted) => continue,
                Err(ReadlineError::Eof) => break,
                Err(err) => perr!("❌ Error reading input: {err}"),
            }
        }
        rl.save_history(&history_file)?;
        Ok(())
    }

    /// Get the default job ID from the `SUSH_JOB_ID` environment variable.
    #[allow(unused)]
    fn default_job_id(&self) -> Option<JobId> {
        env::var(SUSH_JOB_ID)
            .ok()
            .and_then(|job_id| job_id.parse().ok())
    }

    /// (Un)set the `SUSH_JOB_ID` environment variable as a default for
    /// job ID arguments.
    fn set_job_id(&mut self, job_id: Option<JobId>) {
        if let Some(job_id) = job_id {
            unsafe { env::set_var(SUSH_JOB_ID, job_id.to_string()) }
        } else {
            unsafe { env::remove_var(SUSH_JOB_ID) }
        }
    }

    /// Make a prompt indicating online/offline status.
    fn prompt(&self, args: &GlobalArgs) -> String {
        let offline = if args.url.is_some() { "" } else { " (offline)" };
        format!("{PREFIX}{offline}# ")
    }
}

/// Most of these methods simply punt to those of [`Cli`] for display.
/// But we do update local (ephemeral) state in response to some commands.
impl CommandContext for Repl {
    // Context management

    fn get_output_format(&self) -> OutputFormat {
        self.cli.get_output_format()
    }

    fn set_output_format(&mut self, output: OutputFormat) {
        self.cli.set_output_format(output)
    }

    fn get_globals(&self) -> GlobalArgs {
        self.cli.get_globals()
    }

    fn set_globals(&mut self, mut args: GlobalArgs) {
        let GlobalArgs {
            mut output,
            json,
            text,
            mut url,
            offline,
            ssh_auth_sock,
            ssh_key_id,
            proxy_roots: _,
        } = args;
        if json {
            output = Some(OutputFormat::Json);
        } else if text {
            output = Some(OutputFormat::Text);
        }
        if offline {
            url = None;
        }
        if ssh_auth_sock.is_some() || ssh_key_id.is_some() {
            self.set_credentials(None);
        }

        macro_rules! set_or_unset {
            ($arg:ident, $var:expr, $name:literal) => {{
                if let Some(arg) = $arg {
                    unsafe { env::set_var($var, arg.to_string()) }
                    args.$arg = Some(arg.clone());
                    println!("✅ {} set to `{}`", $name, arg);
                } else {
                    unsafe { env::remove_var($var) }
                    args.$arg = None;
                    println!("✅ {} unset", $name);
                }
            }};
        }
        set_or_unset!(output, SUSH_OUTPUT_FORMAT, "Output format");
        set_or_unset!(url, SUSH_URL, "Server URL");
        set_or_unset!(ssh_auth_sock, SSH_AUTH_SOCK, "SSH agent socket");
        set_or_unset!(ssh_key_id, SUSH_KEY_ID, "SSH key ID");

        self.cli.set_globals(args);
    }

    // Build provenance

    fn versions(
        &mut self,
        client: &VersionInfo,
        server: Option<&VersionInfo>,
        sleds: &[SledVersion],
    ) {
        self.cli.versions(client, server, sleds)
    }

    // Session management

    fn authz_signer(&self) -> AuthzSigner {
        self.cli.authz_signer()
    }

    fn session_id(&self) -> Option<SessionId> {
        self.cli.session_id()
    }

    fn next_job_id(&self) -> Result<JobId, CommandError> {
        self.cli.next_job_id()
    }

    fn session_start_params(
        &self,
        baseboard_id: BaseboardId,
        nonce: SessionStartNonce,
    ) -> Result<(), CommandError> {
        self.cli.session_start_params(baseboard_id, nonce)
    }

    fn session_started(&mut self, session: Session) -> Result<(), CommandError> {
        self.cli.session_started(session)
    }

    fn session_stopped(&mut self, session_id: &SessionId) -> Result<(), CommandError> {
        self.cli.session_stopped(session_id)
    }

    fn attach_allowed(&mut self, key_id: &KeyId, access: Access) {
        self.cli.attach_allowed(key_id, access)
    }

    fn attach_denied(&mut self, key_id: &KeyId) {
        self.cli.attach_denied(key_id)
    }

    // Job signing certificates

    fn cert_chain(
        &mut self,
        key_id: KeyId,
        certs: &str,
        roots: &[Certificate],
    ) -> Result<Certificate, CommandError> {
        self.cli.cert_chain(key_id, certs, roots)
    }

    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError> {
        self.cli.cert_imported(path, key_id)
    }

    // Job management

    fn job_started(&mut self, job: &SignedJob) {
        self.set_job_id(Some(job.job_id().to_owned()));
        self.cli.job_started(job);
    }

    fn job_stopped(&mut self, job_id: &JobId) {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_stopped(job_id);
    }

    fn job_skipped(&mut self, job_id: &JobId) -> bool {
        self.cli.job_skipped(job_id)
    }

    fn job_error(&mut self, error: CommandError) -> CommandError {
        self.cli.job_error(error)
    }

    fn job_output_target(&mut self, target: &BaseboardId) {
        self.cli.job_output_target(target)
    }

    fn job_output(&mut self, job_id: &JobId, stream: JobOutputStream, output: &[u8], binary: bool) {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_output(job_id, stream, output, binary);
    }

    fn job_output_started(
        &mut self,
        job_id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total: u64,
    ) {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_output_started(job_id, stream, stage, total);
    }

    fn job_output_update(&mut self, job_id: &JobId, stream: JobOutputStream, length: u64) {
        self.cli.job_output_update(job_id, stream, length);
    }

    fn job_output_finished(
        &mut self,
        job_id: &JobId,
        stream: JobOutputStream,
        stage: Option<&str>,
    ) {
        self.cli.job_output_finished(job_id, stream, stage);
    }

    fn job_attached(&mut self, job_id: &JobId) {
        self.cli.job_attached(job_id);
    }

    fn job_detached(&mut self, job_id: &JobId) {
        self.cli.job_detached(job_id);
    }

    fn job_signing_started(&mut self, job_id: &JobId) {
        self.cli.job_signing_started(job_id);
    }

    fn job_signing_update(&mut self, job_id: &JobId) {
        self.cli.job_signing_update(job_id);
    }

    fn job_signing_finished(&mut self, job_id: &JobId) {
        self.cli.job_signing_finished(job_id);
    }

    fn job_signed(&mut self, job: &SignedJob, show: bool) {
        self.cli.job_signed(job, show);
    }

    fn job_watch_started(&mut self, job_id: &JobId) {
        self.cli.job_watch_started(job_id)
    }

    fn job_watch_update(&mut self, status: &JobStatusMap) {
        self.cli.job_watch_update(status)
    }

    fn job_watch_stalled(&mut self, job_id: &JobId) {
        self.cli.job_watch_stalled(job_id)
    }

    fn job_watch_finished(&mut self, job_id: &JobId) {
        self.cli.job_watch_finished(job_id)
    }

    fn job_status(&mut self, job_id: &JobId, status: &JobStatusMap, style: StatusDisplayStyle) {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_status(job_id, status, style);
    }

    fn read_signed_job(&mut self) -> Result<SignedJob, CommandError> {
        self.cli.read_signed_job()
    }

    // SSH agent and identity

    fn iam(&mut self, identity: &Identity) -> Result<(), CommandError> {
        self.cli.iam(identity)
    }

    fn identities(&mut self, identities: &[SshPublicKey]) -> Result<(), CommandError> {
        self.cli.identities(identities)
    }

    fn please_touch(&mut self, identity: &SshPublicKey) -> Result<(), CommandError> {
        self.cli.please_touch(identity)
    }

    fn really_target(&mut self, sled: &SledId) -> Result<(), CommandError> {
        self.cli.really_target(sled)
    }

    fn really_revoke(&mut self, what: &str, key_id: KeyId) -> Result<KeyId, CommandError> {
        self.cli.really_revoke(what, key_id)
    }

    fn revoked(&mut self, what: &str, key_id: KeyId) -> Result<(), CommandError> {
        self.cli.revoked(what, key_id)
    }
}
