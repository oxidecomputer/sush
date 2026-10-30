// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Read, evaluate, print, loop.
//!
//! Inherits most of its behavior from the (non-interactive) CLI.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{Permissions, set_permissions};
use std::os::unix::fs::PermissionsExt as _;

use clap::{ArgMatches, CommandFactory as _, FromArgMatches as _, Parser};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use shlex::split as split_command;
use sled_hardware_types::BaseboardId;
use x509_cert::Certificate;

use sush_common::authn::Identity;
use sush_common::jobs::{
    Access, JobId, JobOutputStream, JobStartRequest, JobStatusMap, Session, SessionClientNonce,
    SessionId, SessionSeq, SessionSignerNonce, SessionSushNonce, SignedJob,
};
use sush_common::keys::{KeyId, SshPublicKey};
use sush_common::targets::{SledId, SledVersion};
use sush_common::version::VersionInfo;

use crate::cli::Cli;
use crate::commands::{ClientCommand, CommandError, GlobalArgs};
use crate::config::{ConfigOptions, SuppliedOptions, parse_with_config};
use crate::context::{CommandContext, OutputFormat, StartedDisplay, StatusDisplayStyle};
use crate::{AuthzSigner, PREFIX, base_directories};

const HISTORY_FILE: &str = "history.txt";

#[derive(Debug, Parser)]
#[command(multicall = true)]
struct ReplCommandParser {
    #[clap(subcommand)]
    command: ClientCommand,
}

impl ReplCommandParser {
    /// Parse `words`, taking defaults from `options`.
    fn try_parse<I, T>(words: I, options: &ConfigOptions) -> Result<Self, CommandError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let command = Self::command();
        let matches = parse_with_config(command.clone(), words, options)?;
        let mut parsed = Self::from_arg_matches(&matches)?;
        if let ClientCommand::Set { args } = &mut parsed.command
            && let Some((name, matches)) = matches.subcommand()
            && let Some(set) = command.find_subcommand(name)
        {
            args.supplied = SuppliedOptions::from_matches(set, matches);
        }
        Ok(parsed)
    }
}

/// Interactive REPL context.
#[derive(Clone, Debug, Default)]
pub struct Repl {
    /// The underlying CLI context. Most methods forward to this.
    cli: Cli,

    /// Configuration options for the selected profile.
    config: ConfigOptions,

    /// Global options explicitly supplied on the command line.
    supplied: SuppliedOptions,

    /// The default for job ID arguments.
    last_job_id: Option<JobId>,
}

impl Repl {
    pub async fn run(mut self, args: GlobalArgs) -> Result<(), CommandError> {
        self.cli.load_session();
        self.config = ConfigOptions::from_supplied(&args.supplied)?;
        self.supplied = args.supplied;
        let (globals, _) = parse_globals(&self.supplied, &self.config)?;
        self.cli.set_globals(globals);
        self.show_options()?;
        let history_file = base_directories()
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
                    let command = match ReplCommandParser::try_parse(&words, &self.config) {
                        Ok(ReplCommandParser { command }) => command,
                        Err(err) => {
                            self.command_error(&err);
                            continue;
                        }
                    };
                    match command.execute(&mut self).await {
                        Ok(()) => (),
                        Err(CommandError::Quit) => break,
                        Err(err) => self.command_error(&err),
                    }
                }
                Err(ReadlineError::Interrupted) => continue,
                Err(ReadlineError::Eof) => break,
                Err(err) => perr!("❌ Error reading input: {err}"),
            }
        }
        rl.save_history(&history_file)?;
        set_permissions(&history_file, Permissions::from_mode(0o600))
            .map_err(|error| CommandError::io(HISTORY_FILE, error))?;
        Ok(())
    }

    fn apply_options(&mut self, supplied: SuppliedOptions) -> Result<(), CommandError> {
        let config = ConfigOptions::from_supplied(&supplied)?;
        let old = self.get_globals();
        let (globals, _) = parse_globals(&supplied, &config)?;
        if (&old.ssh_auth_sock, &old.ssh_key_id) != (&globals.ssh_auth_sock, &globals.ssh_key_id) {
            self.set_credentials(None);
            self.authz_signer().clear_claim();
        }
        self.supplied = supplied;
        self.config = config;
        self.cli.set_globals(globals);
        self.show_options()
    }

    /// Print each global option that has a value, and its source.
    fn show_options(&self) -> Result<(), CommandError> {
        let (_, matches) = parse_globals(&self.supplied, &self.config)?;
        for line in self.config.describe(&matches) {
            eprintln!("✅ {line}");
        }
        Ok(())
    }

    /// Make a prompt indicating the profile and online/offline status.
    fn prompt(&self, args: &GlobalArgs) -> String {
        let profile = match &args.profile {
            Some(profile) => format!(" [{profile}]"),
            None => String::new(),
        };
        let offline = if args.url.is_some() { "" } else { " (offline)" };
        format!("{PREFIX}{profile}{offline}# ")
    }
}

/// Parse the global options in `supplied`, as if typed on the command
/// line, over the environment and `options`.
fn parse_globals(
    supplied: &SuppliedOptions,
    options: &ConfigOptions,
) -> Result<(GlobalArgs, ArgMatches), CommandError> {
    let matches = parse_with_config(GlobalArgs::command(), supplied.command_line(), options)?;
    let mut globals = GlobalArgs::from_arg_matches(&matches)?;
    globals.supplied = supplied.clone();
    Ok((globals, matches))
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

    fn last_job_id(&self) -> Option<JobId> {
        self.last_job_id
    }

    fn set_options(&mut self, options: SuppliedOptions) -> Result<(), CommandError> {
        let mut supplied = self.supplied.clone();
        supplied.update(&GlobalArgs::command(), &options);
        self.apply_options(supplied)
    }

    fn unset_options(&mut self, long_names: &[String]) -> Result<(), CommandError> {
        let command = GlobalArgs::command();
        let mut supplied = self.supplied.clone();
        for long_name in long_names {
            if !command
                .get_arguments()
                .any(|arg| arg.get_long() == Some(long_name))
            {
                return Err(CommandError::UnknownOption(long_name.to_owned()));
            }
            if !supplied.remove(long_name) {
                return Err(CommandError::OptionNotSet(long_name.to_owned()));
            }
        }
        self.apply_options(supplied)
    }

    // Errors

    fn command_error(&mut self, error: &CommandError) {
        self.cli.command_error(error)
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

    fn pending_client_nonce(&self) -> Option<SessionClientNonce> {
        self.cli.pending_client_nonce()
    }

    fn save_client_nonce(&self, client_nonce: SessionClientNonce) {
        self.cli.save_client_nonce(client_nonce)
    }

    fn session_start_params(
        &self,
        baseboard_id: BaseboardId,
        client_nonce: SessionClientNonce,
        sush_nonce: SessionSushNonce,
    ) {
        self.cli
            .session_start_params(baseboard_id, client_nonce, sush_nonce)
    }

    fn job_start_params(&self, request: &JobStartRequest) {
        self.cli.job_start_params(request)
    }

    fn session_created(
        &mut self,
        session: Session,
        signer_nonce: SessionSignerNonce,
        seq: SessionSeq,
    ) {
        self.cli.session_created(session, signer_nonce, seq)
    }

    fn session_started(&mut self, session: Session, force: bool) {
        self.cli.session_started(session, force)
    }

    fn session_joined(&mut self, session: Session, force: bool) {
        self.cli.session_joined(session, force)
    }

    fn session_stopped(&mut self, session_id: &SessionId) {
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

    // Job management

    fn job_started(
        &mut self,
        job: &SignedJob,
        sleds: Option<&BTreeSet<BaseboardId>>,
        display: StartedDisplay,
    ) {
        self.last_job_id = Some(*job.job_id());
        self.cli.job_started(job, sleds, display);
    }

    fn job_stopped(&mut self, job_id: &JobId) {
        self.last_job_id = Some(*job_id);
        self.cli.job_stopped(job_id);
    }

    fn job_skipped(&mut self, job_id: &JobId) -> bool {
        self.cli.job_skipped(job_id)
    }

    fn job_output(
        &mut self,
        job_id: &JobId,
        target: &BaseboardId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    ) {
        self.last_job_id = Some(*job_id);
        self.cli.job_output(job_id, target, stream, output, binary);
    }

    fn job_output_started(
        &mut self,
        job_id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total: u64,
    ) {
        self.last_job_id = Some(*job_id);
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

    fn job_signing_finished(&mut self, job_id: &JobId, signed: bool) {
        self.cli.job_signing_finished(job_id, signed);
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
        self.last_job_id = Some(*job_id);
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

    #[cfg(feature = "permslip")]
    fn please_authn(&mut self, url: &str) {
        self.cli.please_authn(url)
    }

    fn really_target(&mut self, sled: &SledId) -> Result<(), CommandError> {
        self.cli.really_target(sled)
    }
}
