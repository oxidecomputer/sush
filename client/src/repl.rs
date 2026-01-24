//! Read, evaluate, print, loop.
//!
//! Inherits most of its behavior from the (non-interactive) CLI.

use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::Parser;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use shlex::split as split_command;
use xdg::BaseDirectories;

use sush_common::certs::KeyId;
use sush_common::jobs::{JobId, JobOutputStream, JobStatus, JobsReserved, SignedJob};

use crate::Client;
use crate::cli::Cli;
use crate::commands::{
    ClientCommand, CommandContext, CommandError, GlobalArgs, OutputFormat, SUSH_JOB_ID,
    SUSH_OUTPUT_FORMAT, SUSH_URL,
};

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
#[derive(Debug, Default)]
pub struct Repl {
    cli: Cli,
    reserved: Vec<JobId>,
}

impl Repl {
    pub async fn run(
        mut self,
        args: &mut GlobalArgs,
        client: Option<Client>,
    ) -> Result<(), CommandError> {
        if let Some(client) = client {
            let map = client.get_reserved().await?.into_inner();
            self.reserved_map(&map)?;
        }

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
            match rl.readline(&self.prompt(args)) {
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
                    match command.execute(args, &mut self).await {
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

    /// Set the `SUSH_JOB_ID` environment variable to a reserved but unused job.
    fn set_default_job_id(&mut self) {
        self.set_job_id(self.reserved.first().cloned());
    }

    /// Remove `job_id` from the list of reserved jobs.
    fn unreserve_job_id(&mut self, job_id: &JobId) {
        if let Some(i) = self.reserved.iter().position(|j| j == job_id) {
            self.reserved.remove(i);
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
    fn get_output_format(&self) -> OutputFormat {
        self.cli.get_output_format()
    }

    fn set_output_format(&mut self, output: OutputFormat) {
        self.cli.set_output_format(output)
    }

    fn set_globals(&mut self, args: &mut GlobalArgs, values: GlobalArgs) {
        let GlobalArgs {
            mut output,
            json,
            text,
            mut url,
            offline,
        } = values;
        if json {
            output = Some(OutputFormat::Json);
        } else if text {
            output = Some(OutputFormat::Text);
        }
        if offline {
            url = None;
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
    }

    fn pre_parse_hook(&mut self, command: &str) {
        if matches!(command, "job-start" | "start") {
            self.set_default_job_id();
        }
    }

    fn ack(&mut self, url: &str, time: DateTime<Utc>) -> Result<(), CommandError> {
        self.cli.ack(url, time)
    }

    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<(), CommandError> {
        self.cli.cert_chain(key_id, certs)
    }

    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<(), CommandError> {
        self.cli.cert_imported(path, key_id)
    }

    fn job_aborted(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_aborted(job_id)?;
        self.unreserve_job_id(job_id);
        Ok(())
    }

    fn job_output(
        &mut self,
        job_id: &JobId,
        stream: JobOutputStream,
        output: &[u8],
        binary: bool,
    ) -> Result<(), CommandError> {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_output(job_id, stream, output, binary)?;
        Ok(())
    }

    fn job_output_started(
        &mut self,
        job_id: &JobId,
        stream: JobOutputStream,
        stage: &str,
        total: u64,
    ) -> Result<(), CommandError> {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_output_started(job_id, stream, stage, total)
    }

    fn job_output_update(
        &mut self,
        job_id: &JobId,
        stream: JobOutputStream,
        length: u64,
    ) -> Result<(), CommandError> {
        self.cli.job_output_update(job_id, stream, length)
    }

    fn job_output_finished(
        &mut self,
        job_id: &JobId,
        stream: JobOutputStream,
        stage: Option<&str>,
    ) -> Result<(), CommandError> {
        self.cli.job_output_finished(job_id, stream, stage)
    }

    fn job_polling_started(
        &mut self,
        job_id: &JobId,
        duration: Duration,
    ) -> Result<(), CommandError> {
        self.cli.job_polling_started(job_id, duration)
    }

    fn job_polling_update(
        &mut self,
        job_id: &JobId,
        status: &JobStatus,
    ) -> Result<(), CommandError> {
        self.cli.job_polling_update(job_id, status)
    }

    fn job_polling_finished(&mut self, job_id: &JobId) -> Result<(), CommandError> {
        self.cli.job_polling_finished(job_id)
    }

    fn job_status(&mut self, job_id: &JobId, status: &JobStatus) -> Result<(), CommandError> {
        self.set_job_id(Some(job_id.to_owned()));
        self.cli.job_status(job_id, status)?;
        self.unreserve_job_id(job_id);
        Ok(())
    }

    fn job_signed(&mut self, job: &SignedJob) -> Result<(), CommandError> {
        self.cli.job_signed(job)?;
        self.unreserve_job_id(job.job_id());
        Ok(())
    }

    fn jobs_reserved(&mut self, reserved: &JobsReserved) -> Result<(), CommandError> {
        self.cli.jobs_reserved(reserved)?;
        self.reserved = reserved.job_ids.clone();
        Ok(())
    }

    fn reserved_read(&mut self, reserved: &JobsReserved) -> Result<(), CommandError> {
        self.cli.reserved_read(reserved)?;
        self.reserved = reserved.job_ids.clone();
        Ok(())
    }

    fn reserved_map(
        &mut self,
        reserved: &HashMap<String, DateTime<Utc>>,
    ) -> Result<(), CommandError> {
        self.cli.reserved_map(reserved)?;
        self.reserved = reserved.keys().map(JobId::from).collect();
        if let Some(job_id) = self.reserved.first() {
            self.set_job_id(Some(job_id.to_owned()));
        }
        Ok(())
    }

    fn revoked(&mut self, revoked: &[JobId]) -> Result<(), CommandError> {
        self.cli.revoked(revoked)?;
        self.reserved.retain(|j| !revoked.contains(j));
        Ok(())
    }
}
