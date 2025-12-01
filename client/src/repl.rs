//! Read, evaluate, print, loop.

use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::path::Path;

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use clap::Parser;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use shlex::split as split_command;
use xdg::BaseDirectories;

use sush_common::certs::KeyId;
use sush_common::jobs::{JobId, JobStatus, JobsReserved};

use crate::cli::Cli;
use crate::commands::{ClientArgs, ClientCommand, CommandContext, OutputFormat, SUSH_JOB_ID};

const PREFIX: &str = "sush";
const PROMPT: &str = "sush# ";
const HISTORY_FILE: &str = "history.txt";

#[derive(Debug, Parser)]
#[command(multicall = true)]
struct ReplCommandParser {
    #[clap(subcommand)]
    command: ClientCommand,
}

impl ReplCommandParser {
    fn try_parse<I, T, C>(words: I, ctx: &mut C) -> Result<Self>
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

/// Interactive Read-Evaluate-Print-Loop.
#[derive(Clone, Debug, Default)]
pub struct Repl {
    cli: Cli,
    reserved: Vec<JobId>,
}

impl Repl {
    pub async fn run(mut self, args: &ClientArgs) -> Result<()> {
        let xdg = BaseDirectories::with_prefix(PREFIX);
        let history_file = xdg.place_state_file(HISTORY_FILE)?;
        let mut rl = DefaultEditor::new()?;
        let _ = rl.load_history(&history_file);
        loop {
            match rl.readline(PROMPT) {
                Ok(command) => {
                    if command.trim().is_empty() {
                        continue;
                    }
                    rl.add_history_entry(&command)?;
                    let Some(words) = split_command(&command) else {
                        println!("invalid quoting in command");
                        continue;
                    };
                    let command = match ReplCommandParser::try_parse(&words, &mut self) {
                        Ok(ReplCommandParser { command }) => command,
                        Err(err) => {
                            println!("{err}");
                            continue;
                        }
                    };
                    match command.execute(args, &mut self).await {
                        Ok(()) => (),
                        Err(err) => println!("{err}"),
                    }
                }
                Err(ReadlineError::Interrupted) => continue,
                Err(ReadlineError::Eof) => break,
                Err(err) => {
                    println!("Error reading input: {err}");
                    break;
                }
            }
        }
        rl.save_history(&history_file)?;
        Ok(())
    }

    /// Set the `SUSH_JOB_ID` environment variable to a reserved but unused job
    /// as a default for `--job-id` arguments.
    fn set_job_id(&mut self) {
        if let Ok(job_id) = env::var(SUSH_JOB_ID)
            && let Ok(job_id) = job_id.parse()
        {
            self.remove_job_id(job_id);
        }

        if let Some(job_id) = self.reserved.first() {
            unsafe { env::set_var(SUSH_JOB_ID, job_id.to_string()) }
            println!("✅ Default job ID = {job_id}");
        } else {
            unsafe { env::remove_var(SUSH_JOB_ID) }
            println!("❌ No more reserved job IDs, try `reserve-jobs`");
        }
    }

    /// Note that `job_id` is no longer available.
    fn remove_job_id(&mut self, job_id: JobId) {
        if let Some(i) = self.reserved.iter().position(|&j| j == job_id) {
            self.reserved.remove(i);
        }
    }
}

/// Most of these methods simply punt to those of [`Cli`] for display.
/// But we also update local (ephemeral) state for certain responses.
impl CommandContext for Repl {
    fn get_output_format(&self) -> OutputFormat {
        self.cli.get_output_format()
    }

    fn set_output_format(&mut self, output: OutputFormat) {
        self.cli.set_output_format(output)
    }

    fn pre_parse_hook(&mut self, command: &str) {
        if command == "start" {
            self.set_job_id();
        }
    }

    fn ack(&mut self, reserved: JobsReserved) -> Result<()> {
        self.cli.ack(reserved)
    }

    fn cert_chain(&mut self, key_id: KeyId, certs: &str) -> Result<()> {
        self.cli.cert_chain(key_id, certs)
    }

    fn cert_imported(&mut self, path: &Path, key_id: KeyId) -> Result<()> {
        self.cli.cert_imported(path, key_id)
    }

    fn job_aborted(&mut self, job_id: JobId) -> Result<()> {
        self.cli.job_aborted(job_id)?;
        self.remove_job_id(job_id);
        Ok(())
    }

    fn job_stdout(&mut self, job_id: JobId, output: &[u8], binary: bool) -> Result<()> {
        self.cli.job_stdout(job_id, output, binary)
    }

    fn job_stderr(&mut self, job_id: JobId, errors: &[u8], binary: bool) -> Result<()> {
        self.cli.job_stderr(job_id, errors, binary)
    }

    fn job_status(&mut self, job_id: JobId, status: &JobStatus) -> Result<()> {
        self.cli.job_status(job_id, status)?;
        Ok(())
    }

    fn jobs_reserved(&mut self, number: u8, reserved: &JobsReserved) -> Result<()> {
        self.cli.jobs_reserved(number, reserved)?;
        self.reserved = reserved.job_ids.clone();
        Ok(())
    }

    fn reserved_map(&mut self, reserved: &HashMap<String, DateTime<Utc>>) -> Result<()> {
        self.cli.reserved_map(reserved)?;
        self.reserved = reserved
            .keys()
            .map(|s| s.parse::<JobId>().map_err(|e| anyhow!(e)))
            .collect::<Result<Vec<JobId>, _>>()?;
        Ok(())
    }

    fn revoked(&mut self, revoked: &[JobId]) -> Result<()> {
        self.cli.revoked(revoked)?;
        self.reserved.retain(|j| !revoked.contains(j));
        Ok(())
    }
}
