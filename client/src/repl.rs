//! Read, evaluate, print, loop.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::Parser;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use shlex::split as split_command;
use xdg::BaseDirectories;

use sush_common::certs::KeyId;
use sush_common::jobs::{JobId, JobStatus, JobsReserved};

use crate::commands::{Cli, ClientArgs, ClientCommand, CommandContext, OutputFormat};

const PREFIX: &str = "sush";
const PROMPT: &str = "sush# ";
const HISTORY_FILE: &str = "history.txt";

#[derive(Debug, Parser)]
#[command(multicall = true)]
struct ClientCommandParser {
    #[clap(subcommand)]
    command: ClientCommand,
}

/// Interactive Read-Evaluate-Print-Loop.
#[derive(Clone, Debug, Default)]
struct Repl {
    cli: Cli,
}

impl CommandContext for Repl {
    fn get_output_format(&self) -> OutputFormat {
        self.cli.get_output_format()
    }

    fn set_output_format(&mut self, output: OutputFormat) {
        self.cli.set_output_format(output)
    }

    fn ack(&self, reserved: JobsReserved) -> Result<()> {
        self.cli.ack(reserved)
    }

    fn cert_chain(&self, key_id: KeyId, certs: String) -> Result<()> {
        self.cli.cert_chain(key_id, certs)
    }

    fn cert_imported(&self, path: &Path, key_id: KeyId) -> Result<()> {
        self.cli.cert_imported(path, key_id)
    }

    fn job_aborted(&self, job_id: JobId) -> Result<()> {
        self.cli.job_aborted(job_id)
    }

    fn job_output(&self, output: Vec<u8>, binary: bool) -> Result<()> {
        self.cli.job_output(output, binary)
    }

    fn job_status(&self, job_id: JobId, status: JobStatus) -> Result<()> {
        self.cli.job_status(job_id, status)
    }

    fn jobs_reserved(&self, number: u8, reserved: JobsReserved) -> Result<()> {
        self.cli.jobs_reserved(number, reserved)
    }

    fn reserved_map(&self, reserved: HashMap<String, DateTime<Utc>>) -> Result<()> {
        self.cli.reserved_map(reserved)
    }

    fn revoked(&self, nrevoked: u64) -> Result<()> {
        self.cli.revoked(nrevoked)
    }
}

pub async fn repl(args: &ClientArgs) -> Result<()> {
    let xdg = BaseDirectories::with_prefix(PREFIX);
    let history_file = xdg.place_state_file(HISTORY_FILE)?;
    let mut rl = DefaultEditor::new()?;
    let _ = rl.load_history(&history_file);
    let mut ctx = Repl::default();
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
                let command = match ClientCommandParser::try_parse_from(&words) {
                    Ok(ClientCommandParser { command }) => command,
                    Err(err) => {
                        println!("{err}");
                        continue;
                    }
                };
                match command.execute(args, &mut ctx).await {
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
