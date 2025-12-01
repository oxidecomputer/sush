//! Command-line interface to the Oxide Support Shell.

use std::process::ExitCode;

use clap::Parser as _;

use sush_client::cli::Cli;
use sush_client::commands::ClientArgs;

#[tokio::main]
async fn main() -> ExitCode {
    match ClientArgs::parse().execute(&mut Cli::default()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
