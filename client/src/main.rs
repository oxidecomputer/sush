//! Command-line interface to the Oxide Support Shell.

use clap::Parser as _;

use sush_client::cli::{Cli, CliError};
use sush_client::commands::ClientArgs;

#[tokio::main]
async fn main() -> Result<(), CliError> {
    ClientArgs::parse().execute(&mut Cli::default()).await
}
