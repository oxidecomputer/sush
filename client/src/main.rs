//! Command-line interface to the Oxide Support Shell.

use anyhow::Result;
use clap::Parser as _;

use sush_client::commands::{Cli, ClientArgs};

#[tokio::main]
async fn main() -> Result<()> {
    ClientArgs::parse().execute(&mut Cli::default()).await
}
