//! Command-line interface to the Oxide Support Shell API server.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use clap::builder::PathBufValueParser;
use dropshot::{ConfigDropshot, ConfigLogging, ConfigLoggingLevel, HandlerTaskMode, ServerBuilder};

use sush_common::database::open_database;
use sush_server::api::api;
use sush_server::manager::JobManager;

const DEFAULT_ADDRESS: &str = "0.0.0.0:44444";
const DEFAULT_DATABASE: &str = "sush.db";
const ROOT_LOG_NAME: &str = "sush";
const REQUEST_MAX_BODY_BYTES: usize = 0xFFFF;

#[derive(Parser)]
#[clap(name = "Oxide Support Shell Server")]
#[clap(author = "Oxide Computer Company")]
struct ServerArgs {
    /// Address for HTTP API listener
    #[arg(short = 'a', long, default_value_t = DEFAULT_ADDRESS.parse().unwrap())]
    address: SocketAddr,

    /// Path to the jobs database
    #[arg(short = 'd', long, default_value = DEFAULT_DATABASE, value_parser = PathBufValueParser::new())]
    database: PathBuf,

    /// Enable debug log messages
    #[arg(short = 'D', long, default_value_t = false)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let args = ServerArgs::parse();
    let log = ConfigLogging::StderrTerminal {
        level: if args.debug {
            ConfigLoggingLevel::Debug
        } else {
            ConfigLoggingLevel::Info
        },
    }
    .to_logger(ROOT_LOG_NAME)
    .map_err(|e| e.to_string())?;

    let db = open_database(args.database).map_err(|e| e.to_string())?;
    let mgr = JobManager::new(db).await.map_err(|e| e.to_string())?;
    ServerBuilder::new(api(), mgr, log)
        .config(ConfigDropshot {
            bind_address: args.address,
            default_request_body_max_bytes: REQUEST_MAX_BODY_BYTES,
            default_handler_task_mode: HandlerTaskMode::Detached,
            log_headers: vec![],
        })
        .start()
        .map_err(|error| format!("failed to start server: {}", error))?
        .await?;
    Ok(())
}
