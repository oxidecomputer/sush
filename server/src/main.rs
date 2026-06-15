//! Command-line interface to the Oxide Support Shell API server.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use dropshot::{ConfigDropshot, ConfigLogging, ConfigLoggingLevel, HandlerTaskMode, ServerBuilder};

use sush_api::sush_api_mod::api_description;
use sush_server::manager::JobManager;
use sush_server::server::ApiServer;

const DEFAULT_ADDRESS: &str = "0.0.0.0:44444";
const ROOT_LOG_NAME: &str = "sush";
const REQUEST_MAX_BODY_BYTES: usize = 0xFFFF;

#[derive(Parser)]
#[clap(name = "Oxide Support Shell Server")]
#[clap(author = "Oxide Computer Company")]
struct ServerArgs {
    /// Address for HTTP API listener
    #[arg(short = 'a', long, default_value_t = DEFAULT_ADDRESS.parse().unwrap())]
    address: SocketAddr,

    /// Enable debug log messages
    #[arg(short = 'D', long, default_value_t = false)]
    debug: bool,

    /// Path to the job output directory
    #[arg(short = 'o', long, default_value = ".")]
    directory: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let ServerArgs {
        address,
        debug,
        directory,
    } = ServerArgs::parse();
    let log = ConfigLogging::StderrTerminal {
        level: if debug {
            ConfigLoggingLevel::Debug
        } else {
            ConfigLoggingLevel::Info
        },
    }
    .to_logger(ROOT_LOG_NAME)
    .map_err(|e| e.to_string())?;

    let mgr = JobManager::new(log.clone(), &directory)
        .await
        .map_err(|e| e.to_string())?;

    let api = api_description::<ApiServer>()
        .map_err(|error| format!("failed to get API description: {error}"))?;
    ServerBuilder::new(api, mgr, log)
        .config(ConfigDropshot {
            bind_address: address,
            default_request_body_max_bytes: REQUEST_MAX_BODY_BYTES,
            default_handler_task_mode: HandlerTaskMode::Detached,
            log_headers: vec![],
        })
        .start()
        .map_err(|error| format!("failed to start server: {error}"))?
        .await?;

    Ok(())
}
