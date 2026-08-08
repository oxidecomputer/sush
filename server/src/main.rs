// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command-line interface to the Oxide Support Shell API server.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use dropshot::{ConfigDropshot, ConfigLogging, ConfigLoggingLevel, HandlerTaskMode, ServerBuilder};
use rumors::Peer;
use sled_hardware_types::BaseboardId;
use tokio::signal::unix::{SignalKind, signal};
use tokio::{select, spawn};
use tokio_util::sync::CancellationToken;
use x509_cert::Certificate;
use x509_cert::der::DecodePem as _;

use sush_api::sush_api_mod::api_description;
use sush_server::executor::PathIsolation;
use sush_server::manager::JobManager;
use sush_server::server::ApiServer;

const DEFAULT_ADDRESS: &str = "0.0.0.0:44444";
const ROOT_CERTS: &[&[u8]] = &[
    // export PERMSLIP_URL="https://permslip.inickles.0xeng.dev"
    // export SUSH_PERMSLIP_KEY="UNTRUSTED Support Shell Prototype"
    include_bytes!("../certs/sandbox.pem"),
];
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

    /// Whether to disable $PATH isolation
    ///
    /// Disabling $PATH isolation could be insecure, and must never be done on production.
    #[arg(long, default_value_t = false)]
    insecure_disable_path_isolation: bool,

    /// Root certificates to use to verify signatures
    #[cfg(feature = "test-support")]
    #[arg(long = "root-cert")]
    override_root_certs: Vec<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let ServerArgs {
        address,
        debug,
        directory,
        #[cfg(feature = "test-support")]
        override_root_certs,
        insecure_disable_path_isolation,
    } = ServerArgs::parse();

    let path_isolation = if insecure_disable_path_isolation {
        PathIsolation::InsecureDisable
    } else {
        PathIsolation::Enable
    };

    let log = ConfigLogging::StderrTerminal {
        level: if debug {
            ConfigLoggingLevel::Debug
        } else {
            ConfigLoggingLevel::Info
        },
    }
    .to_logger(ROOT_LOG_NAME)
    .map_err(|e| e.to_string())?;

    // TODO: get actual baseboard ID
    let baseboard = BaseboardId {
        part_number: "a part".to_string(),
        serial_number: "0001".to_string(),
    };

    // TODO: get/seed Rumors network
    let gossip = Peer::seed().into_rumors();

    #[cfg(feature = "test-support")]
    let roots = overridable_root_certs(&override_root_certs)?;
    #[cfg(not(feature = "test-support"))]
    let roots = builtin_root_certs()?;

    let shutdown = listen_for_shutdown()?;
    let mut mgr = JobManager::new(
        log.clone(),
        path_isolation,
        directory,
        baseboard,
        gossip,
        &roots,
        shutdown.clone(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let join = mgr.take_join_handle().expect("should have join handle");

    let api = api_description::<ApiServer>()
        .map_err(|error| format!("failed to get API description: {error}"))?;
    let server = ServerBuilder::new(api, mgr, log)
        .config(ConfigDropshot {
            bind_address: address,
            default_request_body_max_bytes: REQUEST_MAX_BODY_BYTES,
            default_handler_task_mode: HandlerTaskMode::Detached,
            log_headers: vec![],
        })
        .start()
        .map_err(|error| format!("failed to start server: {error}"))?;

    shutdown.cancelled().await;
    server
        .close()
        .await
        .map_err(|error| format!("failed to shutdown server: {error}"))?;
    join.await
        .map_err(|error| format!("failed to wait for manager: {error}"))?;
    Ok(())
}

fn builtin_root_certs() -> Result<Vec<Certificate>, String> {
    ROOT_CERTS
        .iter()
        .map(Certificate::from_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

#[cfg_attr(not(feature = "test-support"), expect(dead_code))]
fn overridable_root_certs(override_root_certs: &[PathBuf]) -> Result<Vec<Certificate>, String> {
    if override_root_certs.is_empty() {
        builtin_root_certs()
    } else {
        override_root_certs
            .iter()
            .map(|path| {
                Certificate::from_pem(&std::fs::read(path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())
            })
            .collect()
    }
}

/// Trigger a cancellation token on receipt of a terminal Unix signal(7).
fn listen_for_shutdown() -> Result<CancellationToken, String> {
    let Ok(mut sighup) = signal(SignalKind::hangup()) else {
        return Err("can't get SIGHUP listener".to_string());
    };
    let Ok(mut sigint) = signal(SignalKind::interrupt()) else {
        return Err("can't get SIGINT listener".to_string());
    };
    let Ok(mut sigterm) = signal(SignalKind::terminate()) else {
        return Err("can't get SIGTERM listener".to_string());
    };
    let shutdown = CancellationToken::new();
    let trigger_shutdown = shutdown.clone();
    spawn(async move {
        loop {
            select! {
                Some(_) = sighup.recv() => (),
                Some(_) = sigint.recv() => (),
                Some(_) = sigterm.recv() => (),
                else => break
            }
            trigger_shutdown.cancel();
        }
    });
    Ok(shutdown)
}
