//! Command-line interface to the Oxide Support Shell.

use std::fs::File;
use std::io::Read as _;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;

use sush_client::Client;
use sush_common::certs::KeyId;
use sush_common::jobs::{JobId, JobsReserved};

const DEFAULT_URL: &str = "http://127.0.0.1:44444";

#[derive(Parser)]
#[clap(name = "Oxide Support Shell")]
#[clap(author = "Oxide Computer Company")]
struct ClientArgs {
    /// HTTP API server address
    #[arg(short = 'u', long, default_value_t = DEFAULT_URL.to_string(), env = "SUSH_URL")]
    #[clap(global = true)]
    url: String,

    #[clap(subcommand)]
    command: ClientCommand,
}

#[derive(Subcommand)]
enum ClientCommand {
    /// Import a certificate, verify its signature, and return a key ID for it.
    ImportCert { path: PathBuf },

    /// Get the certificate chain that validates a key, in root-to-leaf order.
    CertChain { key_id: KeyId },

    /// Reserve 0 job slots and display the returned reservation time.
    Ping,

    /// Reserve some job slots with fresh, globally unique IDs.
    Reserve {
        /// How many job slots to reserve.
        number: u8,
    },

    /// Get reserved but unused job slots.
    GetReserved,

    /// Revoke a set of reserved but unused job slots.
    RevokeReserved { job_ids: Vec<JobId> },

    /// Get the status of a started job.
    JobStatus { job_id: JobId },

    /// Get the standard output of a job.
    JobStdout { job_id: JobId },

    /// Get the standard error of a job.
    JobStderr { job_id: JobId },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = ClientArgs::parse();
    let client = Client::new(&args.url);
    match args.command {
        ClientCommand::ImportCert { path } => {
            let mut file = File::open(path)?;
            let mut cert = Vec::new();
            file.read_to_end(&mut cert)?;
            let key_id = client.import_cert(&cert).await?.into_inner();
            println!("{}", json!(key_id));
        }
        ClientCommand::CertChain { key_id } => {
            let chain = client.cert_chain(&key_id).await?.into_inner();
            println!("{}", json!([chain]));
        }
        ClientCommand::Ping => {
            let JobsReserved {
                job_ids,
                time_reserved,
            } = client.reserve_jobs(0).await?.into_inner();
            assert!(job_ids.is_empty());
            println!("{}", json!({"ack": time_reserved}));
        }
        ClientCommand::Reserve { number } => {
            let reserved = client.reserve_jobs(number).await?.into_inner();
            assert_eq!(reserved.job_ids.len(), number as usize);
            println!("{}", serde_json::to_string(&reserved).unwrap());
        }
        ClientCommand::GetReserved => {
            let reserved = client.get_reserved().await?.into_inner();
            println!("{}", serde_json::to_string(&reserved).unwrap());
        }
        ClientCommand::RevokeReserved { job_ids } => {
            let nrevoked = client.revoke_reserved(&job_ids).await?.into_inner();
            println!("{}", serde_json::to_string(&nrevoked).unwrap());
        }
        ClientCommand::JobStatus { job_id } => {
            let status = client.job_status(&job_id).await?.into_inner();
            println!("{}", serde_json::to_string(&status).unwrap());
        }
        ClientCommand::JobStdout { job_id } => {
            let stdout = client.job_stdout(&job_id).await?.into_inner();
            print!("{}", String::from_utf8_lossy(&stdout));
        }
        ClientCommand::JobStderr { job_id } => {
            let stderr = client.job_stderr(&job_id).await?.into_inner();
            print!("{}", String::from_utf8_lossy(&stderr));
        }
    }
    Ok(())
}
