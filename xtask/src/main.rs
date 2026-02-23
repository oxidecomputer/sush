//! Tasks for developing or building the Oxide Support Shell

use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sush_api::sush_api_mod::stub_api_description;
use sush_common::{OPENAPI_DOCUMENT, OPENAPI_TITLE, OPENAPI_VERSION};

#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    task: XTask,
}

#[derive(Debug, Subcommand)]
enum XTask {
    /// Generate an OpenAPI document from the Support Shell Dropshot API.
    Openapi {
        /// Where to put the generated OpenAPI JSON file.
        #[clap(default_value = OPENAPI_DOCUMENT)]
        path: PathBuf,
    },
}

impl XTask {
    fn execute(self) -> Result<(), String> {
        match self {
            Self::Openapi { path } => {
                eprint!("Generating OpenAPI document `{}`... ", path.display());
                let api = stub_api_description().map_err(|e| e.to_string())?;
                let openapi = api.openapi(OPENAPI_TITLE, OPENAPI_VERSION.parse().unwrap());
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .map_err(|e| e.to_string())?;
                openapi.write(&mut file).map_err(|e| e.to_string())?;
                eprintln!("done!");
                Ok(())
            }
        }
    }
}

fn main() -> ExitCode {
    match Args::parse().task.execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
