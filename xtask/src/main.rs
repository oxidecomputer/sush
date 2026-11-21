// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Tasks for developing or building the Oxide Support Shell

use std::process::ExitCode;

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::{Parser, Subcommand};
use dropshot_api_manager::{App, Environment, ManagedApi, ManagedApiConfig, ManagedApis};
use dropshot_api_manager_types::{ManagedApiMetadata, Versions};
use sush_api::supported_versions;
use sush_api::sush_api_mod::stub_api_description;
use sush_common::OPENAPI_TITLE;

#[derive(Debug, Parser)]
struct Args {
    #[clap(subcommand)]
    task: XTask,
}

#[derive(Debug, Subcommand)]
enum XTask {
    /// Manage the OpenAPI documents for the Support Shell Dropshot API.
    Openapi(App),
}

fn environment() -> Result<Environment> {
    let workspace_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask should be in the workspace")
        .to_path_buf();
    Environment::new("cargo xtask openapi", workspace_root, "openapi")
}

fn apis() -> Result<ManagedApis> {
    ManagedApis::new(vec![ManagedApi::from(ManagedApiConfig {
        ident: "sush",
        versions: Versions::new_versioned(supported_versions()),
        title: OPENAPI_TITLE,
        metadata: ManagedApiMetadata::default(),
        api_description: stub_api_description,
    })])
}

fn main() -> Result<ExitCode> {
    match Args::parse().task {
        XTask::Openapi(app) => Ok(app.exec(&environment()?, &apis()?)),
    }
}
