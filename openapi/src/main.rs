//! Generate an OpenAPI document from the Dropshot API.

use std::fs::OpenOptions;

use sush_common::{OPENAPI_DOCUMENT, OPENAPI_TITLE, OPENAPI_VERSION};
use sush_server::api::api;

fn main() -> Result<(), String> {
    eprint!("Generating OpenAPI document `{OPENAPI_DOCUMENT}`... ");
    let api = api();
    let openapi = api.openapi(OPENAPI_TITLE, OPENAPI_VERSION.parse().unwrap());
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(OPENAPI_DOCUMENT)
        .map_err(|e| e.to_string())?;
    openapi.write(&mut file).map_err(|e| e.to_string())?;
    eprintln!("done!");
    Ok(())
}
