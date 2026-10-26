// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Arguments;
use std::io::{self, ErrorKind, Write as _, stdout};
use std::process::exit;
use std::sync::{Arc, Mutex};

use reqwest::header::AUTHORIZATION;
use sush_common::authn::AuthnError;

use crate::context::Authz;

/// Like `print!`, but exit quietly if stdout is a closed pipe.
#[macro_export]
macro_rules! qprint {
    ($($arg:tt)*) => {
        $crate::quiet_print(::std::format_args!($($arg)*))
    };
}

/// Like `println!`, but exit quietly if stdout is a closed pipe.
#[macro_export]
macro_rules! qprintln {
    () => {
        $crate::quiet_print(::std::format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::quiet_print(::std::format_args!("{}\n", ::std::format_args!($($arg)*)))
    };
}

#[doc(hidden)]
pub fn quiet_print(args: Arguments<'_>) {
    if let Err(error) = anstream::stdout().lock().write_fmt(args) {
        if error.kind() == ErrorKind::BrokenPipe {
            exit(0);
        }
        panic!("failed printing to stdout: {error}");
    }
}

/// Write `bytes` to standard output (unaltered), but exit quietly if
/// it is a closed pipe.
pub fn quiet_write(bytes: &[u8]) -> io::Result<()> {
    match stdout().lock().write_all(bytes) {
        Err(error) if error.kind() == ErrorKind::BrokenPipe => exit(0),
        result => result,
    }
}

pub mod agent;
pub mod cli;
pub mod commands;
pub mod context;
pub mod identity;
pub mod interactive;
#[cfg(feature = "permslip")]
pub mod permslip;
pub mod repl;
pub mod tls;
pub mod tunnel;

/// Authorization state shared between the command context and the
/// client's pre-send hook, which signs every request with the current
/// ephemeral key once one exists.
#[derive(Clone, Debug, Default)]
pub struct AuthzSigner(Arc<Mutex<Option<Authz>>>);

impl AuthzSigner {
    pub fn get(&self) -> Option<Authz> {
        self.0.lock().unwrap().clone()
    }

    pub fn set(&self, authz: Option<Authz>) {
        *self.0.lock().unwrap() = authz;
    }
}

/// Sign `request` with the current ephemeral key, unless it already
/// carries an `Authorization` header (initial authentication does).
async fn sign_request(
    signer: &AuthzSigner,
    request: &mut reqwest::Request,
) -> Result<(), AuthnError> {
    if request.headers().contains_key(AUTHORIZATION) {
        return Ok(());
    }
    let Some(authz) = signer.get() else {
        return Ok(());
    };
    let url = request.url();
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let header = authz.header(request.method().as_str(), &target);
    let header = header.parse().map_err(|_| AuthnError::InvalidParam)?;
    request.headers_mut().insert(AUTHORIZATION, header);
    Ok(())
}

progenitor::generate_api!(
    spec = "../sush.json", // must match `sush_common::OPENAPI_DOCUMENT`
    interface = Builder,
    inner_type = crate::AuthzSigner,
    pre_hook_async = crate::sign_request,
    replace = {
        Access = sush_common::jobs::Access,
        BaseboardId = sled_hardware_types::BaseboardId,
        Identity = sush_common::authn::Identity,
        Session = sush_common::jobs::Session,
        SessionId = sush_common::jobs::SessionId,
        JobId = sush_common::jobs::JobId,
        JobLimits = sush_common::jobs::JobLimits,
        JobOutputHash = sush_common::jobs::JobOutputHash,
        JobOutputStream = sush_common::jobs::JobOutputStream,
        JobStarted = sush_api::JobStarted,
        JobStatus = sush_common::jobs::JobStatus,
        JobWait = sush_api::JobWait,
        KeyId = sush_common::keys::KeyId,
        Signature = sush_common::keys::Signature,
        SignedForJobStartRequest = sush_common::jobs::SignedJob,
        SessionClientNonce = sush_common::jobs::SessionClientNonce,
        SessionSeq = sush_common::jobs::SessionSeq,
        SessionServerNonce = sush_common::jobs::SessionServerNonce,
        SessionSignerNonce = sush_common::jobs::SessionSignerNonce,
        SledVersion = sush_common::targets::SledVersion,
        JobMode = sush_common::jobs::JobMode,
        VersionInfo = sush_common::version::VersionInfo,
    },
    timeout = 600,
);
