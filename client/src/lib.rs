// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Arguments;
use std::io::{self, ErrorKind, Write as _, stdout};
use std::process::exit;
use std::sync::{Arc, Mutex};

use reqwest::header::AUTHORIZATION;
use sush_common::authn::{AuthnError, BoundCredentials};
use sush_common::keys::KeyId;
use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};

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
pub struct AuthzSigner(Arc<AuthzState>);

#[derive(Debug, Default)]
struct AuthzState {
    /// The current authorization, and how many times it has been set.
    authz: Mutex<(Option<Authz>, u64)>,

    /// The key ID to claim in requests made before logging in.
    claim: Mutex<Option<KeyId>>,

    /// Held during a login. When the server refuses several concurrent
    /// requests, the first to take this lock logs in, and the others
    /// retry with its credentials.
    login: AsyncMutex<()>,
}

impl AuthzSigner {
    pub fn get(&self) -> Option<Authz> {
        self.0.authz.lock().unwrap().0.clone()
    }

    pub fn set(&self, authz: Option<Authz>) {
        let mut guard = self.0.authz.lock().unwrap();
        guard.0 = authz;
        guard.1 += 1;
    }

    pub fn claim(&self) -> Option<KeyId> {
        self.0.claim.lock().unwrap().clone()
    }

    pub fn set_claim(&self, key_id: KeyId) {
        *self.0.claim.lock().unwrap() = Some(key_id);
    }

    pub fn clear_claim(&self) {
        *self.0.claim.lock().unwrap() = None;
    }

    /// How many times the authorization has been set.
    pub fn generation(&self) -> u64 {
        self.0.authz.lock().unwrap().1
    }

    /// Wait for any login in progress. Return the login guard if the
    /// authorization has not been set since `generation`, or `None` if
    /// another login set it.
    pub async fn login_needed(&self, generation: u64) -> Option<AsyncMutexGuard<'_, ()>> {
        let login = self.0.login.lock().await;
        (self.generation() == generation).then_some(login)
    }
}

/// Sign `request` with the login's ephemeral key. Before logging in,
/// only claim the key that will log in.
async fn sign_request(
    signer: &AuthzSigner,
    request: &mut reqwest::Request,
) -> Result<(), AuthnError> {
    // A login request carries its own credentials.
    if request.headers().contains_key(AUTHORIZATION) {
        return Ok(());
    }
    let header = if let Some(authz) = signer.get() {
        authz.sign(request.method().as_str(), &request_target(request.url()))
    } else if let Some(key_id) = signer.claim() {
        BoundCredentials::claim(key_id).to_string()
    } else {
        return Ok(());
    };
    let header = header.parse().map_err(|_| AuthnError::InvalidParam)?;
    request.headers_mut().insert(AUTHORIZATION, header);
    Ok(())
}

/// Format the path and query of `url` exactly as sent. The proxy
/// verifies the request signature against these bytes.
fn request_target(url: &reqwest::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
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
