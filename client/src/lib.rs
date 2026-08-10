// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::{Arc, Mutex};

use reqwest::header::AUTHORIZATION;
use sush_common::authn::AuthnError;

use crate::context::Authz;

pub mod agent;
pub mod cli;
pub mod commands;
pub mod context;
pub mod identity;
pub mod interactive;
#[cfg(feature = "permslip")]
pub mod permslip;
pub mod repl;

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
        JobStatus = sush_common::jobs::JobStatus,
        JobWait = sush_api::JobWait,
        KeyId = sush_common::keys::KeyId,
        Signature = sush_common::keys::Signature,
        SignedForJobStartRequest = sush_common::jobs::SignedJob,
    },
    timeout = 600,
);
