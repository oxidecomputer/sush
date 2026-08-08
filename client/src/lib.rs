// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod agent;
pub mod cli;
pub mod commands;
pub mod context;
pub mod identity;
pub mod interactive;
#[cfg(feature = "permslip")]
pub mod permslip;
pub mod repl;

progenitor::generate_api!(
    spec = "../sush.json", // must match `sush_common::OPENAPI_DOCUMENT`
    interface = Builder,
    replace = {
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
