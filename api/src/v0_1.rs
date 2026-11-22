// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Types defined by API version `0.1.0` and later superseded.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sush_common::jobs::{JobLimits, SessionClientNonce, SessionSeq, SessionSignerNonce};

use crate::{JobWait, deserialize_job_limits};

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SessionStartBody {
    pub client_nonce: SessionClientNonce,
    pub signer_nonce: SessionSignerNonce,
    pub seq: SessionSeq,
}

/// Job parameters _not_ specified in the signed job request.
#[derive(Clone, Debug, Default, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(default)]
pub struct JobStartParams {
    #[serde(flatten, deserialize_with = "deserialize_job_limits")]
    pub limits: JobLimits,

    /// Terminal type for interactive jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,

    /// Terminal window height for interactive jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,

    /// Terminal window width for interactive jobs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,

    /// Wait for the job to start or stop.
    #[serde(skip_serializing_if = "JobWait::is_none")]
    pub wait: JobWait,
}

impl From<JobStartParams> for crate::JobStartParams {
    fn from(params: JobStartParams) -> Self {
        let JobStartParams {
            limits,
            term,
            rows,
            cols,
            wait,
        } = params;
        Self {
            limits,
            term,
            rows,
            cols,
            wait,
            via: None,
        }
    }
}
