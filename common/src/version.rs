// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The build's provenance.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The git commit of this build, "-dirty" suffixed when the tree had
/// uncommitted changes.
pub const COMMIT: &str = env!("SUSH_GIT_COMMIT");

/// The package version and commit, as `--version` reports them.
pub const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("SUSH_GIT_COMMIT"),
    ")"
);

/// One build's version and commit.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct VersionInfo {
    /// The package version.
    pub version: String,
    /// The git commit, "-dirty" suffixed for an unclean tree.
    pub commit: String,
}

impl VersionInfo {
    /// This build's info.
    pub fn current() -> Self {
        VersionInfo {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: COMMIT.to_string(),
        }
    }
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.version, self.commit)
    }
}
