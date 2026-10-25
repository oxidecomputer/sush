// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What we know about the sled and rack on which we're running.

use std::collections::BTreeSet;

use sled_hardware_types::BaseboardId;

use sush_common::jobs::SignedJob;
use sush_common::targets::Cubbies;
use sush_common::version::{VersionInfo, VersionMap};

#[derive(Debug)]
pub struct Rack {
    /// The ID of the baseboard (sled) this server is running on.
    own_baseboard: BaseboardId,

    /// Sled baseboards by cubby number, as reported by MGS.
    cubbies: Cubbies,

    /// Server versions (*not* message or gossip versions) by sled.
    versions: VersionMap,

    /// Message versions from newer builds, each warned about once.
    unknown_versions: BTreeSet<String>,
}

impl Rack {
    pub fn new(own_baseboard: BaseboardId) -> Self {
        Self {
            versions: [(own_baseboard.clone(), VersionInfo::current())].into(),
            own_baseboard,
            cubbies: Default::default(),
            unknown_versions: Default::default(),
        }
    }

    pub fn runs_here(&self, job: &SignedJob, sleds: &BTreeSet<BaseboardId>) -> bool {
        job.runs_on(&self.own_baseboard, sleds)
    }

    pub fn own_baseboard(&self) -> &BaseboardId {
        &self.own_baseboard
    }

    pub fn cubbies(&self) -> &Cubbies {
        &self.cubbies
    }

    pub fn set_cubbies(&mut self, cubbies: Cubbies) {
        self.cubbies = cubbies;
    }

    pub fn versions(&self) -> &VersionMap {
        &self.versions
    }

    pub fn known_version(&mut self, baseboard: BaseboardId, version: VersionInfo) -> bool {
        // Our own seed is authoritative, and may be newer than a replayed
        // announce from a previous boot.
        if baseboard != self.own_baseboard {
            self.versions.insert(baseboard, version);
            true
        } else {
            false
        }
    }

    pub fn unknown_version(&mut self, version: String) -> bool {
        self.unknown_versions.insert(version)
    }
}
