// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! What we know about the sled and rack on which we're running.

use std::collections::BTreeSet;

use sled_hardware_types::BaseboardId;

use sush_common::jobs::{JobStartRequest, SkipReason};
use sush_common::targets::Cubbies;
use sush_common::version::{VersionInfo, VersionMap};

#[derive(Debug)]
pub struct Rack {
    /// The ID of the baseboard (sled) this server is running on.
    own_baseboard: BaseboardId,

    /// The cubby this sled occupies, once MGS has reported it.
    /// Does not change once known, since a sled cannot change
    /// cubbies without rebooting.
    own_cubby: Option<u8>,

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
            own_cubby: None,
            cubbies: Default::default(),
            unknown_versions: Default::default(),
        }
    }

    /// Why `job` should not run on this sled, or `None` if it should.
    /// The sled that accepted the job resolved its target to this sled,
    /// but that resolution is unsigned so we must check it ourselves.
    pub fn check_target(&self, job: &JobStartRequest) -> Option<SkipReason> {
        let target = job.target();
        if job.target_matches_mode() && target.matches(&self.own_baseboard, self.own_cubby) {
            None
        } else if self.own_cubby.is_none() {
            Some(SkipReason::CubbyUnknown)
        } else {
            Some(SkipReason::NotTargeted)
        }
    }

    pub fn own_baseboard(&self) -> &BaseboardId {
        &self.own_baseboard
    }

    pub fn cubbies(&self) -> &Cubbies {
        &self.cubbies
    }

    pub fn set_cubbies(&mut self, cubbies: Cubbies) {
        if let Some((&cubby, _)) = cubbies
            .iter()
            .find(|(_, baseboard)| **baseboard == self.own_baseboard)
        {
            self.own_cubby = Some(cubby);
        }
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

#[cfg(test)]
mod test {
    use sush_common::jobs::{JobId, JobMode, SessionId};
    use sush_common::targets::Target;

    use super::*;

    #[test]
    fn check_target() {
        let me: BaseboardId = "913-0000019:BRM42220031".parse().unwrap();
        let mut rack = Rack::new(me.clone());
        let check_target = |rack: &Rack, mode, target: &str| {
            rack.check_target(&JobStartRequest::new(
                JobId::random(),
                SessionId::random(),
                "true",
                mode,
                target.parse::<Target>().unwrap(),
            ))
        };

        use JobMode::*;
        use SkipReason::*;

        // Before this sled knows its cubby.
        assert_eq!(check_target(&rack, Batch, "*"), None);
        assert_eq!(check_target(&rack, Batch, "913-0000019:BRM42220031"), None);
        assert_eq!(check_target(&rack, Batch, "14"), Some(CubbyUnknown));

        // Once a cubby map places this sled in cubby 14, the sled keeps
        // that cubby, even after a later map that omits it.
        rack.set_cubbies(Cubbies::from([(14, me.clone())]));
        rack.set_cubbies(Cubbies::new());
        assert_eq!(check_target(&rack, Batch, "14"), None);
        assert_eq!(check_target(&rack, Batch, "15"), Some(NotTargeted));
        assert_eq!(
            check_target(&rack, Batch, "913-0000019:BRM42220040"),
            Some(NotTargeted)
        );

        // Interactive jobs run only on the single sled they target.
        assert_eq!(
            check_target(&rack, Interactive, "913-0000019:BRM42220031"),
            None
        );
        assert_eq!(check_target(&rack, Interactive, "14"), None);
        assert_eq!(check_target(&rack, Interactive, "15"), Some(NotTargeted));
        assert_eq!(check_target(&rack, Interactive, "*"), Some(NotTargeted));
        assert_eq!(
            check_target(&rack, Interactive, "913-0000019:BRM42220031,14"),
            Some(NotTargeted)
        );
    }
}
