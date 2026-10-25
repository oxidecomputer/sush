// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Which sleds a request names.
//!
//! One grammar serves signed job requests, the client, and the proxy:
//! `*` means every sled in the rack, and a comma-separated list names
//! sleds by baseboard ID or cubby number. The sled that accepts a job
//! resolves its target once, to the baseboards it can reach, and every
//! sled runs the job against that resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use schemars::r#gen::SchemaGenerator;
use schemars::schema::Schema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sled_hardware_types::BaseboardId;
use thiserror::Error;

use crate::version::VersionInfo;

/// Baseboards by cubby number, as much of it as is known.
pub type Cubbies = BTreeMap<u8, BaseboardId>;

/// The highest cubby number in a rack.
pub const MAX_CUBBY: u8 = 31;

/// One sled's location, build, and health.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SledVersion {
    pub cubby: Option<u8>,
    pub baseboard: BaseboardId,
    pub version: Option<VersionInfo>,
    #[serde(default)]
    pub health: Option<SledHealth>,
}

/// One sled's gossip link health, as the answering sled sees it. A
/// silent death can lag `Linked` at TCP's pace.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SledHealth {
    /// Attested, holding a live gossip link.
    Linked,
    /// Known by version or cubby, but no live link.
    Unlinked,
    /// A state from a build newer than this one.
    #[serde(other)]
    Unknown,
}

/// The sleds a request names.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum Target {
    #[default]
    All,
    Sleds(Vec<SledId>),
}

/// One sled, named by baseboard or by cubby.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SledId {
    Baseboard(BaseboardId),
    Cubby(u8),
}

/// A target failed to parse.
#[derive(Debug, Error)]
#[error("invalid target `{0}`")]
pub struct InvalidTarget(String);

/// A target names a cubby that no known sled occupies.
#[derive(Debug, Error)]
#[error("no known sled occupies cubby {0}")]
pub struct UnknownCubby(pub u8);

impl Target {
    /// The sleds in `reachable` that this target names, with cubbies
    /// looked up in `cubbies`.
    pub fn resolve(
        &self,
        reachable: &BTreeSet<BaseboardId>,
        cubbies: &Cubbies,
    ) -> Result<BTreeSet<BaseboardId>, UnknownCubby> {
        match self {
            Self::All => Ok(reachable.clone()),
            Self::Sleds(sleds) => {
                let mut named = BTreeSet::new();
                for sled in sleds {
                    named.insert(match sled {
                        SledId::Baseboard(baseboard) => baseboard.clone(),
                        SledId::Cubby(cubby) => {
                            cubbies.get(cubby).ok_or(UnknownCubby(*cubby))?.clone()
                        }
                    });
                }
                Ok(named.intersection(reachable).cloned().collect())
            }
        }
    }

    /// Whether every sled in `sleds` is one this target names. Each cubby
    /// matches any one sled.
    pub fn matches(&self, sleds: &BTreeSet<BaseboardId>) -> bool {
        match self {
            Self::All => true,
            Self::Sleds(named) => {
                let mut baseboards = BTreeSet::new();
                let mut cubbies = BTreeSet::new();
                for sled in named {
                    match sled {
                        SledId::Baseboard(baseboard) => baseboards.insert(baseboard.clone()),
                        SledId::Cubby(cubby) => cubbies.insert(*cubby),
                    };
                }
                sleds.difference(&baseboards).count() <= cubbies.len()
            }
        }
    }

    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    /// A singular target or `None`.
    pub fn single_baseboard(&self) -> Option<&BaseboardId> {
        match self {
            Self::All => None,
            Self::Sleds(sleds) => match sleds.as_slice() {
                [SledId::Baseboard(baseboard)] => Some(baseboard),
                _ => None,
            },
        }
    }
}

impl From<BaseboardId> for Target {
    fn from(baseboard: BaseboardId) -> Self {
        Self::Sleds(vec![SledId::Baseboard(baseboard)])
    }
}

impl FromStr for Target {
    type Err = InvalidTarget;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim() == "*" {
            return Ok(Self::All);
        }
        s.split(',')
            .map(|sled| sled.trim().parse())
            .collect::<Result<_, _>>()
            .map(Self::Sleds)
    }
}

impl FromStr for SledId {
    type Err = InvalidTarget;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            s.parse().ok().filter(|n| *n <= MAX_CUBBY).map(Self::Cubby)
        } else {
            s.parse().map(Self::Baseboard).ok()
        }
        .ok_or_else(|| InvalidTarget(s.to_string()))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("*"),
            Self::Sleds(sleds) => {
                for (i, sled) in sleds.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{sled}")?;
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for SledId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseboard(baseboard) => write!(f, "{baseboard}"),
            Self::Cubby(cubby) => write!(f, "{cubby}"),
        }
    }
}

impl Serialize for Target {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

impl JsonSchema for Target {
    fn schema_name() -> String {
        <String as JsonSchema>::schema_name()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        <String as JsonSchema>::json_schema(generator)
    }

    fn is_referenceable() -> bool {
        <String as JsonSchema>::is_referenceable()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn baseboard(s: &str) -> BaseboardId {
        s.parse().unwrap()
    }

    #[test]
    fn targets_parse() {
        assert_eq!("*".parse::<Target>().unwrap(), Target::All);
        assert_eq!(" * ".parse::<Target>().unwrap(), Target::All);
        assert_eq!(
            "14".parse::<Target>().unwrap(),
            Target::Sleds(vec![SledId::Cubby(14)]),
        );
        assert_eq!(
            "14, 16".parse::<Target>().unwrap(),
            Target::Sleds(vec![SledId::Cubby(14), SledId::Cubby(16)]),
        );
        assert_eq!(
            "913-0000019:BRM42220031,8".parse::<Target>().unwrap(),
            Target::Sleds(vec![
                SledId::Baseboard(baseboard("913-0000019:BRM42220031")),
                SledId::Cubby(8),
            ]),
        );

        for bad in ["", " ", "14,,16", "no-colon", "32", "999", "-1", "*,3"] {
            assert!(bad.parse::<Target>().is_err(), "`{bad}` should not parse");
        }
        assert!("31".parse::<Target>().is_ok());
    }

    #[test]
    fn targets_round_trip() {
        for target in ["*", "14", "14,16", "913-0000019:BRM42220031,8"] {
            assert_eq!(target.parse::<Target>().unwrap().to_string(), target);
        }
        // Display canonicalizes whitespace.
        assert_eq!("14, 16".parse::<Target>().unwrap().to_string(), "14,16");
    }

    #[test]
    fn targets_resolve() {
        let brm31 = baseboard("913-0000019:BRM42220031");
        let brm40 = baseboard("913-0000019:BRM42220040");
        let brm41 = baseboard("913-0000019:BRM42220041");
        let reachable = BTreeSet::from([brm31.clone(), brm40.clone()]);
        let cubbies = Cubbies::from([(14, brm31.clone()), (16, brm41.clone())]);
        let resolve = |target: &str| {
            target
                .parse::<Target>()
                .unwrap()
                .resolve(&reachable, &cubbies)
        };

        assert_eq!(resolve("*").unwrap(), reachable);
        assert_eq!(
            resolve("913-0000019:BRM42220031,913-0000019:BRM42220041").unwrap(),
            BTreeSet::from([brm31.clone()]),
        );
        assert_eq!(resolve("14").unwrap(), BTreeSet::from([brm31]));
        // Cubby 16 holds a sled we cannot reach.
        assert!(resolve("16").unwrap().is_empty());
        assert!(matches!(resolve("14,17"), Err(UnknownCubby(17))));
    }

    #[test]
    fn targets_match() {
        let brm31 = baseboard("913-0000019:BRM42220031");
        let brm40 = baseboard("913-0000019:BRM42220040");
        let both = BTreeSet::from([brm31.clone(), brm40.clone()]);
        let matches = |target: &str, sleds: &BTreeSet<BaseboardId>| {
            target.parse::<Target>().unwrap().matches(sleds)
        };

        assert!(matches("*", &both));
        assert!(matches(
            "913-0000019:BRM42220031",
            &BTreeSet::from([brm31.clone()])
        ));
        assert!(matches("913-0000019:BRM42220031", &BTreeSet::new()));
        assert!(!matches("913-0000019:BRM42220031", &both));
        assert!(matches("14", &BTreeSet::from([brm40.clone()])));
        assert!(!matches("14", &both));
        assert!(matches("913-0000019:BRM42220031,14", &both));
    }
}
