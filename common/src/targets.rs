// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Which sleds a request names.
//!
//! One grammar serves signed job requests, the client, and the proxy:
//! `*` means every sled in the rack, and a comma-separated list names
//! sleds by baseboard ID or cubby number. Cubby numbers resolve
//! against a mapping the rack learns at runtime, so a target is
//! evaluated lazily, against what is known when it is asked.

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

/// One sled's location and build.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
pub struct SledVersion {
    pub cubby: Option<u8>,
    pub baseboard: BaseboardId,
    pub version: Option<VersionInfo>,
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

impl Target {
    /// Whether `baseboard` is targeted, as far as `cubbies` can say.
    /// A cubby the mapping does not know targets nothing.
    pub fn includes(&self, baseboard: &BaseboardId, cubbies: &Cubbies) -> bool {
        match self {
            Self::All => true,
            Self::Sleds(sleds) => sleds.iter().any(|sled| match sled {
                SledId::Baseboard(named) => named == baseboard,
                SledId::Cubby(cubby) => cubbies.get(cubby) == Some(baseboard),
            }),
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

    /// Every sled this target names, when it names only baseboards.
    pub fn named_baseboards(&self) -> Option<BTreeSet<&BaseboardId>> {
        match self {
            Self::All => None,
            Self::Sleds(sleds) => sleds
                .iter()
                .map(|sled| match sled {
                    SledId::Baseboard(baseboard) => Some(baseboard),
                    SledId::Cubby(_) => None,
                })
                .collect(),
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
    fn targets_include() {
        let brm31 = baseboard("913-0000019:BRM42220031");
        let brm40 = baseboard("913-0000019:BRM42220040");
        let cubbies = Cubbies::from([(14, brm31.clone())]);

        let all = Target::All;
        assert!(all.includes(&brm31, &cubbies));
        assert!(all.includes(&brm40, &cubbies));

        let by_baseboard: Target = "913-0000019:BRM42220031".parse().unwrap();
        assert!(by_baseboard.includes(&brm31, &cubbies));
        assert!(!by_baseboard.includes(&brm40, &cubbies));

        let by_cubby: Target = "14,16".parse().unwrap();
        assert!(by_cubby.includes(&brm31, &cubbies));
        // Cubby 16 is not in the mapping, so it targets nothing.
        assert!(!by_cubby.includes(&brm40, &cubbies));
        assert!(!by_cubby.includes(&brm40, &Cubbies::new()));
    }
}
