// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! SHA3-256 hashing in a BLAKE3 trenchcoat.

use std::fmt;

use hex::FromHexError;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest as _, Sha3_256};

use crate::wire::ExactBytes;

pub const OUT_LEN: usize = 32;

/// A SHA3-256 digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash([u8; OUT_LEN]);

impl Hash {
    pub fn as_bytes(&self) -> &[u8; OUT_LEN] {
        &self.0
    }

    pub fn from_hex(hex: &str) -> Result<Self, FromHexError> {
        let mut bytes = [0; OUT_LEN];
        hex::decode_to_slice(hex, &mut bytes)?;
        Ok(Self(bytes))
    }
}

impl From<[u8; OUT_LEN]> for Hash {
    fn from(bytes: [u8; OUT_LEN]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// Hex for humans, raw bytes for binary formats.
impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let hex = <String as Deserialize>::deserialize(deserializer)?;
            Self::from_hex(&hex).map_err(D::Error::custom)
        } else {
            Ok(Self(deserializer.deserialize_bytes(ExactBytes::<OUT_LEN>)?))
        }
    }
}

pub fn hash(bytes: &[u8]) -> Hash {
    Hash(Sha3_256::digest(bytes).into())
}

/// A byte-counting incremental hasher.
#[derive(Clone, Debug, Default)]
pub struct Hasher {
    inner: Sha3_256,
    count: u64,
}

impl Hasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: &[u8]) -> &mut Self {
        self.inner.update(bytes);
        self.count += bytes.len() as u64;
        self
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn finalize(&self) -> Hash {
        Hash(self.inner.clone().finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST's SHA3-256 short-message vector for the empty message,
    /// both one-shot and incremental, plus the hex round trip.
    #[test]
    fn sha3_256_empty_vector() {
        let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        assert_eq!(hash(&[]).to_string(), expected);

        let mut hasher = Hasher::new();
        hasher.update(b"one").update(b"two");
        assert_eq!(hasher.count(), 6);
        assert_eq!(hasher.finalize(), hash(b"onetwo"));

        assert_eq!(Hash::from_hex(expected).unwrap(), hash(&[]));
        assert!(Hash::from_hex("bogus").is_err());
    }
}
