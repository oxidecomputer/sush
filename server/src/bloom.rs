// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A fixed-size Bloom filter for durable, grow-only sets.
//!
//! Designed for the boundary record's burned networks set. Entries may
//! never be dropped (once burned, a network stays burned), the size must
//! stay bounded under adversarial growth (we must not fill the M.2s),
//! and the filter may err only by claiming a key it never held. The
//! caller must treat that claim as refusal.
//!
//! The layout and hash algorithm determine the on-disk format, and must
//! not be changed without updating the boundary record's magic. Each key
//! probes the table at seven positions, cut as 16-bit words from its
//! SHA3-256 digest. The table is currently sized at 8192 bits, for
//! which seven probes is the optimal count out to about 800 entries
//! (bits * ln 2 / probes). The false positive rate there is about 0.7%,
//! degrading gradually past it. Real occupancy should stay in the tens,
//! where false positives are negligible.

use std::array::from_fn;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use sush_common::hash::{OUT_LEN, hash};
use sush_common::wire::ExactBytes;

const BYTES: usize = 1024;
const BITS: u64 = (BYTES * 8) as u64;
const PROBES: usize = 7;

// The probes must fit in the digest, and the table size must divide
// 2^16, or reducing a 16-bit word to a table slot would favor some
// slots over others.
const _: () = {
    assert!(2 * PROBES <= OUT_LEN);
    assert!((1u64 << 16).is_multiple_of(BITS));
};

/// A grow-only set of byte-string keys.
#[derive(Clone, Eq, PartialEq)]
pub struct Bloom {
    bits: Box<[u8; BYTES]>,
}

/// The probe positions for `key` are seven 16-bit words cut from
/// the leading bytes of the key's SHA3-256 digest, each reduced to
/// a table slot.
fn probes(key: &[u8]) -> [u64; PROBES] {
    let digest = *hash(key).as_bytes();
    from_fn(|i| {
        let j = 2 * i;
        let word = u16::from_le_bytes(digest[j..j + 2].try_into().expect("two bytes"));
        u64::from(word) % BITS
    })
}

/// The byte index and mask selecting `probe`'s bit.
fn bit(probe: u64) -> (usize, u8) {
    ((probe / 8) as usize, 1 << (probe % 8))
}

impl Bloom {
    pub fn new() -> Self {
        Self {
            bits: Box::new([0; BYTES]),
        }
    }

    /// Permanently add `key` to the set.
    pub fn insert(&mut self, key: &[u8]) {
        for (byte, mask) in probes(key).map(bit) {
            self.bits[byte] |= mask;
        }
    }

    /// Whether `key` may have been inserted. Never returns a false negative,
    /// but false positives occur at the documented rate.
    pub fn contains(&self, key: &[u8]) -> bool {
        probes(key)
            .map(bit)
            .into_iter()
            .all(|(byte, mask)| self.bits[byte] & mask != 0)
    }
}

impl Default for Bloom {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Bloom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set: u32 = self.bits.iter().map(|byte| byte.count_ones()).sum();
        write!(f, "Bloom({set}/{BITS} bits set)")
    }
}

impl Serialize for Bloom {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bits[..])
    }
}

impl<'de> Deserialize<'de> for Bloom {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = deserializer.deserialize_bytes(ExactBytes::<BYTES>)?;
        Ok(Self {
            bits: Box::new(bits),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn round_trip() {
        let mut bloom = Bloom::new();
        assert!(!bloom.contains(b"lost-network"));
        bloom.insert(b"lost-network");
        assert!(bloom.contains(b"lost-network"));
        assert!(!bloom.contains(b"other-network"));
    }

    #[test]
    fn serde_preserves_bits() {
        let mut bloom = Bloom::new();
        bloom.insert(b"burned");
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&bloom, &mut bytes).unwrap();
        let back: Bloom = ciborium::de::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(bloom, back);
        assert!(back.contains(b"burned"));
    }

    #[test]
    fn false_positives_are_rare() {
        let mut bloom = Bloom::new();
        for i in 0..128 {
            bloom.insert(format!("burned-{i}").as_bytes());
        }
        let hits = (0..10_000)
            .filter(|i| bloom.contains(format!("probe-{i}").as_bytes()))
            .count();
        assert_eq!(
            hits, 0,
            "false positives at plausible occupancy: {hits}/10000"
        );
    }

    /// If this test fails, STOP! The on-disk format may have changed!
    #[test]
    fn pin_probes() {
        assert_eq!(probes(b"sush"), [3392, 1007, 8018, 5416, 1335, 7804, 1908]);
    }
}
