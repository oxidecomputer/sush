// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Random code phrases like `abstract misery favorite ordinary moon talk`.
//!
//! These are intended to serve not as secrets, but as representations
//! of up to 256 bits of entropy (e.g., identifiers, signature scalars)
//! that must be readily transmissible over low bandwidth channels (e.g.,
//! email, voice, printed or handwritten notes, etc.).

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use crypto_bigint::{
    ArrayEncoding as _, CheckedAdd as _, CheckedMul as _, Encoding as _, Limb, Random as _,
    Reciprocal, U256,
};
use rand_core::OsRng;
use schemars::JsonSchema;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::wire::ExactBytes;
use crate::wordlist::{WORDLIST, WORDLIST_LEN};

/// Entropy is treated as an integer whose base is to be changed
/// to 2048, which gives us indexes into the BIP-39 word list.
/// Since 2048<sup>23</sup> < 2<sup>256</sup> < 2048<sup>24</sup>,
/// 24 words suffice to represent 256 bits with no redundancy.
const PHRASE_WORDS_256: usize = 24;

/// The BIP-39 word list contains no punctuation of any kind, so we are
/// free to use ASCII hyphen (`-`) as the default word separator. Decoding
/// will also accept arbitrary ASCII whitespace as word separators.
const WORD_SEPARATOR: &str = "-";

/// With 2048 words, an 8 word code phrase has ~88 bits of entropy,
/// making it suitable for use as a unique, hard-to-guess identifier,
/// but not a secret.
///
/// Note that the security of the Support Shell protocol (RFD 620) does
/// *not* rely on such identifiers being unguessable; it relies only on
/// the strength of the signatures produced over these phrases.
const TRUNCATED_BITS: u32 = 88;

/// Random code phrase like `abstract misery favorite ordinary moon talk`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Codephrase(U256);

impl Codephrase {
    /// Generate a new random codephrase.
    pub fn random() -> Self {
        Self(U256::random(&mut OsRng))
    }

    /// Turn 256 bits of entropy into a reasonably unique code phrase.
    /// We use the low-order words of the full codephrase, and pad to
    /// the canonical length; these phrases are intended for machine
    /// consumption, and are short enough for easy transmission.
    pub fn truncate(self) -> Self {
        let mask = U256::from_u128(2u128.pow(TRUNCATED_BITS) - 1);
        Self(self.0.bitand(&mask))
    }

    /// Construct a codephrase from its big-endian byte representation.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(U256::from_be_bytes(bytes))
    }

    /// Get the underlying big-endian byte representation of the codephrase.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0.to_be_byte_array().into()
    }
}

impl fmt::Display for Codephrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Turn 256 bits of entropy into an un-padded big-endian code phrase.
        let b = Reciprocal::new(Limb(WORDLIST_LEN as u64)).expect("should have some words");
        let mut n = self.0;
        let mut r;
        let mut words = Vec::with_capacity(PHRASE_WORDS_256);
        while n > U256::ZERO {
            (n, r) = n.ct_div_rem_limb_with_reciprocal(&b);
            words.push(word(r.0 as usize)); // accumulate little-endian
        }
        words.reverse(); // emit big-endian

        f.write_str(&words.join(WORD_SEPARATOR))
    }
}

impl fmt::Debug for Codephrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Codephrase({self})")
    }
}

impl FromStr for Codephrase {
    type Err = InvalidCodephrase;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        // Decode a big endian code phrase into 256 bits of entropy.
        //
        // Decoding is non-injective, or "liberal" in the sense that it will
        // accept non-canonical codephrases, e.g., ones with spaces instead of
        // separators, words in mixed case, or without leading zeros. This is
        // for the comfort of humans that may have to transmit such phrases.
        // It rejects phrases that no entropy encodes to: unknown words, more
        // than [`PHRASE_WORDS_256`] words, or a value of 256 bits or more.
        // The empty phrase decodes to zero. Callers that must distinguish
        // absent input from zero should check before decoding.

        let b = U256::from_u64(WORDLIST_LEN as u64);
        let mut n = U256::ZERO;
        let mut words = 0;
        for word in value
            .to_ascii_lowercase()
            .replace(WORD_SEPARATOR, " ")
            .split_ascii_whitespace()
        {
            words += 1;
            if words > PHRASE_WORDS_256 {
                return Err(InvalidCodephrase);
            }
            let r = U256::from_u64(index(word)? as u64);
            n = Option::from(n.checked_mul(&b)).ok_or(InvalidCodephrase)?;
            n = Option::from(n.checked_add(&r)).ok_or(InvalidCodephrase)?;
        }
        Ok(Self(n))
    }
}

/// Phrases for humans, raw big-endian bytes for binary formats.
impl Serialize for Codephrase {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            serializer.serialize_bytes(&self.to_be_bytes())
        }
    }
}

impl<'de> Deserialize<'de> for Codephrase {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let string = <String as Deserialize>::deserialize(deserializer)?;
            Self::from_str(&string).map_err(D::Error::custom)
        } else {
            Ok(Self::from_be_bytes(
                deserializer.deserialize_bytes(ExactBytes::<32>)?,
            ))
        }
    }
}

// Treat a codephrase as a string in JSON schemas.
impl JsonSchema for Codephrase {
    fn schema_name() -> String {
        String::schema_name()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        String::json_schema(generator)
    }

    fn is_referenceable() -> bool {
        String::is_referenceable()
    }

    fn schema_id() -> Cow<'static, str> {
        String::schema_id()
    }
}

#[macro_export]
macro_rules! codephrase_newtype {
    ($(#[$meta:meta])* $vis:vis struct $name:ident = $len:ident;) => {
        $(#[$meta])*
        $vis struct $name($crate::codephrases::Codephrase);

        impl $name {
            #[allow(unused)]
            $vis fn random() -> Self {
                let mut codephrase = $crate::codephrases::Codephrase::random();
                match $crate::codephrases::CodephraseLength::$len {
                    $crate::codephrases::CodephraseLength::Full => {}
                    $crate::codephrases::CodephraseLength::Truncated => {
                        codephrase = codephrase.truncate();
                    }
                }
                Self(codephrase)
            }

            #[allow(unused)]
            $vis fn from_hash(hash: $crate::hash::Hash) -> Self {
                let mut codephrase = $crate::codephrases::Codephrase::from_be_bytes(*hash.as_bytes());
                match $crate::codephrases::CodephraseLength::$len {
                    $crate::codephrases::CodephraseLength::Full => {}
                    $crate::codephrases::CodephraseLength::Truncated => {
                        codephrase = codephrase.truncate();
                    }
                }
                Self(codephrase)
            }

            #[allow(unused)]
            $vis fn from_be_bytes(bytes: [u8; 32]) -> Self {
                let mut codephrase = $crate::codephrases::Codephrase::from_be_bytes(bytes);
                match $crate::codephrases::CodephraseLength::$len {
                    $crate::codephrases::CodephraseLength::Full => {}
                    $crate::codephrases::CodephraseLength::Truncated => {
                        codephrase = codephrase.truncate();
                    }
                }
                Self(codephrase)
            }

            #[allow(unused)]
            $vis fn to_be_bytes(&self) -> [u8; 32] {
                self.0.to_be_bytes()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                <$crate::codephrases::Codephrase as std::fmt::Display>::fmt(&self.0, f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::codephrases::InvalidCodephrase;

            fn from_str(s: &str) -> Result<$name, Self::Err> {
                Ok($name(s.parse()?))
            }
        }
    }
}

#[derive(Clone, Copy)]
pub enum CodephraseLength {
    Full,
    Truncated,
}

/// Decoding a phrase failed.
#[derive(Debug, Error)]
#[error("invalid or non-canonical code phrase")]
pub struct InvalidCodephrase;

/// Look up a word in the word list.
#[inline]
fn word(index: usize) -> &'static str {
    WORDLIST[index]
}

/// Find the index of a word in the word list.
#[inline]
fn index(word: &str) -> Result<usize, InvalidCodephrase> {
    WORDLIST.binary_search(&word).map_err(|_| InvalidCodephrase)
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;

    fn round_trip(entropy: U256) -> String {
        let codephrase = Codephrase::from_be_bytes(entropy.to_be_bytes());
        let decoded: Codephrase = codephrase.to_string().parse().unwrap();
        assert_eq!(codephrase, decoded);
        codephrase.to_string()
    }

    #[test]
    fn trivial_codephrases() {
        let b = WORDLIST_LEN as u64;
        assert_eq!(round_trip(U256::ZERO), "");
        assert_eq!(round_trip(U256::ONE), "ability");
        assert_eq!(round_trip(U256::from_u64(b - 1)), "zoo");
        assert_eq!(round_trip(U256::from_u64(b)), "ability-abandon");
        assert_eq!(round_trip(U256::from_u64(b + 1)), "ability-ability");
        assert_eq!(
            round_trip(U256::from_u64(b.pow(2))),
            "ability-abandon-abandon"
        );
        assert_eq!(
            round_trip(U256::from_u64(b.pow(3))),
            "ability-abandon-abandon-abandon"
        );
        assert_eq!(
            round_trip(U256::from_u64(b.pow(3) + 1)),
            "ability-abandon-abandon-ability"
        );
        assert_eq!(
            round_trip(U256::from_u64(b.pow(3) + b - 1)),
            "ability-abandon-abandon-zoo"
        );
        round_trip(U256::MAX);
    }

    #[test]
    fn non_phrases() {
        // Unknown words, wherever they appear.
        assert!(Codephrase::from_str("plugh").is_err());
        assert!(Codephrase::from_str("abandon-plugh").is_err());

        // More words than any entropy encodes to.
        let long = [word(0); PHRASE_WORDS_256 + 1].join(WORD_SEPARATOR);
        assert!(Codephrase::from_str(&long).is_err());

        // 24-word values of 256 bits or more: the smallest, exactly
        // 2^256, and the largest.
        let mut smallest = vec![word(8)];
        smallest.extend([word(0); PHRASE_WORDS_256 - 1]);
        assert!(Codephrase::from_str(&smallest.join(WORD_SEPARATOR)).is_err());
        let largest = [word(WORDLIST_LEN - 1); PHRASE_WORDS_256].join(WORD_SEPARATOR);
        assert!(Codephrase::from_str(&largest).is_err());
    }

    #[test]
    fn constant_codephrases() {
        assert_eq!(
            round_trip(U256::from_be_slice(
                crate::hash::hash(b"test phrase one").as_bytes()
            )),
            "above-favorite-secret-decorate-wolf-year-pencil-\
             scan-cage-stage-neither-border-transfer-hamster-\
             hand-journey-track-amazing-put-inmate-bread-\
             fossil-sugar-metal"
        );
        assert_eq!(
            round_trip(U256::from_be_slice(
                crate::hash::hash(b"another test phrase").as_bytes()
            )),
            "above-accident-quarter-topic-mango-chef-galaxy-\
             brisk-company-tray-affair-lumber-raccoon-cat-\
             devote-boy-festival-slab-trip-fantasy-drum-\
             output-worry-chunk"
        );
        assert_eq!(
            round_trip(U256::from_be_slice(
                crate::hash::hash(b"one more for luck!").as_bytes()
            )),
            "abstract-humor-genuine-clarify-flash-extend-\
             hospital-hockey-reduce-picnic-avoid-crawl-voice-\
             tool-cash-neck-enlist-gossip-unlock-crime-piano-\
             gloom-search-video"
        );
    }

    #[test]
    fn random_codephrases() {
        let mut seen = HashSet::new();

        // Although this test is probabilistic, you should be able to set
        // the iteration count arbitrarily high and never see a failure
        // (though you may run out of memory or time). The current value
        // was chosen to run in < 1 second on a modest development system.
        for _ in 0..10_000 {
            let nonce = U256::random(&mut OsRng);
            let codephrase = round_trip(nonce);
            let n = codephrase.split(WORD_SEPARATOR).count();

            // Because we're using un-padded phrases, we have to guess at a
            // lower bound for the number of words here. 16 should be safe;
            // if you've hit that, congratulations! You've found a highly
            // unlikely run of leading zeros in your "entropy"! Realistically,
            // phrases with 22 words are easy to find, 21 much harder. Below
            // that, you should be mining for ₿ instead of running this test.
            assert!(n > 16 && n <= 24, "{codephrase} has {n} words");

            // If this assertion fails, congratulations are again in order:
            // you've found two distinct sets of 256 bits of "entropy" that
            // are exactly the same! Either something is deeply wrong with
            // the universe or our understanding of it, this code is broken,
            // or your OS RNG is not so R after all.
            assert!(
                seen.insert(codephrase.clone()),
                "duplicate codephrase {codephrase}"
            );
        }
    }

    #[test]
    fn id_phrases() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let id = Codephrase::random().truncate();
            assert!(seen.insert(id), "duplicate ID {id}");

            let roundtrip = Codephrase::from_str(&id.to_string()).unwrap();
            assert_eq!(id, roundtrip);
        }
    }

    #[test]
    fn leading_zeros_after_truncation() {
        let truncated = Codephrase::random().truncate();
        assert_eq!(U256::from_u8(0), truncated.0.shr(TRUNCATED_BITS as _));
    }
}
