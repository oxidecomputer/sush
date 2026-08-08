// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Random code phrases like `abstract misery favorite ordinary moon talk`.
//!
//! These are intended to serve not as secrets, but as representations
//! of up to 256 bits of entropy (e.g., identifiers, signature scalars)
//! that must be readily transmissible over low bandwidth channels (e.g.,
//! email, voice, printed or handwritten notes, etc.).

use crypto_bigint::{CheckedAdd as _, CheckedMul as _, Limb, Random as _, Reciprocal, U256};
use rand_core::OsRng;
use thiserror::Error;

use crate::wordlist::{WORDLIST, WORDLIST_LEN};

/// Entropy is treated as an integer whose base is to be changed
/// to 2048, which gives us indexes into the BIP-39 word list.
/// Since 2048<sup>23</sup> < 2<sup>256</sup> < 2048<sup>24</sup>,
/// 24 words suffice to represent 256 bits with no redundancy.
pub const PHRASE_WORDS_256: usize = 24;

/// With 2048 words, an 8 word code phrase has ~88 bits of entropy,
/// making it suitable for use as a unique, hard-to-guess identifier,
/// but not a secret.
///
/// Note that the security of the Support Shell protocol (RFD 620) does
/// *not* rely on such identifiers being unguessable; it relies only on
/// the strength of the signatures produced over these phrases.
pub const PHRASE_WORDS_ID: usize = 8;

/// The BIP-39 word list contains no punctuation of any kind, so we are
/// free to use ASCII hyphen (`-`) as the default word separator. Decoding
/// will also accept arbitrary ASCII whitespace as word separators.
pub const WORD_SEPARATOR: &str = "-";

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

/// Turn 256 bits of entropy into an un-padded big-endian code phrase.
pub fn codephrase(value: U256) -> Vec<&'static str> {
    let b = Reciprocal::new(Limb(WORDLIST_LEN as u64)).expect("should have some words");
    let mut n = value;
    let mut r;
    let mut words = Vec::with_capacity(PHRASE_WORDS_256);
    while n > U256::ZERO {
        (n, r) = n.ct_div_rem_limb_with_reciprocal(&b);
        words.push(word(r.0 as usize)); // accumulate little-endian
    }
    words.reverse(); // emit big-endian
    words
}

/// Turn 256 bits of entropy into a reasonably unique code phrase.
/// We use the low-order words of the full codephrase, and pad to
/// the canonical length; these phrases are intended for machine
/// consumption, and are short enough for easy transmission.
pub fn id_phrase(value: U256) -> Vec<&'static str> {
    let mut phrase = codephrase(value);
    let n = phrase.len().saturating_sub(PHRASE_WORDS_ID);
    let mut phrase = phrase.split_off(n);
    while phrase.len() < PHRASE_WORDS_ID {
        phrase.insert(0, word(0)); // pad w/leading zeros
    }
    phrase
}

/// Generate a code phrase for use as an identifier.
pub fn generate_id() -> String {
    id_phrase(U256::random(&mut OsRng)).join(WORD_SEPARATOR)
}

/// Decode a big endian code phrase into 256 bits of entropy.
///
/// Decoding is non-injective, or "liberal" in the sense that it will
/// accept non-canonical codephrases, e.g., ones with spaces instead of
/// separators, words in mixed case, or without leading zeros. This is
/// for the comfort of humans that may have to transmit such phrases.
/// It rejects phrases that no entropy encodes to: unknown words, more
/// than [`PHRASE_WORDS_256`] words, or a value of 256 bits or more.
/// The empty phrase decodes to zero; callers that must distinguish
/// absent input from a zero value should check before decoding.
pub fn decode_phrase(phrase: &str) -> Result<U256, InvalidCodephrase> {
    let b = U256::from_u64(WORDLIST_LEN as u64);
    let mut n = U256::ZERO;
    let mut words = 0;
    for word in phrase
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
    Ok(n)
}

#[cfg(test)]
mod test {
    use super::*;
    use sha2::{Digest as _, Sha256};
    use std::collections::HashSet;

    fn round_trip(entropy: U256) -> String {
        let codephrase = codephrase(entropy).join(WORD_SEPARATOR);
        let decoded = decode_phrase(&codephrase).unwrap();
        assert_eq!(entropy, decoded);
        codephrase
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
        assert!(decode_phrase("plugh").is_err());
        assert!(decode_phrase("abandon-plugh").is_err());

        // More words than any entropy encodes to.
        let long = [word(0); PHRASE_WORDS_256 + 1].join(WORD_SEPARATOR);
        assert!(decode_phrase(&long).is_err());

        // 24-word values of 256 bits or more: the smallest, exactly
        // 2^256, and the largest.
        let mut smallest = vec![word(8)];
        smallest.extend([word(0); PHRASE_WORDS_256 - 1]);
        assert!(decode_phrase(&smallest.join(WORD_SEPARATOR)).is_err());
        let largest = [word(WORDLIST_LEN - 1); PHRASE_WORDS_256].join(WORD_SEPARATOR);
        assert!(decode_phrase(&largest).is_err());
    }

    #[test]
    fn constant_codephrases() {
        assert_eq!(
            round_trip(U256::from_be_slice(&Sha256::digest("test phrase one"))),
            "abstract-summer-orange-gown-urge-model-\
             exact-gorilla-outside-common-this-pepper-\
             pear-dust-minimum-black-double-recipe-\
             castle-crystal-clog-logic-delay-hamster"
        );
        assert_eq!(
            round_trip(U256::from_be_slice(&Sha256::digest("another test phrase"))),
            "abstract-misery-favorite-ordinary-moon-talk-\
             write-coffee-digital-slogan-spray-angry-\
             once-jazz-random-income-garage-regret-accident-\
             file-release-deny-reward-drastic"
        );
        assert_eq!(
            round_trip(U256::from_be_slice(&Sha256::digest("one more for luck!"))),
            "able-dismiss-cost-scheme-amazing-slogan-\
             service-current-protect-feed-length-text-\
             cruise-wisdom-beauty-angle-regret-truck-\
             prosper-album-decline-wheel-pause-legend"
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
            let id = generate_id();
            let n = id.split(WORD_SEPARATOR).count();
            assert_eq!(n, PHRASE_WORDS_ID);
            assert!(seen.insert(id.clone()), "duplicate ID {id}");

            let entropy = decode_phrase(&id).unwrap();
            round_trip(entropy);
            assert_eq!(id, id_phrase(entropy).join(WORD_SEPARATOR));
        }
    }

    #[test]
    fn id_leading_zero() {
        let v = U256::ONE.shl_vartime(66); // 7 digits, since 2048⁶ = 2⁶⁶
        let id = id_phrase(v);
        assert_eq!(id.len(), PHRASE_WORDS_ID);
        assert_eq!(decode_phrase(&id.join(WORD_SEPARATOR)).unwrap(), v);
    }
}
