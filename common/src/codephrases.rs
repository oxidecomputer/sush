//! Random code phrases like `cozy bountiful dullness quarry icing sixfold`.
//!
//! These are intended to serve not as secrets, but as representations
//! of up to 256 bits of entropy (e.g., identifiers, signature scalars)
//! that must be readily transmissible over low bandwidth channels, e.g.,
//! email, voice, printed or handwritten notes, etc.

use crypto_bigint::{Limb, NonZero, Random as _, U256, Wrapping};
use diceware_wordlists::EFF_LONG_WORDLIST;
use rand_core::OsRng;
use thiserror::Error;

/// 6<sup>5</sup> = 7,776 = five rolls of a six-sided die.
pub const WORDLIST_LEN: usize = 7_776;

/// The constituents of code phrases. We use the EFF Diceware list.
pub const WORDLIST: &[&str; WORDLIST_LEN] = &EFF_LONG_WORDLIST;

/// Decoding a phrase failed.
#[derive(Debug, Error)]
#[error("invalid code phrase, must be ≤ 20 space-separated words from the EFF Diceware list")]
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

/// Turn 256 bits of entropy into a code phrase.
///
/// We treat the entropy as a single 256 bit integer and change its base to
/// 6<sup>5</sup>, which gives us indexes into the EFF Diceware word list.
/// Since 6<sup>5<sup>19</sup></sup> < 2<sup>256</sup> < 6<sup>5<sup>20</sup></sup>,
/// 20 words suffice to represent 256 bits with no redundancy. Emits big endian
/// phrases with no padding.
pub fn codephrase(value: U256) -> Vec<&'static str> {
    let b = NonZero::new(Limb(WORDLIST_LEN as u64)).expect("should have some words");
    let mut n = value;
    let mut r;
    let mut words = Vec::new();
    while n >= (*b).into() {
        (n, r) = n.div_rem_limb(b);
        words.push(word(r.0 as usize)); // accumulate little endian
    }

    // limbs are little endian
    if let [Limb(l), Limb(0), Limb(0), Limb(0)] = n.to_limbs() {
        words.push(word(l as usize));
    } else {
        unreachable!("final remainder should fit in one limb");
    }

    assert!(words.len() <= 20, "codephrase should be at most 20 words");
    words.reverse(); // emit big endian
    words
}

/// Generate a code phrase with 256 bits of entropy.
pub fn generate_codephrase() -> String {
    codephrase(U256::random(&mut OsRng)).join(" ")
}

/// Generate a 6 word code phrase suitable for use as an identifier,
/// but not a secret (~77.5 bits of entropy).
pub fn generate_id() -> String {
    codephrase(U256::random(&mut OsRng))[..6].join(" ")
}

/// Decode a big endian code phrase into 256 bits of entropy.
pub fn decode_phrase(phrase: &str) -> Result<U256, InvalidCodephrase> {
    let b = Wrapping(U256::from_u64(WORDLIST_LEN as u64));
    let mut n = Wrapping(U256::ZERO);
    for word in phrase.split_ascii_whitespace().take(20) {
        let i = index(word)?;
        let r = Wrapping(U256::from_u64(i as u64));
        n *= b;
        n += r;
    }
    Ok(n.0)
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use sha2::{Digest as _, Sha256};

    use super::*;

    fn round_trip(entropy: U256) -> String {
        let codephrase = codephrase(entropy).join(" ");
        let decoded = decode_phrase(&codephrase).unwrap();
        assert_eq!(entropy, decoded);
        codephrase
    }

    #[test]
    fn trivial_codephrases() {
        let b = WORDLIST_LEN as u64;
        assert_eq!(round_trip(U256::ZERO), "abacus");
        assert_eq!(round_trip(U256::ONE), "abdomen");
        assert_eq!(round_trip(U256::from_u64(b - 1)), "zoom");
        assert_eq!(round_trip(U256::from_u64(b)), "abdomen abacus");
        assert_eq!(round_trip(U256::from_u64(b + 1)), "abdomen abdomen");
        assert_eq!(
            round_trip(U256::from_u64(b.pow(2))),
            "abdomen abacus abacus"
        );
        assert_eq!(
            round_trip(U256::from_u64(b.pow(3))),
            "abdomen abacus abacus abacus"
        );
        assert_eq!(
            round_trip(U256::from_u64(b.pow(3) + 1)),
            "abdomen abacus abacus abdomen"
        );
        assert_eq!(
            round_trip(U256::from_u64(b.pow(3) + b - 1)),
            "abdomen abacus abacus zoom"
        );
    }

    #[test]
    fn constant_codephrases() {
        assert_eq!(
            round_trip(U256::from_be_slice(&Sha256::digest("test phrase one"))),
            "cozy bountiful dullness quarry icing \
             sixfold plank armband childish gumminess \
             ibuprofen unvaried recliner subheader muzzle \
             map retention excitable dried unclamped"
        );
        assert_eq!(
            round_trip(U256::from_be_slice(&Sha256::digest("another test phrase"))),
            "cork drained obsolete wish service \
             grout graph caution feel refurnish \
             cobalt scrap relax identity estranged \
             repacking underpass guiding tartly impurity"
        );
        assert_eq!(
            round_trip(U256::from_be_slice(&Sha256::digest("one more for luck!"))),
            "avenge chemicals gusty ascend unending \
             gaffe ranking suffix doorknob overpower \
             pamperer clarify walk unbeaten overcast \
             pants respect elsewhere angrily distinct"
        );
    }

    #[test]
    fn random_codephrases() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let nonce = U256::random(&mut OsRng);
            let codephrase = round_trip(nonce);
            assert!([19, 20].contains(&codephrase.split_ascii_whitespace().count()));
            assert!(seen.insert(codephrase));
        }
    }

    #[test]
    fn verify_wordlist() {
        assert_eq!(WORDLIST_LEN, 6_usize.pow(5));
        assert_eq!(WORDLIST_LEN, WORDLIST.len());
        assert_eq!(HashSet::from(*WORDLIST).len(), WORDLIST.len());
        assert!(WORDLIST.iter().all(|word| {
            word.len() >= 3 && word.chars().all(|c| c.is_ascii_lowercase() || c == '-')
        }));
    }
}
