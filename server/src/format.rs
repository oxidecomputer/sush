// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Versioned durable formats.
//!
//! Every version names its predecessor as its `Previous`. [`Record`] and
//! [`Wire`] each require a conversion from it; fallible for [`Record`],
//! infallible for [`Wire`]. A new version therefore does not compile
//! until the conversion from the old one exists, so by induction every
//! version ever shipped can be upgraded to the latest.
//!
//! A [`Locker`](crate::locker::Locker) tenant record is stored as a
//! two-element CBOR array, `[version, bytes]`, the byte string holding
//! the record's own CBOR encoding. The version lets a newer release
//! read every record an older release ever wrote: [`decode`] matches
//! the stored version against the chain of known formats, parses the
//! body as the format that matches, and converts the result up the
//! chain to the latest format. A gossip message instead carries its
//! version as the [`VersionedMessage`](crate::messages::VersionedMessage)
//! variant tag, and converts up when the state machine unwraps it.
//!
//! Tests must pin each version's serialized bytes. To change a format,
//! copy the live type into a frozen module under its version's name,
//! point the pin test at the copy, give the live type the next version,
//! name the frozen type as its `Previous`, and write the conversion the
//! compiler requires.

use std::fmt::Display;

use ciborium::{de::from_reader as from_cbor, ser::into_writer as into_cbor};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;

/// A type that is one version of a durable format. Version numbers
/// must be unique within a chain and increase along it, so that any
/// version above the latest must belong to newer software.
pub trait Versioned: Sized {
    const VERSION: u16;
}

/// A [`Locker`](crate::locker::Locker) tenant's record format.
/// New versions will not compile without a conversion from their
/// predecessors. The conversion may fail, because the caller can
/// quarantine a record that will not convert; the boundary store,
/// for example, stays untrusted.
pub trait Record: Versioned + Serialize + DeserializeOwned {
    /// The format this one supersedes.
    type Previous: Record + TryInto<Self, Error: Display>;

    /// Parse `body` as the chain member whose version is `version`,
    /// converting the result up to `Self`. This is not a public
    /// interface; use [`decode`].
    fn walk(version: u16, body: &[u8]) -> Result<Self, FormatError> {
        const {
            assert!(
                Self::Previous::VERSION == NoFormat::VERSION
                    || Self::Previous::VERSION < Self::VERSION,
                "chain versions must increase",
            )
        };

        if version == Self::VERSION {
            return from_cbor(body).map_err(|error: ciborium::de::Error<_>| FormatError::Body {
                version,
                message: error.to_string(),
            });
        }

        let previous = Self::Previous::walk(version, body)?;
        previous.try_into().map_err(|error| FormatError::Convert {
            from: Self::Previous::VERSION,
            message: error.to_string(),
        })
    }
}

/// A wire format for messages, with the same upgrade guarantee
/// as [`Record`]. But here the conversion is infallible, because
/// message processing cannot in general skip a replayed message
/// or stop at it.
pub trait Wire: Versioned {
    /// The format this one supersedes.
    type Previous: Wire + Into<Self>;
}

/// The end of every version chain.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum NoFormat {}

impl Versioned for NoFormat {
    // Reserved for the terminus.
    const VERSION: u16 = u16::MAX;
}

impl Record for NoFormat {
    type Previous = NoFormat;

    fn walk(version: u16, _body: &[u8]) -> Result<Self, FormatError> {
        Err(FormatError::Unknown { version })
    }
}

impl Wire for NoFormat {
    type Previous = NoFormat;
}

/// Why a record could not be read.
#[derive(Debug, Error)]
pub enum FormatError {
    #[error("the record's version envelope did not parse")]
    Envelope,
    #[error("the record's format version {version} is newer than this software")]
    Future { version: u16 },
    #[error("no format in this record's chain has version {version}")]
    Unknown { version: u16 },
    #[error("the record did not parse as format version {version}: {message}")]
    Body { version: u16, message: String },
    #[error("converting the record from format version {from} failed: {message}")]
    Convert { from: u16, message: String },
}

/// The version envelope: `[version, body]`, with the body nested
/// as a CBOR byte string holding the encoded record. Nesting
/// keeps the body out of `ciborium::Value`, whose deserializer is
/// stricter than the byte-stream one and refuses serde adapters that
/// read CBOR byte strings; [`decode`] reads the version and hands
/// the untouched body bytes to the stream deserializer.
#[derive(serde::Serialize)]
struct Envelope(u16, #[serde(with = "cbor_bytes")] Vec<u8>);

// Manual impl to refuse trailing elements.
impl<'de> serde::Deserialize<'de> for Envelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error as _, IgnoredAny, SeqAccess, Visitor};

        struct Body(Vec<u8>);
        impl<'de> serde::Deserialize<'de> for Body {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                cbor_bytes::deserialize(deserializer).map(Body)
            }
        }

        struct EnvelopeVisitor;
        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = Envelope;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a two-element version envelope")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let version = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| A::Error::custom("an envelope without a version"))?;
                let Body(body) = seq
                    .next_element::<Body>()?
                    .ok_or_else(|| A::Error::custom("an envelope without a body"))?;
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("trailing elements in the envelope"));
                }
                Ok(Envelope(version, body))
            }
        }

        deserializer.deserialize_seq(EnvelopeVisitor)
    }
}

/// Serialize a byte buffer as a CBOR byte string rather than an
/// array of integers.
pub(crate) mod cbor_bytes {
    use serde::de::Visitor;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Bytes;
        impl<'de> Visitor<'de> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(v.to_vec())
            }
        }
        deserializer.deserialize_bytes(Bytes)
    }
}

/// Encode `value` at the latest version, inside the version envelope.
pub fn encode<T: Record>(value: &T) -> Vec<u8> {
    let mut body = Vec::new();
    into_cbor(value, &mut body).expect("writing to a Vec cannot fail");
    let mut bytes = Vec::new();
    into_cbor(&Envelope(T::VERSION, body), &mut bytes).expect("writing to a Vec cannot fail");
    bytes
}

/// Decode a record at whatever version it was stored, converting up
/// the chain to `T`.
pub fn decode<T: Record>(bytes: &[u8]) -> Result<T, FormatError> {
    let Envelope(version, body) = from_cbor(bytes).map_err(|_| FormatError::Envelope)?;
    if version > T::VERSION {
        return Err(FormatError::Future { version });
    }
    T::walk(version, &body)
}

#[cfg(test)]
mod test {
    use super::*;

    use serde::Deserialize;

    #[derive(Debug, Deserialize, Serialize)]
    struct TestV0 {
        count: u8,
    }

    #[derive(Debug, Deserialize, Serialize, PartialEq)]
    struct TestV1 {
        count: u32,
        label: String,
    }

    impl Versioned for TestV0 {
        const VERSION: u16 = 0;
    }
    impl Record for TestV0 {
        type Previous = NoFormat;
    }

    // The gap at version 1 is deliberate: unknown_version_is_refused
    // walks the whole chain without matching it.
    impl Versioned for TestV1 {
        const VERSION: u16 = 2;
    }
    impl Record for TestV1 {
        type Previous = TestV0;
    }

    impl TryFrom<NoFormat> for TestV0 {
        type Error = &'static str;
        fn try_from(none: NoFormat) -> Result<Self, Self::Error> {
            match none {}
        }
    }

    impl TryFrom<TestV0> for TestV1 {
        type Error = &'static str;
        fn try_from(old: TestV0) -> Result<Self, Self::Error> {
            if old.count == u8::MAX {
                return Err("saturated count");
            }
            Ok(TestV1 {
                count: old.count.into(),
                label: String::new(),
            })
        }
    }

    #[test]
    fn trailing_envelope_elements_are_refused() {
        #[derive(Serialize)]
        struct Extended(u16, #[serde(with = "cbor_bytes")] Vec<u8>, u16);
        let mut body = Vec::new();
        into_cbor(&TestV0 { count: 7 }, &mut body).unwrap();
        let mut bytes = Vec::new();
        into_cbor(&Extended(0, body, 7), &mut bytes).unwrap();
        assert!(matches!(
            decode::<TestV0>(&bytes),
            Err(FormatError::Envelope)
        ));
    }

    #[test]
    fn round_trip_at_latest() {
        let value = TestV1 {
            count: 7,
            label: "seven".to_string(),
        };
        let decoded: TestV1 = decode(&encode(&value)).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn old_version_converts_up() {
        let old = encode(&TestV0 { count: 7 });
        let new: TestV1 = decode(&old).unwrap();
        assert_eq!(
            new,
            TestV1 {
                count: 7,
                label: String::new(),
            }
        );
    }

    #[test]
    fn future_version_is_refused() {
        let futuristic = encode(&TestV1 {
            count: 1,
            label: String::new(),
        });
        assert!(matches!(
            decode::<TestV0>(&futuristic),
            Err(FormatError::Future { version: 2 })
        ));
    }

    #[test]
    fn unknown_version_is_refused() {
        let mut bytes = Vec::new();
        into_cbor(&Envelope(1, Vec::new()), &mut bytes).unwrap();
        assert!(matches!(
            decode::<TestV1>(&bytes),
            Err(FormatError::Unknown { version: 1 })
        ));
    }

    #[test]
    fn failed_conversion_is_reported() {
        let saturated = encode(&TestV0 { count: u8::MAX });
        assert!(matches!(
            decode::<TestV1>(&saturated),
            Err(FormatError::Convert { from: 0, .. })
        ));
    }

    #[test]
    fn garbage_is_refused() {
        assert!(matches!(
            decode::<TestV1>(b"scribble"),
            Err(FormatError::Envelope)
        ));
    }

    #[derive(Debug, PartialEq)]
    struct WireV0(u8);
    #[derive(Debug, PartialEq)]
    struct WireV1(u32);

    impl Versioned for WireV0 {
        const VERSION: u16 = 0;
    }
    impl Wire for WireV0 {
        type Previous = NoFormat;
    }

    impl Versioned for WireV1 {
        const VERSION: u16 = 1;
    }
    impl Wire for WireV1 {
        type Previous = WireV0;
    }

    impl From<NoFormat> for WireV0 {
        fn from(none: NoFormat) -> Self {
            match none {}
        }
    }

    impl From<WireV0> for WireV1 {
        fn from(old: WireV0) -> Self {
            WireV1(old.0.into())
        }
    }

    /// A wire chain converts infallibly; the bound will not accept a
    /// fallible conversion.
    #[test]
    fn wire_chain_converts() {
        assert_eq!(WireV1::from(WireV0(7)), WireV1(7));
    }

    #[test]
    fn wrong_body_is_reported() {
        let mut bytes = Vec::new();
        let mut body = Vec::new();
        into_cbor(&"not a struct", &mut body).unwrap();
        into_cbor(&Envelope(0, body), &mut bytes).unwrap();
        assert!(matches!(
            decode::<TestV0>(&bytes),
            Err(FormatError::Body { version: 0, .. })
        ));
    }
}
