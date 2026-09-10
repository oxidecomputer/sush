// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Serde support for raw byte fields in binary wire formats.

use std::fmt;

use serde::de::{Error, Visitor};

/// Visits exactly `N` raw bytes.
pub struct ExactBytes<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for ExactBytes<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{N} raw bytes")
    }

    fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        bytes
            .try_into()
            .map_err(|_| E::invalid_length(bytes.len(), &self))
    }
}
