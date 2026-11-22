// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Common data structures and algorithms for the Oxide Support Shell.

pub mod authn;
#[macro_use]
pub mod codephrases;
pub mod hash;
pub mod interactive;
pub mod jobs;
pub mod keys;
pub mod targets;
pub mod version;
pub mod wire;
pub mod wordlist;

pub const OPENAPI_TITLE: &str = "Oxide Support Shell";
