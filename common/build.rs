// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Embed the git commit, "-dirty" suffixed when the tree has
//! uncommitted changes.

use std::process::Command;

fn main() {
    println!("cargo:rustc-env=SUSH_GIT_COMMIT={}", commit());
}

fn commit() -> String {
    let Some(sha) = git(&["rev-parse", "HEAD"]) else {
        return "unknown".to_string();
    };
    // Rebuild when the checked-out commit changes.
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]) {
        println!("cargo:rerun-if-changed={git_dir}/HEAD");
        if let Some(head) = git(&["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={git_dir}/{head}");
        }
    }
    let dirty = match git(&["status", "--porcelain", "--untracked-files=no"]) {
        Some(status) if status.is_empty() => "",
        _ => "-dirty",
    };
    format!("{sha}{dirty}")
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}
