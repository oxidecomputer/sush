#!/bin/bash
#: name = "Build Helios client / CI"
#: variety = "basic"
#: target = "helios-2.0"
#: rust_toolchain = true
#: output_rules = ["=/work/sush"]
#: access_repos = ["oxidecomputer/permission-slip"]
#:
#: [[publish]]
#: series = "helios"
#: name = "sush"
#: from_output = "/work/sush"

set -o errexit
set -o pipefail
set -o xtrace

cargo --version
rustc --version

# Cargo's builtin fetch does not read buildomat's netrc token.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_INCREMENTAL=0

pfexec mkdir -p /work && pfexec chown "$USER" /work

# Build and stage the published client before the gate, so a red run
# still leaves a binary in the job outputs.
cargo build --release --locked --package sush-client --features permslip
cp target/release/sush /work/sush

cargo install just --locked
curl -sSfL https://get.nexte.st/latest/illumos | gunzip | tar -xf - -C ~/.cargo/bin

just ci
