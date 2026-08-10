#!/bin/bash
#: name = "client (helios)"
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

cargo build --release --locked --package sush-client --features permslip
cp target/release/sush /work/sush
