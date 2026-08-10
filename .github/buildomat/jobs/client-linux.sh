#!/bin/bash
#: name = "Build Linux client"
#: variety = "basic"
#: target = "ubuntu-22.04"
#: rust_toolchain = true
#: output_rules = ["=/work/sush"]
#: access_repos = ["oxidecomputer/permission-slip"]
#:
#: [[publish]]
#: series = "linux"
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

mkdir -p /work

cargo build --release --locked --package sush-client --features permslip
cp target/release/sush /work/sush
