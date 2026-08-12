#!/bin/bash
#: name = "client (linux)"
#: variety = "basic"
#: target = "ubuntu-26.04"
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

# We build the client binary with MUSL to be compatible with any Linux distribution, regardless of
# whether it uses an older glibc version than this CI job. This also makes the binary work on NixOS.
TARGET=x86_64-unknown-linux-musl
rustup target install "$TARGET"

DEBIAN_FRONTEND=noninteractive sudo apt-get install -y musl-tools

cargo --version
rustc --version

# Cargo's builtin fetch does not read buildomat's netrc token.
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_INCREMENTAL=0

mkdir -p /work

cargo build --target "$TARGET" --release --locked --package sush-client --features permslip
cp "target/$TARGET/release/sush" /work/sush
