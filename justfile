set shell := ["bash", "-euo", "pipefail", "-c"]

check:
    cargo check --workspace --all-targets

lint:
    cargo fmt --check && cargo clippy --tests

test *FILTER:
    cargo nextest run --workspace {{FILTER}}

openapi:
    cargo xtask openapi

ci:
    cargo fmt --check
    cargo clippy -- --no-deps --deny warnings
    cargo clippy --tests -- --no-deps --deny warnings
    cargo build --locked
    cargo nextest run --run-ignored all
    cargo test --doc
    cargo xtask openapi && git diff --exit-code sush.json

ci-client:
    cargo clippy --package sush-client --features permslip -- --no-deps --deny warnings
    cargo build --locked --package sush-client --features permslip
