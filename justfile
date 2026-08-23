default:
    @just --list

build-ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! rustup toolchain list | grep -q '^nightly'; then
        rustup toolchain install nightly --profile minimal --component rust-src
    fi
    cargo xtask build-ebpf

build: build-ebpf
    cargo build

run-daemon: build
    sudo ./target/debug/electric-eyed --stdout

test:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run

check:
    cargo check --workspace
