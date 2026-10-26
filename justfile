default:
    @just --list

build-ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! rustup toolchain list | grep -q '^nightly-2026-01-20'; then
        rustup toolchain install nightly-2026-01-20 --profile minimal --component rust-src
    fi
    if ! command -v bpf-linker >/dev/null 2>&1; then
        echo "installing bpf-linker (LLVM 21 feature to match the dev shell LLVM)"
        RUSTUP_TOOLCHAIN=stable cargo install bpf-linker --locked \
            --no-default-features --features llvm-21
    fi
    cargo xtask build-ebpf

build: build-ebpf
    cargo build

release: build-ebpf
    cargo build --release --locked -p electric-eyed -p electric-eye-cli

run-daemon: build
    sudo ./target/debug/electric-eyed --stdout

test-lxc:
    ./tests/lxc/capture-test.sh

dist:
    #!/usr/bin/env bash
    set -euo pipefail
    ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
    install -d packaging/arch
    git archive --format=tar.gz --prefix="electric-eye-$ver/" \
        -o "packaging/arch/electric-eye-$ver.tar.gz" HEAD
    sha256sum "packaging/arch/electric-eye-$ver.tar.gz"

test:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run

check:
    cargo check --workspace
