default:
    @just --list

build-ebpf:
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/arch-toolchain.sh
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
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/arch-toolchain.sh
    if [ "$ARCH_BUILD" = 1 ]; then
        echo "Arch Linux detected: using the system Rust/sqlite toolchain"
    fi
    cargo build
    verify_arch_binaries target/debug/electric-eyed target/debug/electric-eye

release: build-ebpf
    #!/usr/bin/env bash
    set -euo pipefail
    source scripts/arch-toolchain.sh
    if [ "$ARCH_BUILD" = 1 ]; then
        echo "Arch Linux detected: using the system Rust/LLVM/sqlite toolchain"
    fi
    cargo build --release --locked -p electric-eyed -p electric-eye-cli
    verify_arch_binaries target/release/electric-eyed target/release/electric-eye
    if [ "$ARCH_BUILD" = 1 ]; then
        echo "Arch release binaries use system libraries"
    fi

run-daemon: build
    sudo ./target/debug/electric-eyed --stdout

install-skill:
    #!/usr/bin/env bash
    set -euo pipefail
    dest="${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills/electric-eye"
    install -d "$dest/references"
    install -m644 .opencode/skills/electric-eye/SKILL.md "$dest/SKILL.md"
    install -m644 .opencode/skills/electric-eye/references/queries.md \
        "$dest/references/queries.md"
    echo "installed electric-eye skill in $dest"

test-lxc:
    ./tests/lxc/capture-test.sh

dist:
    #!/usr/bin/env bash
    set -euo pipefail
    ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
    install -d packaging/arch
    # Keep the verified PKGBUILD out of the source archive; it lives in the
    # repository/AUR and would otherwise carry a placeholder checksum.
    git archive --format=tar.gz --prefix="electric-eye-$ver/" \
        -o "packaging/arch/electric-eye-$ver.tar.gz" HEAD \
        -- . ':(exclude)packaging/arch'
    sha256sum "packaging/arch/electric-eye-$ver.tar.gz"

test:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo nextest run

check:
    cargo check --workspace
