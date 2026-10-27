# shellcheck shell=bash
# Source this before building userspace binaries on Arch Linux.
#
# `nix develop` supplies a pinned LLVM/clang/bpf-linker toolchain, but its Rust
# and pkg-config environment also links the resulting binary against Nix glibc,
# sqlite and libsystemd. Such a binary cannot dlopen Arch's system libalpm.so,
# so package provenance silently falls back to filesystem-only metadata. Keep
# the Nix shell for BPF work; use the system toolchain for anything installed
# on Arch.

ARCH_BUILD=0
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" = arch ]; then
        ARCH_BUILD=1
    fi
fi

if [ "$ARCH_BUILD" = 1 ]; then
    export PATH="/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:${HOME}/.cargo/bin"
    # Clear Nix's library and pkg-config search paths so libsqlite3-sys and the
    # linker resolve Arch libraries and do not emit /nix/store RUNPATHs.
    unset LD_LIBRARY_PATH LIBRARY_PATH CPATH C_INCLUDE_PATH CPLUS_INCLUDE_PATH
    unset PKG_CONFIG_PATH NIX_CFLAGS_COMPILE NIX_LDFLAGS
fi

# Fail instead of deploying a Nix-linked binary on Arch. The check is a no-op
# on other distributions, where the caller's toolchain is intentional.
verify_arch_binaries() {
    if [ "$ARCH_BUILD" != 1 ]; then
        return 0
    fi
    for binary in "$@"; do
        if [ ! -e "$binary" ]; then
            echo "error: expected binary is missing: $binary" >&2
            return 1
        fi
        if ldd "$binary" | grep -q '/nix/store'; then
            echo "error: $binary links to Nix store libraries" >&2
            echo "build it with the system toolchain, not from 'nix develop'" >&2
            return 1
        fi
    done
}
