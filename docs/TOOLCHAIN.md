# Toolchain pinning and dependency policy

Building the eBPF side of electric-eye involves a **three-way LLVM version
triangle** that is easy to get wrong:

```text
nightly rustc ──(emits objects with its bundled LLVM)──▶ bpf-linker ──(reads them)──▶ linked LLVM
     producer                                                reader
```

The object files produced by rustc carry LLVM metadata (attribute kinds,
bitcode records) that only newer-or-equal readers understand. If the reader
(bpf-linker's linked libLLVM) is older than the producer (rustc's bundled
LLVM), builds fail in confusing ways. Everything below follows from that rule.

## Current pins

| Component          | Version              | Where it is pinned                        |
| ------------------ | -------------------- | ----------------------------------------- |
| eBPF rustc         | nightly-2026-01-20   | `justfile`, `xtask/src/build_ebpf.rs`     |
|                    | (rustc 1.95.0-nightly, LLVM 21.1.8)                                |
| bpf-linker         | 0.11.0, built with   | installed to `~/.cargo/bin` by            |
|                    | `--features llvm-21` | `just build-ebpf` bootstrap               |
| dev-shell LLVM     | nixpkgs clang/lld/llvm/libclang 21.1.8 | `flake.lock` + `flake.nix` |
| userspace rustc    | 1.97.1 stable        | nixpkgs via `nix develop`                 |

## Why each pin exists

### nightly-2026-01-20

Chosen so that rustc's bundled LLVM (**21.1.8**) exactly matches the LLVM
major our bpf-linker binary was built against (`--features llvm-21`,
linking nixpkgs' llvm 21.1.8). Any nightly whose bundled LLVM is *newer*
produces objects this linker cannot parse.

To find a compatible nightly for a given LLVM major, probe candidates
without installing components:

```bash
rustup toolchain install nightly-2026-MM-DD --profile minimal
rustup run nightly-2026-MM-DD rustc --version --verbose | grep LLVM
```

Rough LLVM-era map (verified empirically on this repo's history):

| Nightly range      | Bundled LLVM |
| ------------------ | ------------ |
| ≥ 2026-08          | 23.x         |
| 2026-05 … 2026-07  | 22.x         |
| 2025-12 … 2026-04  | 21.x         |

### bpf-linker --features llvm-21

bpf-linker 0.11.0 defaults to the `llvm-23` feature. Building against
*nixpkgs'* LLVM 23 fails because nixpkgs currently ships **23.1.0-rc1**,
which lacks `LLVMParseIRInContext2` (added between rc and final). The
`llvm-21` feature matches the shell's final-release LLVM 21.1.8 and works.
The bootstrap lives in `just build-ebpf`.

If you rebuild bpf-linker yourself, keep this invariant:

> bpf-linker's linked LLVM major == rustc nightly's bundled LLVM major

### nixpkgs flake.lock

`flake.nix` pins `nixpkgs/nixos-unstable`; `flake.lock` freezes the exact
snapshot providing clang/llvm/lld/libclang/bpftools and the userspace
stable Rust. Bumping it can silently change the shell's LLVM major — after
`nix flake update`, re-run the pairing check above before building the
eBPF crate.

## Arch Linux packaging

The Arch `extra/bpf-linker` package (0.11.0-2) is built against the distro's
current LLVM (23.1.x at the time of writing). That is fine with the pinned
nightly because the reader is **newer** than the producer (nightly
2026-01-20 bundles LLVM 21.1.8). The PKGBUILD installs a stable Rust toolchain
for the userspace/xtask crates and the pinned nightly for the eBPF object.
Nixpkgs' LLVM 23.1.0-rc1 is the case that needs `--features llvm-21`, because
the rc lacks `LLVMParseIRInContext2`.

## Known failure signatures

| Symptom                                                             | Cause                                        |
| ------------------------------------------------------------------- | -------------------------------------------- |
| `error: linking with 'bpf-linker' failed: signal: 11 (SIGSEGV)` in `sroa` at `-O3` | producer LLVM > reader LLVM; crashes early instead of erroring |
| `ERROR llvm: Unknown attribute kind (105) (Producer: 'LLVM…' Reader: 'LLVM…')`     | same mismatch, visible at `-O1`              |
| `undefined reference to LLVMParseIRInContext2` when installing bpf-linker           | linked against LLVM 23.1.0-rc1 (symbol added post-rc); use `--features llvm-21` against shell LLVM |
| `no such command: xtask`                                             | `.cargo/config.toml` alias missing           |
| `"/nix/store/…/lib/rustlib/src/rust/library/Cargo.lock" does not exist` during build-std | PATH leaked nixpkgs rustc into the eBPF build; xtask sets `RUSTC` explicitly to prevent this |
| `libbpf: legacy map definitions in 'maps' section are not supported` from `bpftool gen skeleton` | benign — aya emits legacy-style maps; we load with aya, not libbpf |

## Upgrade procedure

1. `cargo update` in both workspaces (root + `crates/electric-eye-ebpf`);
   run tests.
2. When bumping `aya` / `aya-ebpf`: bump **both** together, rebuild the
   eBPF object first, then userspace. The wire format of our ring-buffer
   events is ours, but map-section conventions and program macros are aya's.
3. If a bump requires a newer nightly than the pin allows, re-pair the
   toolchain instead of weakening the pin:
   - find a nightly whose bundled LLVM major equals an LLVM you can link
     bpf-linker against (see table above),
   - update `NIGHTLY` in `xtask/src/build_ebpf.rs` and `justfile`,
   - rebuild bpf-linker with the matching `--features llvm-NN`.
4. Never let the eBPF build resolve `rustc` from `$PATH`; xtask forces
   `RUSTC` into the pinned toolchain on purpose.

## Dependency policy

- Userspace dependencies live in `[workspace.dependencies]`; crates inherit
  with `.workspace = true`. Bump via plain `cargo update` (semver-safe).
- Cross-semver bumps (`aya`, `aya-ebpf`) are deliberate events: do them as
  their own jj commit, verified by a full `just check && just test` plus one
  live `sudo ./target/debug/electric-eyed --stdout` run.
- The eBPF crate keeps its own lockfile (it is a standalone workspace so the
  root workspace never tries to compile it for the host target).
