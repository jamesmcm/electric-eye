# electric-eye

electric-eye explains what applications are doing: process execution, file
writes/renames/unlinks, TCP connects/listens/accepts and per-process traffic
totals, enriched with systemd units and Nix store provenance.

This tree currently targets **Arch Linux** (the NixOS module is deliberately
deferred). It is the Milestone 0 / early Milestone 1 slice: reliable kernel
attribution plus a small local query API.

## What works

- `EXEC` / `EXIT` with pid, ppid, uid and stable `(pid, start_ticks)` identity
- `CONNECT`, `LISTEN` and `ACCEPT` for IPv4/IPv6 TCP. ACCEPT is captured at
  `accept()`/`accept4()` exit, so it is attributed to the accepting server
  rather than the packet-processing context.
- `OPEN` / `CREATE` / `TRUNC` for writable opens, and aggregated `WRITE`
  summaries for actual `write(2)` syscalls (including fd redirection via
  `dup2`/`dup3`)
- `unlink`/`unlinkat`/`rmdir` and `rename`/`renameat`/`renameat2`
- per-process TCP/UDP sent/received byte totals (top-N every 5 seconds)
- systemd unit and Nix store-path suffixes on human output
- JSON Lines output (`--json`) and a read-only Unix socket API
- SQLite persistence with a background writer, 5-minute raw retention,
  5-minute activity rollups, 30-day activity retention and an incidents table
- structured journald export for startup/incidents plus bounded nearby-journal
  context on incidents
- asynchronous reverse-DNS/hosts enrichment for connect/accept/listen events
- deterministic rules: sensitive-path writes (SSH, GnuPG, cloud, browser and
  password-manager stores), persistence paths, `/nix/store` writes,
  executable-from-suspicious-location, credential sweep, bulk mutation and
  sensitive-access-then-egress
- `electric-eye status|activity|apps|app|file|network|why|incidents`

Kernel events are collected with Aya. Tracepoint offsets are discovered from
the live kernel's tracefs at startup, so the object is not tied to a specific
kernel build. A single perf attachment enables each tracepoint/kprobe
system-wide; the kernel's BPF program array is shared by all CPUs.

## Build and run (development)

The Nix flake provides the pinned userspace and eBPF toolchains:

```bash
nix develop
just build-ebpf          # bootstraps nightly-2026-01-20 + bpf-linker if needed
cargo build
sudo ./target/debug/electric-eyed --stdout
```

In another terminal:

```bash
electric-eye status
electric-eye activity
electric-eye apps
```

Without Nix, install `rustup`, `clang`, `llvm`, `lld`, `bpf-linker` (built with
LLVM 21), `sqlite` and `just`. See `docs/TOOLCHAIN.md` for the producer/reader
LLVM rule.

Useful daemon flags:

```text
--json                 emit one JSON object per line
--socket <path>        override /run/electric-eye/electric-eye.sock
--no-socket            do not start the query API
--db <path>            SQLite database path
--no-db                disable persistence
--ebpf-object <path>   override the built BPF object
--no-bpf               startup diagnostics only
```

The service stores data in `/var/lib/electric-eye/electric-eye.db` via
systemd's `StateDirectory`. Raw events are retained for 5 minutes, rolled into
5-minute activity buckets, and activities are retained for 30 days. Incidents
are stored separately for future anomaly rules.

## Arch Linux package

The packaging files live in `packaging/arch/`. A release tarball is expected next
to the PKGBUILD:

```bash
just dist
cd packaging/arch
makepkg -si
sudo systemctl enable --now electric-eye.service
systemctl status electric-eye
electric-eye status
```

The service runs as the unprivileged `electric-eye` system user with only
`CAP_BPF`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE`. Add
yourself to the `electric-eye` group to use the read-only CLI:

```bash
sudo usermod -aG electric-eye "$USER"
# log out and back in, or use: newgrp electric-eye
```

The hardening posture is checked with:

```bash
systemd-analyze security electric-eye.service
```

`packaging/systemd/electric-eye.service` currently scores **2.5 (OK)** in
offline analysis on systemd 262 and **4.1 (OK)** when inspected from a running
Arch LXC container. The remaining exposure is inherent to a kernel observer
(BPF load, perf events, ptrace read access for `/proc/<pid>/exe`, tracefs read,
outbound DNS for reverse lookups, and the local Unix socket).

## Layout

```text
crates/electric-eye-ebpf   BPF programs and ring-buffer event ABI
crates/electric-eye-core   shared event types and rendering
crates/electric-eyed       loader, enrichment, daemon and Unix socket API
crates/electric-eye-cli    electric-eye query client
crates/electric-eye-nix    Nix store-path provenance
packaging/                 Arch package, systemd unit, sysusers
tests/lxc                  isolated kernel-capture integration test
docs/TOOLCHAIN.md          LLVM/nightly/bpf-linker pinning notes
```

## Testing

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Kernel-facing testing that touches the host is run in an isolated Arch LXC
container (see `tests/lxc/capture-test.sh`). It starts the daemon on the host,
runs workloads pinned to non-zero CPUs inside the container, and asserts that
file events are captured from those CPUs.

## Known limitations / next steps

- Actual write capture currently covers `write(2)`. `writev`, `pwrite64`,
  `sendfile`, `copy_file_range` and mmap-based writes are not yet covered.
  Write syscalls are aggregated into 5-second top-32 summaries; the SQLite
  layer retains per-process/path totals after the 5-minute raw window.
- Sensitive-path rules currently see writable opens, actual writes, unlinks
  and renames, not read-only opens. Read-based credential-access and
  baseline-style novelty rules need a filtered read-open capture mode.
- Rules are deterministic and not yet baseline-aware; `nix-daemon` writes to
  `/nix/store` are exempted, but package activation and legitimate bulk
  operations can still produce incidents.
- No Quickshell UI, freeze/enforcement or NixOS packaging yet.
- Process ancestry for very short-lived processes can fall back to `(exited)`
  when `/proc/<pid>` disappears before enrichment.
- NixOS packaging and NixOS VM tests are deferred until the Arch release is
  stable.
