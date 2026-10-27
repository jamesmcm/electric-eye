# electric-eye

electric-eye explains what applications are doing: process execution, file
writes/renames/unlinks, TCP connects/listens/accepts and per-process traffic
totals, enriched with systemd units and Nix store provenance.

This tree currently targets **Arch Linux** (the NixOS module is deliberately
deferred). It is the Milestone 0 / early Milestone 1 slice: reliable kernel
attribution plus a small local query API.

## What works

- `EXEC` / `EXIT` with pid, ppid where available, uid and kernel-captured
  `(boot_id, pid, start_ns)` identity (`start_ticks` remains on EXEC)
- `CONNECT`, `LISTEN` and `ACCEPT` for IPv4/IPv6 TCP. ACCEPT is captured at
  `accept()`/`accept4()` exit, so it is attributed to the accepting server
  rather than the packet-processing context.
- `OPEN` / `CREATE` / `TRUNC` for writable opens, and aggregated actual-write
  summaries for `write(2)`, `writev`, `pwrite64`, `pwritev`, `sendfile`,
  `pwritev2`, `copy_file_range` and writable shared `mmap` intent. File
  paths are captured from kernel file objects, including inherited or duplicated
  descriptors; successful writes use returned byte counts
- filtered read-open capture for sensitive paths via an in-kernel LPM trie;
  credential reads are observable without reporting every read-only open
- `unlink`/`unlinkat`/`rmdir` and `rename`/`renameat`/`renameat2`, completed
  at syscall exit. Failed file operations have negative `syscall_result` values
  and `.attempt` history kinds; they do not add written bytes or trigger
  success-based correlations
- per-process TCP/UDP sent/received byte totals from immutable return-value
  deltas; all process totals reach history, with top-N stdout every 5 seconds
- systemd unit and Nix store-path suffixes on human output
- JSON Lines output (`--json`) and a read-only Unix socket API
- SQLite persistence with a background writer, 5-minute raw retention,
  5-minute activity rollups, 30-day activity retention and an incidents table
- structured journald export for startup/incidents plus bounded nearby-journal
  context on incidents
- asynchronous reverse-DNS/hosts enrichment for connect/accept/listen events
- deterministic rules: sensitive-path accesses (SSH, GnuPG, cloud, browser
  and password-manager stores), persistence paths, `/nix/store` writes,
  executable-from-suspicious-location, credential sweep, bulk mutation,
  sensitive-access-then-egress and novel network destinations
- baseline suppression and a per-application allowlist
  (`/etc/electric-eye/allowlist.conf`) to reduce deterministic-rule false
  positives; system authentication helpers reading shadow files are allowed by
  default
- `electric-eye status|activity|apps|app|file|network|why|incidents`

Kernel events are collected with Aya. Kernel BTF and tracefs supply live struct
and tracepoint offsets, so the object is not tied to a specific kernel build.
Linux **5.17 or newer**, kernel BTF, and raw syscall tracepoints are required.
The BPF build includes BTF function metadata for bounded path-walking callbacks;
rebuild both userspace and the BPF object when updating the event ABI.

A single perf attachment enables each tracepoint/kprobe across CPUs. Capture is
scoped to the daemon's PID namespace: running on the host observes the system,
while a daemon inside LXC observes its container. Paths use the monitored task's
filesystem root and mount namespace. `path_resolution` identifies exact kernel
paths, lexical fallbacks, or unresolved names; uncertain paths do not trigger
sensitive-resource correlations. Kernel event losses are exposed in `status` as
`capture_loss` (ring, pending syscall, identity, and path failures).

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
are stored separately as complete records with stable IDs, process identities,
executables, and affected paths. Rename rollups retain both source and destination.
Existing databases are migrated without deleting history; metadata missing from
old incident records cannot be reconstructed.

The allowlist is read from `/etc/electric-eye/allowlist.conf` (override with
`ELECTRIC_EYE_ALLOWLIST`). Each line is `<comm-or-exe> <subject-prefix>`; `*`
suppresses all rules for that identity. Known paths and network destinations
from recent events/activities form a baseline at startup, and deterministic
standalone sensitive-path novelty alerts are suppressed for previously seen file
paths. Known credential accesses still feed per-process sweep/egress correlation;
known document writes and truncations still feed bulk mutation. Bulk mutation ignores
cache/thumbnail/build directories; novel-network rules are skipped for
browsers and high-churn P2P clients.

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
packaging/                 Arch package, systemd unit, sysusers, allowlist
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
container (see `tests/lxc/capture-test.sh`). The daemon and workloads both run
inside an existing container, as its unprivileged test user; only the observer
receives BPF/perf/read capabilities. No mounts or package installation are done.

```bash
EE_LXC_NAME=ee-arch ./tests/lxc/capture-test.sh
```

The test verifies syscall failures and short writes, cwd/dirfd/symlink paths,
FD redirection, short-lived writers, aggregation beyond display limits, sensitive
reads, bulk mutation, TCP/UDP byte totals, ACCEPT endpoints, API responsiveness,
and incident identity after a daemon restart. Workloads run on a non-zero CPU.
Test artifacts are retained in fresh container directories for inspection.

## Known limitations / next steps

- `mmap` coverage reports writable shared mappings as `MMAP` intent; it does
  not track dirty-page writeback. Anonymous/private mappings are ignored.
- Sensitive read capture filters resolved absolute paths in the LPM trie,
  including successful relative opens. Home-directory prefixes are populated
  from `/etc/passwd` at startup; new accounts require a daemon restart.
- Path snapshots are bounded to 511 bytes and 80 dentry/mount steps. A missing
  VFS path hook leaves rename/unlink names marked lexical; incomplete walks
  remain unresolved. These fallbacks are visible in history.
- Write syscalls are aggregated into 5-second summaries. The top 32 are printed;
  every aggregate is persisted and every original write is evaluated by rules.
- API clients use a bounded worker pool, 16 KiB request limit, and absolute
  request/write deadlines. Journal context is fetched asynchronously with a
  200 ms subprocess deadline and output limit; base incidents are saved first.
- Baseline suppression is intentionally conservative: it only suppresses
  already-known file paths, and novelty network alerts require at least five
  known destinations for that application.
- Quickshell UI, freeze/enforcement and NixOS packaging remain future work.
- Executable and parent names are captured in the kernel, even for short-lived
  processes. Optional systemd-unit enrichment can be absent after process exit.
  Parent PID can be unavailable when observing inside a nested PID namespace.
- NixOS packaging and NixOS VM tests are deferred until the Arch release is
  stable.
