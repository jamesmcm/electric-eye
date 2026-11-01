# Operations

## Build and run

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
electric-eye process 1234
electric-eye tree 1234
electric-eye flows
electric-eye netns
electric-eye flows --netns vopono --role listener
electric-eye explain network Transmission
electric-eye summaries
electric-eye focus
electric-eye investigate <incident-id>
electric-eye noise
electric-eye incidents --since 1h --severity high
electric-eye incidents --unacked
electric-eye ack <incident-id>
electric-eye mute curl novel_network --for 1h
electric-eye activity --follow
electric-eye doctor
electric-eye tui
electric-eye db status
electric-eye --limit 200 flows
electric-eye --json process 1234
```

Without Nix, install `rustup`, `clang`, `llvm`, `lld`, `bpf-linker` (built with
LLVM 21), `sqlite`, `pacman` (libalpm) and `just`. See [Toolchain](TOOLCHAIN.md) for the producer/reader LLVM rule.

On Arch Linux, build the installable release with:

```bash
just release
```

`just release` detects Arch and switches to the system Rust, pkg-config, sqlite
and glibc toolchain even if it is invoked from `nix develop`. This is required
for package provenance: a release built with the Nix toolchain links Nix glibc
and cannot `dlopen` Arch's system `libalpm.so`. The recipe also verifies that
neither release binary has `/nix/store` library references. `just build` uses
the same sanitized environment for the debug daemon. The Nix dev shell remains
useful for the pinned compiler toolchain and BPF work.

Useful daemon flags:

```text
--json                 emit one JSON object per line
--socket <path>        override /run/electric-eye/electric-eye.sock
--no-socket            do not start the query API
--mcp-socket <path>    override /run/electric-eye/mcp.sock
--mcp-tools <profile>  default, all, or a comma-separated tool list
--no-mcp               do not start the MCP server
--config <path>        TOML runtime configuration
--db <path>            SQLite database path
--no-db                disable persistence
--ebpf-object <path>   override the built BPF object
--no-bpf               startup diagnostics only
```

## TUI and operations

`electric-eye tui` is a capture-read-only terminal client with Overview,
Incidents, Activity, Apps & Flows, and Noise views. It polls the same Unix
socket as the CLI every two seconds; `1`–`5`/Tab switch views, `h`/`[` and
`l`/`]` cycle list/detail focus (wrapping), `j`/`k` select with wrap-around,
`PgUp`/`PgDn` page and `Ctrl+U`/`Ctrl+D` half-page the focused list or detail,
and the mouse wheel scrolls the focused pane. Mouse clicks select rows, focus
panes, switch tabs and choose the network scope. `Space`/`p` freezes the
screen, `s` cycles network scope (All/Same machine/Local network/Remote), `c`
cycles the context filter (all/host/vopono/container), `v` cycles the role
filter, `f` toggles follow, `r` refreshes, `a`/`A` acknowledge/unacknowledge an incident,
`m`/`u` mute/unmute its application+rule for one hour, `?` opens help, `Esc`
closes help without quitting, and `q` quits.
Acknowledgements and mutes are stored in a user-owned review file and never
modify the daemon or capture stream. The network scope tabs filter the live
flow table and recompute per-application flow and byte aggregates. The flow
table shows application, namespace/container context, role/protocol,
endpoints, and bytes. Incident details include the application or script name,
command arguments, and a bounded list of changed files for bulk-mutation
incidents.

TUI screenshots (fictional demo data): [Overview](screenshots/tui-overview.png),
[Incidents](screenshots/tui-incidents.png), [Activity](screenshots/tui-activity.png),
[Apps & Flows](screenshots/tui-apps-flows.png), [Noise](screenshots/tui-noise.png),
[Help](screenshots/tui-help.png).

`electric-eye doctor` checks the installation end to end: systemd state, socket
and group access, BTF, tracefs (including the case where only the daemon can
read it), attached probes, capture loss, storage drops, disk headroom,
effective configuration, and noise candidates. It prints actionable hints and
exits non-zero only for actual failures.

`electric-eye db status` reports database/WAL/SHM size, raw event and rollup
counts, document collections, retention, activity window, page utilization and
filesystem headroom. `electric-eye db compact` flushes pending writes,
VACUUMs the database and truncates the WAL; it is a maintenance operation, not
a capture reset.

`electric-eye config show` prints the effective TOML and
`electric-eye config validate <path>` validates a file without starting the
daemon. `electric-eye noise` produces reviewable tuning suggestions.

Incident review state is local: `ack`, `unack`, `mute` and `unmute` update
`$XDG_STATE_HOME/electric-eye/incidents.json` (or
`~/.local/state/electric-eye/incidents.json`). The file records the incident
ID or the application+rule mute and its expiry, making the decision auditable.
`electric-eye incidents --unacked` hides locally acknowledged or muted entries.
The daemon never receives these writes.

List queries support `--since`, `--before`, `--limit`, `--severity`, `--rule`
and `--app`; activity supports `--follow`. Activity and incident JSON responses
include a stable `next_cursor`; pass it with `--cursor` to continue without
duplicating same-millisecond rows. `--jsonl` emits one object per line, and
`electric-eye export <kind> --since 24h` writes JSONL for activity, incidents,
flows, summaries, apps or noise. Shell completions are available:

```bash
electric-eye completions bash
electric-eye completions zsh
electric-eye completions fish
```

Man pages are installed as `electric-eye(1)` and `electric-eyed(8)`.

## Arch Linux package

The PKGBUILD lives in [`packaging/arch/`](../packaging/arch/) in the repository
and is published to the AUR as `electric-eye` and `electric-eye-bin`. It downloads the tagged source archive from GitHub, so a packaged
install is:

```bash
cd packaging/arch
makepkg -si
sudo systemctl enable --now electric-eye.service
systemctl status electric-eye
electric-eye status
```

Maintainers regenerate the uploaded tarball from a committed release tag with
`just dist`; `makepkg` fetches the same filename from the GitHub release, so the
PKGBUILD checksum and the published asset stay in sync.

The daemon is intended to run as its own unprivileged `electric-eye` system
user, not as root or your desktop user. The group grants only read-only socket
access; daemon capabilities and state remain owned by `electric-eye`. The
service uses only `CAP_BPF`, `CAP_PERFMON`, `CAP_DAC_READ_SEARCH` and
`CAP_SYS_PTRACE`. Add yourself to the `electric-eye` group to use the read-only
CLI:

```bash
sudo usermod -aG electric-eye "$USER"
# log out and back in, or use: newgrp electric-eye
```

The hardening posture is checked with:

```bash
systemd-analyze security electric-eye.service
```

[`packaging/systemd/electric-eye.service`](../packaging/systemd/electric-eye.service) currently scores **2.5 (OK)** in
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
.opencode/skills/          installable agent skill and query reference
scripts/                   Arch toolchain sanitization for Nix shells
packaging/                 Arch package, systemd unit, man pages, sysusers, allowlist
tests/lxc                  isolated kernel-capture integration test
tests/load                 controlled ring/consumer burst generator
docs/TOOLCHAIN.md          LLVM/nightly/bpf-linker pinning notes
docs/PERFORMANCE.md        load-test method, measurements and tuning notes
```
