# electric-eye

electric-eye explains what applications are doing: process lifecycles, file
activity, TCP/UDP flows and evidence-backed activity summaries. It currently
targets **Arch Linux**, with read-only libalpm package provenance, application
and task grouping, a local query API and durable SQLite history. Nix and NixOS
are not required to build or run it on Arch.

## What works

- `FORK` / `EXEC` / `EXIT` with kernel `(boot_id, pid, start_ns)` and parent
  identities, exec generations, uid/euid and exit code/signal. Retained metadata
  includes bounded/redacted arguments, cwd, cgroup and system/user units.
  A labeled startup inventory covers processes already running at attachment.
- Read-only libalpm executable ownership with package/version snapshots,
  pacman validation status and package-mtree SHA-256 verification for
  incident evidence. Unowned, replaced, deleted or different-mount-namespace
  executables retain explicit provenance status.
- Application/task attribution from executable and interpreter/script identity,
  desktop files, application cgroups, ancestry and configurable overrides.
  Shell-launched tasks remain separate; process identities remain accessible.
- IPv4/IPv6 TCP and UDP socket lifecycles: creation, bind, connect outcomes,
  listen/accept and final close, with stable socket/namespace IDs, endpoints,
  duration, per-flow application byte totals and shared-socket contributors.
  UDP peer activity has separate rows for each remote endpoint.
- `OPEN` / `CREATE` / `TRUNC` for writable opens, and aggregated actual-write
  summaries for `write(2)`, `writev`, `pwrite64`, `pwritev`, `sendfile`,
  `pwritev2`, `copy_file_range` and writable shared `mmap` intent. File
  paths are captured from kernel file objects, including inherited or duplicated
  descriptors; successful writes use returned byte counts
- Standalone `truncate`/`ftruncate` and legacy `creat`, including syscall
  failures. Truncation paths resolve from the kernel path/FD and mutation rules
  evaluate successful truncations independently of requested write bytes.
- filtered read-open capture for sensitive paths via an in-kernel LPM trie;
  credential reads are observable without reporting every read-only open
- `unlink`/`unlinkat`/`rmdir` and `rename`/`renameat`/`renameat2`, completed
  at syscall exit. Failed file operations have negative `syscall_result` values
  and `.attempt` history kinds; they do not add written bytes or trigger
  success-based correlations
- per-process TCP/UDP sent/received byte totals from immutable return-value
  deltas; all process totals reach history, with top-N stdout every 5 seconds
- readable CLI output by default, with explicit `--json` for structured queries
- JSON Lines output (`--json`), a read-only Unix socket API, and a read-only
  Model Context Protocol (MCP) server for agent clients
- SQLite persistence with a background writer, 5-minute raw retention,
  5-minute activity rollups, tiered activity/flow/summary retention, a
  7-day default for heuristic summaries, per-severity incident retention and
  an incidents table
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
- Durable process/exec trees, application tasks, flows and summaries, independent
  of short raw-event retention. Build sessions, write/rename saves, application
  starts and download-like activity retain evidence and confidence labels.
- `electric-eye tui|doctor|status|activity|apps|app|process|tree|file|network|flows|netns|explain|focus|investigate|why|incidents|summaries|noise|db|config|export`
- built-in noise allowlist for `tailscaled`, `thunar`, `git` and `cargo`; configurable with
  `rules.builtin_noise_allowlist`

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
sensitive-resource correlations. Failed `openat` calls retry the pathname at
syscall exit, when the kernel has faulted the user page in; recovered relative
names are marked lexical. When no pathname exists, events retain the descriptor,
`dirfd`/`cwd` context, and regular-file inode/device identity in a synthetic
`unresolved:` path. Kernel event losses are exposed in `status` as
`capture_loss` (ring, pending syscall, identity, and path failures; a path
failure keeps the event but marks its path uncertain).

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
LLVM 21), `sqlite`, `pacman` (libalpm) and `just`. See `docs/TOOLCHAIN.md` for the producer/reader
LLVM rule.

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

The service stores data in `/var/lib/electric-eye/electric-eye.db` via
systemd's `StateDirectory`. Retention is tiered:

- raw events: 5 minutes
- general activity buckets: 30 days
- process/exec history: 30 days
- flow documents: 30 days
- summary documents: 30 days
- heuristic summaries (likely noise): 7 days
- low-severity incidents: 30 days
- medium-severity incidents: 90 days
- high-severity incidents: 365 days

`noise_retention_days` applies to summaries with `confidence = "heuristic"`
(for example download-like guesses); correlated/observed summaries use
`summary_retention_days`. Low-severity incidents are not automatically
discarded as noise; use `incident_low_retention_days` to shorten that class.

Incidents are complete records with stable IDs, journal context, actor and
path snapshots, so high-severity evidence remains available for the incident
retention window even when raw events have aged out. Raise raw, activity, flow
or summary retention if you need deeper context around high incidents. Rename
rollups retain both source and destination. Existing databases are migrated
without deleting history; missing metadata in old records cannot be reconstructed.

## Configuration and interpretation

The daemon reads **`~/.config/electric-eye/config.toml`**. Settings take effect
after restart. Discovery order is `--config <path>`, `ELECTRIC_EYE_CONFIG`,
`~/.config/electric-eye/config.toml`, the legacy
`~/.config/electriceye/config.toml`, then `/etc/electric-eye/config.toml`
(installed by the Arch package). An explicitly selected file must exist. Unknown fields, invalid sizes and
inconsistent thresholds fail startup. Partial files inherit defaults for every
omitted field and table.

Create a user configuration with every supported setting:

```bash
mkdir -p ~/.config/electric-eye
electric-eyed --print-default-config > ~/.config/electric-eye/config.toml
sudo electric-eyed --config "$HOME/.config/electric-eye/config.toml" --stdout
```

The explicit path in the last command selects your file even when `sudo` changes
`HOME`. The system service runs as `electric-eye`, so it uses the system fallback;
to use your personal file, add `--config /home/your-user/.config/electric-eye/config.toml`
to its `ExecStart` override. [config/default.toml](config/default.toml) lists all
default values. For example:

```toml
capture_argv = true
max_argv_bytes = 512
redact_arguments = ["--password", "--token", "--secret", "--api-key"]
ignore_paths = ["/home/alice/.cache"]
mcp_tools = []
raw_retention_minutes = 5
activity_retention_days = 30
process_retention_days = 30
flow_retention_days = 30
summary_retention_days = 30
noise_retention_days = 7
incident_high_retention_days = 365
incident_medium_retention_days = 90
incident_low_retention_days = 30

[[grouping]]
executable = "/opt/editor/editor"
application = "Editor"

[[focus]]
name = "codex-project"
applications = ["codex"]
paths = ["/home/alice/work/project"]
# Empty log_paths enables auto-detection of Codex/OpenCode/Hermes/Omarchy logs.

[rules]
bulk_file_threshold = 50
bulk_window_ms = 10000
incoming_local_connections = false
sensitive_window_ms = 60000
dedup_window_ms = 300000
novel_network_min_destinations = 5
max_actors = 8192
max_events_per_actor = 4096
max_dedup_entries = 32768

[[rules.allowlist]]
application = "/usr/bin/example"
subject_prefix = "/home/alice/private"

[[rules.sensitive_paths]]
prefix = "/home/alice/project/secrets"
category = "Project credentials"
severity = "high"

[limits]
aggregation_ms = 5000
flow_entries = 32768
api_workers = 4
api_timeout_ms = 500

[capture]
ring_bytes = 16777216
read_prefixes = ["/home/alice/another-sensitive-directory"]

[correlation]
save_window_ms = 10000
download_window_ms = 30000

[journal]
enabled = true
timeout_ms = 200
```

`[rules]` has individual switches for `sensitive_path`, `credential_sweep`,
`bulk_mutation`, `suspicious_execution`, `sensitive_egress` and `novel_network`.
Custom sensitive paths also populate the kernel read-open filter. Set
`builtin_sensitive_paths = false` to replace the built-in classifications with
your own list. Browser exemptions, high-churn application exclusions, bulk noise
paths, suspicious executable locations, built-in authentication allowances and
additional allowlist entries are configurable in this table. An allowlist
`application` matches a process comm or absolute executable; `subject_prefix = "*"`
suppresses every detection rule for that identity. `builtin_noise_allowlist`
defaults to `true` and allowlists `tailscaled`, `thunar`, `git` and `cargo`; their activity
remains in history, but routine VPN churn and file-manager credential browsing
do not become incidents. Set it to `false` to remove those built-ins.

`ssh` is not globally allowlisted. An `ssh` process launched by `git` for a
GitHub or GitLab remote is recognized contextually from its parent and
command-line destination; those key reads and connections are suppressed.
Other SSH use remains visible and can be allowlisted explicitly by destination.

`known_hosts_allow = true` also treats an SSH destination present in the user's
`~/.ssh/known_hosts` or the system `ssh_known_hosts` as a trusted host for that
SSH process. Plain, wildcard, port-qualified, and OpenSSH hashed (`|1|...`)
entries are supported. This is a user-approved destination exception, not a
general SSH allowlist; set it to `false` to disable it.

Destination allowlists apply to outbound connects and incoming accepts:

```toml
[[rules.network_allowlist]]
application = "sshd"
destination = "192.168.0.0/16"
direction = "inbound"

[[rules.network_allowlist]]
application = "backup"
destination = "backup.example.com"
direction = "outbound"
```

`destination` accepts a hostname, hostname suffix, exact IP, or CIDR. Incoming
connections are classified as `remote`, `local_network`, or `same_machine`.
Only remote sources produce incidents by default; local and same-machine
traffic remains visible in flows. Set `incoming_local_connections = true` to
also emit medium-severity local incidents. `incoming_connections = false`
disables all incoming incidents. High-churn applications such as P2P clients
are excluded from incoming alerts. Deduplication is per local port and remote
source. Incident titles and details include the source scope.

Bulk mutation severity is scope-aware: writes confined to one project or
directory are **low**, mutations spanning multiple ordinary directories are
**medium**, and mutations touching the home root, `/`, or system locations such
as `/etc`, `/usr`, `/boot` or `/root` are **high**. The incident details include
the computed `scope` and the affected files.

### Network semantics

Flows carry a `network_context` object describing the namespace they happened
in. The daemon resolves the namespace inode to `host`, `vopono`, `docker`,
`podman`, `lxc`, `kubernetes`, or a named namespace, together with the systemd
unit, cgroup, VPN flag, addresses, and published ports where available. For
vopono it reads only the `VOPONO_NS`, `VOPONO_NS_IP`, `VOPONO_NS_IPV6`,
`VOPONO_HOST_IP`, `VOPONO_HOST_IPV6`, `VOPONO_OPEN_PORTS` and
`VOPONO_HOST_FORWARDED_PORTS` environment keys; the raw environment is never
stored. It also reads the user-owned vopono lockfiles to attach the namespace's
provider, protocol, server, application PIDs, open ports, host-forwarded ports
and provider-forwarded port. This is the same metadata exposed by
`vopono status --json` and vopono's MCP `status` tool, but electric-eye reads
the lockfiles directly so it does not depend on a vopono binary or daemon
version. The raw lockfile is not exposed. When vopono monitoring is enabled,
`health.json` is also summarised (state, last probe, WireGuard handshake age,
reconnect attempts and last error); stale samples are marked degraded. The
provider forwarded-port sidecar is merged with the lockfile's provider and
automatic flag, so renewals are reflected without exposing the sidecar.

Docker and Podman published ports are read from their container metadata,
including the host-port to container-port mapping. This lets a listener inside
a container be marked `published` even when the namespace-local port differs
from the host port. LXC uses its configured static addresses plus host DNAT
rules as a best-effort fallback, because LXC has no standard published-port
field. Container name, runtime, image, id, addresses and published mappings are
included in `network_context.container`.

Each flow also has a conservative role and exposure:

- `listener`, `inbound`, `outbound`, `udp_peer`, `dns`, `lpd`, `tracker`,
  `failed`, or `socket`
- `loopback`, `local_network`, `all_interfaces`, `published`, or `n/a`

These roles are port/state heuristics. DHT, tracker and BitTorrent payloads are
not inspected, so `udp_peer` covers DHT, µTP and other UDP peer discovery.

Use `electric-eye netns` to list network contexts, listeners, published ports,
vopono provider/protocol/server details, namespace applications and per-context
byte totals. The Applications view has a CONTEXT column and `c`/`v` cycle
context and role filters; the flow table has CONTEXT and ROLE columns.
`electric-eye flows --netns vopono --role listener` filters the CLI flow table.
`electric-eye explain network Transmission` combines
flows, context, roles and file activity into a short verdict such as “idle
listener / control-plane only”. For historical flows recorded before semantic
enrichment, `explain network` excludes them from the verdict and reports how
many legacy flows were found.

Interpreter identity includes the program the user asked to run: `python3
script.py`, `python3 -m module`, `python3 -`, `uv run python script.py`, `env`,
`sudo`, `poetry run`, `pipx run`, `npx` and similar launchers are reduced to the
script or package name rather than the interpreter binary.

`known_hosts`, `known_hosts.old` and `known_hosts2` are public host-key files,
not credential stores, and are not classified as SSH credential access. This
avoids false sensitive-egress incidents from clients such as `curl` that read
`~/.ssh/known_hosts` during normal startup. Private keys and SSH configuration
remain classified.

Opening or listing a sensitive directory is metadata access, not reading the
credentials inside it. Directory opens are still recorded, but only files
inside a sensitive directory produce sensitive-path incidents. This prevents a
file manager that merely enumerates `~/.aws`, `~/.ssh` or `~/.gnupg` from
looking like a credential read.

Download-like summaries ignore high-churn non-browser applications and paths
under caches, logs, `.mozilla`, `.hermes`, `.local/share/opencode`, build
`target` trees and similar database/log artifacts. The heuristic still says
“content linkage is unverified”; use `electric-eye --json summaries` before
treating a write as proof of downloaded content.

`[limits]` controls aggregation size/timing, recent caches, per-flow contributors,
application members, summary evidence/files, DNS cache and lookup concurrency,
API workers/queues/request limits/deadlines, storage queue/batches/flush timing,
activity buckets and collector drain batches. `[capture]` controls ring/map sizes,
read prefixes and noise paths. `[correlation]` controls each summary rule, its
windows and compiler identification. `[journal]` controls enrichment queues,
context, deadlines and output sizes. `electric-eye --json status` reports the
effective configuration.

Anomaly actors and deduplication keys expire independently of future activity
from the same actor, and exits discard actor windows. Capacity limits also bound
state during bursts; pressure can shorten correlation coverage. Lower limits can
therefore trade coverage for memory. Structural kernel ABI ceilings remain fixed:
paths and argv snapshots are at most 512 bytes, and filter prefixes are at most
128 bytes. Runtime limits and rule thresholds are configurable within validated
allocation and arithmetic bounds.

`ignore_paths` and `capture.noise_paths` are installed in a kernel LPM trie and
filtered before ring submission when the path was resolved. The userspace fast
path repeats the check for unresolved names, then reuses process metadata
instead of reading `/proc/<pid>/stat` for every event. `capture.ring_bytes` is a
burst buffer, not a throughput fix: a larger ring absorbs a spike but cannot
keep up with a sustained event rate above the consumer's capacity. Monitor
`capture_loss[0]` and `store.dropped`; add noisy paths to `ignore_paths` or
`capture.noise_paths`, then increase the ring (64–256 MiB is reasonable on a
busy desktop) only after filtering.

`electric-eye noise` inspects recent activity, incidents and summaries and lists
likely capture/rule noise candidates: high-churn path prefixes, applications
with repeated incidents, and heuristic correlations such as `download_like`. It
prints a reviewable TOML suggestion for `ignore_paths`, `rules.allowlist` and
`correlation.download_like`; it never writes configuration or restarts the
service. Wildcard allowlist entries are emitted commented out, because they are
broad and do not suppress bulk-mutation incidents; broad `~/.cache` capture
filters are not suggested. Apply a subset manually, then restart
`electric-eyed`.

The former JSON configuration is replaced by TOML; convert existing overrides
and select the new file when upgrading.

Arguments are capped at 512 bytes and marked when truncated. Redaction covers
configured `--flag value` and `--flag=value` forms before history is stored;
`capture_argv: false` omits arguments. It does not recognize secrets in arbitrary
positional arguments. `ignore_paths` uses path-component boundaries and drops
matching file observations before storage/detection; a rename crossing the
boundary remains visible. Grouping overrides match the absolute executable path.

`process` accepts a PID or stable ID, and includes exec history; `tree` shows
retained descendants. Numeric PIDs can match multiple historical generations;
use a stable ID to select one. Startup inventory identities are approximate and
explicitly labeled; matching exact kernel observations supersede them.

Package ownership is a local installed-database snapshot. Incidents now include a
`package_trust` block with:

- package name/version and pacman `%VALIDATION%` (`pgp`, `none`, ...)
- source classification (`arch_repo_signed` vs `unsigned_or_foreign`)
- SHA-256 expected from the package `mtree` and the actual executable hash
- status such as `arch_signed_unmodified`, `arch_signed_modified`,
  `unsigned_or_foreign_unmodified`, `unowned` or `unverified`

AUR/foreign packages are usually unsigned, so “unsigned_or_foreign” is a trust
signal, not a malware verdict. Hashing is performed on demand for incidents and
cached; it is not run for every syscall. Historical snapshots are retained
across upgrades. If libalpm or package mtree data is unavailable, executable
filesystem identity remains available.
Application grouping retains its reason and confidence; desktop files are read
as data and never executed.

`flows` reports successful application I/O bytes, excluding packet headers and
retransmissions. Shared sockets keep their original owner and list contributing
process identities. `summaries` distinguishes observed sequences, correlations
and heuristics. A build root exit code does not prove every output is complete;
network-receive/file-write timing does not prove that received content was saved.
Summary evidence embeds bounded observations alongside event/flow references so
it remains useful after raw-event compaction. Use `--json` for complete evidence,
`--limit <1..1000>` for list size, and `--help` for commands. Human output shows
relative times, exec generations and flow actors/contributors instead of raw
JSON evidence dumps.

All query commands support recent observations with `--no-db`; SQLite adds
history across restarts and raw-event compaction. Process lookups select the
requested identity before limiting results. Compacted application history keeps
its name, task ID and executable/comm attribution. Flows from a previous daemon
session that lacked an observed close are labeled `observation_ended`, retaining
their last known state without inventing a close time.

Recent query buffers and correlation caches are bounded independently of SQLite
retention. Closed socket state is reclaimed; live process metadata remains until
exit. If capacity pressure evicts an active flow, later I/O starts a distinct,
explicitly partial observation segment so saved totals are preserved. Application
membership snapshots and summary file/evidence lists expose truncation. `status`
reports kernel capture losses and storage drops; sustained whole-system load is
not yet covered by a throughput benchmark.

Legacy additional allowlist entries are also read from `/etc/electric-eye/allowlist.conf` (override with
`ELECTRIC_EYE_ALLOWLIST`). Each line is `<comm-or-exe> <subject-prefix>`; `*`
suppresses all rules for that identity. Known paths and network destinations
from recent events/activities form a bounded baseline at startup, and deterministic
standalone sensitive-path novelty alerts are suppressed for previously seen file
paths. Known credential accesses still feed per-process sweep/egress correlation;
known document writes and truncations still feed bulk mutation. Bulk mutation ignores
cache/thumbnail/build directories; novel-network rules are skipped for
browsers and high-churn P2P clients.

## Focused sessions and investigation bundles

`[[focus]]` rules make project/agent monitoring automatic. A rule matches by
application/comm/executable substring and optional path prefixes:

```toml
[[focus]]
name = "codex-project"
applications = ["codex"]
paths = ["/home/alice/work/project"]
log_paths = []  # empty: auto-detect known harness logs
```

Running `electric-eye focus` summarises each configured focus rule with recent
matching activity, flows, incidents and detected harness logs. `--json` returns
the full matching rows (bounded by `--limit`) for session review/export. Focus rules are
also automatically attached to investigation bundles when an incident matches.

`electric-eye investigate <incident-id>` renders a complete Markdown prompt
containing the incident, actor, package trust, journal/file/network evidence,
focused-session metadata and auto-detected harness log paths. It does not call
a model. `--json` returns the full structured bundle instead of just the prompt.

The same output is available over MCP as the `investigate` tool. An agent in
OpenCode, Hermes, OMP or any other MCP-capable harness can call it directly:

```text
investigate(id="<incident-id>")
```

or from a shell:

```bash
electric-eye investigate <incident-id>
electric-eye investigate <incident-id> --json
```

Harness logs are detected for Codex, OpenCode, Hermes, Omarchy, OMP and similar
agent names, plus generic `.config`/`.local/share`/`.local/state` locations.
The prompt lists the detected file paths; it does not silently upload log
contents. The user's harness can read only the files it is permitted to access.
No HTTPS interception, proxy or bundled model runtime is required.

## MCP server and agent skill

The daemon starts a read-only MCP server at `/run/electric-eye/mcp.sock` by
default. To keep agent context small, the default profile exposes only:

`status`, `activity`, `apps`, `flows`, `incidents`, `focus`, `investigate`.

The full profile adds `app`, `process`, `tree`, `file`, `network`, `summaries`,
`why` and `noise`. Enable it in config:

```toml
mcp_tools = ["all"]
```

or a custom subset:

```toml
mcp_tools = ["status", "incidents", "investigate", "focus"]
```

or at daemon start:

```bash
electric-eyed --mcp-tools all
electric-eyed --mcp-tools status,incidents,flows
```

The MCP server also exposes `electric-eye://status`, `electric-eye://activity`
and `electric-eye://incidents` resources. All tools are annotated read-only and
return structured JSON; the MCP server has no write operations.

MCP clients that use the stdio transport can launch the CLI bridge:

```jsonc
{
  "mcp": {
    "servers": {
      "electric-eye": {
        "type": "local",
        "command": ["electric-eye", "mcp"]
      }
    }
  }
}
```

The bridge connects stdin/stdout to the daemon's Unix socket, so the daemon must
be running with MCP enabled. Disable the daemon endpoint with `--no-mcp`, or
move it with `--mcp-socket <path>` / `ELECTRIC_EYE_MCP_SOCKET`. The CLI bridge
also accepts `--mcp-socket <path>`. MCP access uses the same
`electric-eye`-group and socket permissions as the query API. When the daemon
restarts, existing local MCP bridge processes exit; run `opencode reload` (or
use `/mcps` in the TUI) to reconnect them.

The installable agent skill lives at
[`.opencode/skills/electric-eye/SKILL.md`](.opencode/skills/electric-eye/SKILL.md)
and is auto-discovered when working in this repository. Install it into your
global OpenCode configuration with:

```bash
just install-skill
```

That copies `SKILL.md` and `references/queries.md` to
`~/.config/opencode/skills/electric-eye/` (respecting `XDG_CONFIG_HOME`). The
Arch package also installs the source under
`/usr/share/electric-eye/skills/electric-eye/`.

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

The PKGBUILD lives in `packaging/arch/` in the repository and is published to
the AUR. It downloads the tagged source archive from GitHub, so a packaged
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
.opencode/skills/          installable agent skill and query reference
scripts/                   Arch toolchain sanitization for Nix shells
packaging/                 Arch package, systemd unit, man pages, sysusers, allowlist
tests/lxc                  isolated kernel-capture integration test
tests/load                 controlled ring/consumer burst generator
docs/TOOLCHAIN.md          LLVM/nightly/bpf-linker pinning notes
docs/PERFORMANCE.md        load-test method, measurements and tuning notes
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

Ring-buffer load-test methodology, measurements and tuning guidance are in
[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md). A controlled burst generator is
available at [`tests/load/ring-burst.py`](tests/load/ring-burst.py):

```bash
python3 tests/load/ring-burst.py --count 20000
python3 tests/load/ring-burst.py --count 30000 --path /dev/null
```

```bash
EE_LXC_NAME=ee-arch ./tests/lxc/capture-test.sh
```

The test verifies syscall failures and short writes, cwd/dirfd/symlink paths,
FD redirection, short-lived writers, aggregation beyond display limits, sensitive
reads, bulk mutation, TCP/UDP byte totals, ACCEPT endpoints, API responsiveness,
fork/exec trees and redacted arguments, package ownership, application tasks,
shared sockets, IPv4/IPv6 flows, standalone truncation, compilation/save/download-like
summaries, history after a daemon restart, and all CLI/query routes without SQLite, startup metadata supersession, cleared
`SO_ERROR`, UDP destination detection, IPv4-mapped local addresses and nondefault
TOML settings. Workloads run on a non-zero CPU.
Test artifacts are retained in fresh container directories for inspection.
MCP protocol initialization, tool discovery, structured tool calls, resource
reads, notification handling, and the Unix-socket round trip are covered by
daemon unit tests; the CLI bridge is covered by command-line parsing tests.

## Known limitations / next steps

- `mmap` coverage reports writable shared mappings as `MMAP` intent; it does
  not track dirty-page writeback. Anonymous/private mappings are ignored.
- Sensitive read capture filters resolved absolute paths in the LPM trie,
  including successful relative opens. Home-directory prefixes are populated
  from `/etc/passwd` at startup; new accounts require a daemon restart.
- Path snapshots are bounded to 511 bytes and 80 dentry/mount steps. A missing
  VFS path hook leaves rename/unlink names marked lexical; incomplete walks
  remain unresolved. Failed opens retry at syscall exit and keep relative-name
  lexical fallbacks; pathless descriptors carry fd/dirfd/cwd and inode/device
  identity in the synthetic path. These fallbacks are visible in history.
- Write syscalls default to 5-second summaries, printing the top 32; these
  limits are configurable.
  Every aggregate is persisted and every original write is evaluated by rules.
- API clients default to a bounded worker pool, a 16 KiB request limit, and absolute
  request/write deadlines. Journal context is fetched asynchronously with a
  200 ms subprocess deadline and output limit; base incidents are saved first.
- Baseline suppression is intentionally conservative: it only suppresses
  already-known file paths, and novelty network alerts require at least five
  known destinations for that application by default.
- Quickshell UI, freeze/enforcement and NixOS packaging remain future work.
- Kernel metadata is bounded: argv/cwd/cgroup snapshots can be truncated or
  unavailable, and namespace-external parents may have no visible PID. Startup
  inventory is observational and cannot reconstruct activity before attachment.
- Socket hooks account for ordinary TCP/UDP application I/O; packet capture,
  DNS request decoding and mmap dirty-page accounting are separate capabilities.
  Event loss counters must be considered when interpreting incomplete histories.
- NixOS packaging and NixOS VM tests are deferred until the Arch release is
  stable.
