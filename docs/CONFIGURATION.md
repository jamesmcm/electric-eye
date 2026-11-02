# Configuration

The shipped defaults are in [`config/default.toml`](../config/default.toml).

## Discovery

The daemon reads **`~/.config/electric-eye/config.toml`**. Settings take effect
after restart. Discovery order is `--config <path>`, `ELECTRIC_EYE_CONFIG`,
`~/.config/electric-eye/config.toml`, the legacy
`~/.config/electriceye/config.toml`, then `/etc/electric-eye/config.toml`
(installed by the Arch package). An explicitly selected file must exist. Unknown fields, invalid sizes and
inconsistent thresholds fail startup. Partial files inherit defaults for every
omitted field and table.

## Example configuration

Create a user configuration with every supported setting:

```bash
mkdir -p ~/.config/electric-eye
electric-eyed --print-default-config > ~/.config/electric-eye/config.toml
sudo electric-eyed --config "$HOME/.config/electric-eye/config.toml" --stdout
```

The explicit path in the last command selects your file even when `sudo` changes
`HOME`. The system service runs as `electric-eye`, so it uses the system fallback;
to use your personal file, add `--config /home/your-user/.config/electric-eye/config.toml`
to its `ExecStart` override. [config/default.toml](../config/default.toml) lists all
default values. For example:

```toml
capture_argv = true
max_argv_bytes = 512
redact_arguments = ["--password", "--token", "--secret", "--api-key"]
ignore_paths = ["/home/alice/.cache"]
mcp_tools = []
raw_retention_minutes = 5
activity_retention_days = 7
process_retention_days = 7
flow_retention_days = 7
summary_retention_days = 7
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
auto_noise = true
read_prefixes = ["/home/alice/another-sensitive-directory"]

[correlation]
save_window_ms = 10000
download_window_ms = 30000

[journal]
enabled = true
timeout_ms = 200
```

## Rules and allowlists

`[rules]` has individual switches for `sensitive_path`, `credential_sweep`,
`bulk_mutation`, `suspicious_execution`, `sensitive_egress` and `novel_network`.
Custom sensitive paths also populate the kernel read-open filter. Set
`builtin_sensitive_paths = false` to replace the built-in classifications with
your own list. Browser exemptions, high-churn application exclusions, bulk noise
paths, suspicious executable locations, built-in authentication allowances and
additional allowlist entries are configurable in this table. An allowlist
`application` selects an absolute executable or an installed executable name
resolved under `/usr/bin`, `/usr/lib`, or `/usr/lib/ssh`. Exemptions require the
observed executable's device/inode to match a root-owned file beneath protected,
non-writable directories. Process comm and desktop names never grant an exemption.
`subject_prefix` matches path components; `"*"` grants a broad exemption for the
verified executable. `builtin_noise_allowlist` defaults to `true` and allowlists `tailscaled`, `thunar`, `git` and `cargo`; their activity
remains in history, but routine VPN churn and file-manager credential browsing
do not become incidents. Set it to `false` to remove those built-ins.

`ssh` is not globally allowlisted. A parent process named `git` does not grant
trust. `known_hosts_allow = true` treats an SSH destination present in the user's
`~/.ssh/known_hosts` or the system `ssh_known_hosts` as a trusted host for that
SSH process. Plain, wildcard, port-qualified, and OpenSSH hashed (`|1|...`)
entries are supported. This is a user-approved destination exception, not a
general SSH allowlist; set it to `false` to disable it. This exception also
requires a verified installed SSH executable. Known-host data is loaded in a
bounded background worker and cached for up to 60 seconds. A cache miss leaves
that SSH process eligible for alerts. Restart after executable upgrades to refresh
the identities used for automatic exemptions.

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
connections are classified as `remote`, `local_network`, `same_machine`, or
`tailscale`. Only remote sources produce high-severity incidents by default;
local and same-machine traffic remains visible in flows, while Tailscale peers
produce medium-severity incidents. Set `incoming_local_connections = true` to
also emit medium-severity local incidents. `incoming_connections = false`
disables all incoming incidents. High-churn applications such as P2P clients
are excluded from incoming alerts. Deduplication is per local port and remote
source. Incident titles and details include the source scope.

Bulk mutation severity is scope-aware: writes confined to one project or
directory are **low**, mutations spanning multiple ordinary directories are
**medium**, and mutations touching the home root, `/`, or system locations such
as `/etc`, `/usr`, `/boot` or `/root` are **high**. A low-severity
single-directory burst is treated as generated output when most affected files
were created within the same window, so builds, screen captures and generated
caches do not continuously re-alert; overwrites and removals still count. The
incident details include the computed `scope` and the affected files.

### Automatic generated-output filtering

`capture.auto_noise` (default `true`) recognises conventional build and run
output directories from the path itself: `target`, `build`, `dist`, `out`,
`artifacts`, `generated`, `coverage`, `node_modules`, `__pycache__`, virtual
environments, `*_runs`/`*-runs` directories, and similar project markers. The
first event under such a directory installs the absolute prefix into the
kernel ignore map, so the rest of the build or run is dropped before it reaches
the ring buffer. Only paths under `/home`, `/tmp`, `/var/tmp`, `/mnt` or
`/media` are considered, and credential directories are never auto-filtered.
Set `auto_noise = false` to require explicit `ignore_paths` only.

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

Flow `scope` distinguishes `localhost`, `LAN`, `tailscale`,
`tailscale-magicdns` and `Internet`. Tailscale uses the RFC 6598
`100.64.0.0/10` range and its `fd7a:115c:a1e0::/48` IPv6 prefix. MagicDNS
(`100.100.100.100` and `fd7a:115c:a1e0::53`) is treated as the local Tailscale
resolver and is not reported as an application destination or credential
egress. Other Tailscale
peers are reported as low-severity `Novel Tailscale destination` incidents
rather than Internet destinations, and sensitive-path egress to a Tailscale
peer keeps `destination_scope = "tailscale"`. Novel-network baselines are
stored as a bounded Bloom filter of hashed application/destination pairs, so a
long-running daemon does not re-alert on destinations first seen after startup.

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

## Tuning and limits

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

## Noise tuning

`electric-eye noise` inspects recent activity, incidents and summaries and lists
likely capture/rule noise candidates: high-churn path prefixes, applications
with repeated incidents, and heuristic correlations such as `download_like`. It
prints a reviewable TOML suggestion for `ignore_paths`, `rules.allowlist` and
`correlation.download_like`; it never writes configuration or restarts the
service. Wildcard allowlist entries are emitted commented out, because they are
broad and do not suppress bulk-mutation incidents; broad `~/.cache` capture
filters are not suggested. Apply a subset manually, then restart
`electric-eyed`.

## Migration

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
filesystem identity remains available. Trust checks hash an opened file only
when its device/inode matches the observed actor. Missing or mismatched identities
remain explicitly unverified. Cache keys include full modification/change times,
size, and package-index generation; refreshes invalidate previous package results.
Application grouping retains its reason and confidence; desktop files are read
as data and never executed. Desktop names and user-owned runtime metadata are
loaded in bounded background workers; initial observations can retain executable
names or generic namespace context until enrichment is available.

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
`ELECTRIC_EYE_ALLOWLIST`). Each line is `<installed-name-or-exe> <subject-prefix>`; `*`
suppresses all rules for that identity. Known paths and network destinations
from recent events/activities form a bounded baseline at startup, and network
destinations are also learned as they are first observed so they are reported as
novel once rather than on every reconnect. Deterministic standalone sensitive-path
novelty alerts are suppressed for previously seen file paths. Known credential
accesses still feed per-process sweep/egress correlation; known document writes
and truncations still feed bulk mutation. Bulk mutation ignores
cache/thumbnail/build directories; novel-network rules are skipped for
browsers and high-churn P2P clients.

## Focused sessions

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
