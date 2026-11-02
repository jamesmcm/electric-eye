# Architecture and evidence model

electric-eye is a read-only sensor. It observes kernel activity, keeps bounded
evidence in memory and SQLite, and exposes queries over a local socket. It does
not intercept HTTPS, proxy traffic, enforce policy or inject into processes.

## Evidence model

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
  `rules.builtin_noise_allowlist`; exemptions require the observed device/inode
  of an executable in a protected, root-owned system location

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
failure keeps the event but marks its path uncertain). Runtime-generated output
roots installed by automatic noise detection are listed in
`status.auto_noise_prefixes`.

## Storage and retention

The service stores data in `/var/lib/electric-eye/electric-eye.db` via
systemd's `StateDirectory`. Standalone launches also create private databases
and sidecars; unsafe existing database files are refused without modification.
User-owned desktop, known-host and runtime metadata is read through bounded
workers so those files cannot stall kernel event consumption. Retention is tiered:

- raw events: 5 minutes
- general activity buckets: 7 days
- process/exec history: 7 days
- flow documents: 7 days
- summary documents: 7 days
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
