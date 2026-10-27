---
name: Electric Eye
description: Investigate Linux process, file, network, summary, and incident activity observed by the electric-eye eBPF daemon. Use for "what is this program doing", incident triage, file/network provenance, and agentic review of recent system activity.
---

# Electric Eye

Electric Eye is a read-only Linux activity monitor. It observes process
lifecycles, file opens/reads/writes/renames/unlinks, TCP/UDP flows, and
evidence-backed activity summaries. It never enforces, freezes, or blocks
anything.

## Before you start

1. Check that the daemon is healthy:
   - MCP tool: `status`
   - CLI: `electric-eye status`
   - Full installation check: `electric-eye doctor`
2. If the query fails, inspect the service:
   - `systemctl status electric-eye`
   - `journalctl -u electric-eye -n 100 --no-pager`
3. Confirm the socket:
   - query API: `/run/electric-eye/electric-eye.sock`
   - MCP: `/run/electric-eye/mcp.sock`
4. Ask before treating missing data as proof of no activity. Capture loss,
   retention, path-resolution fallbacks, and process-startup inventory all
   create explicit gaps.

The CLI and MCP server are read-only. Do not try to use them to change system
state.

## Preferred interfaces

If an MCP client is configured, use the tools exposed by the `electric-eye`
server: `status`, `incidents`, `activity`, `apps`, `app`, `process`, `tree`,
`file`, `network`, `flows`, `summaries`, `why`, `noise`.

Otherwise use the CLI:

```bash
electric-eye status
electric-eye incidents
electric-eye activity --limit 200
electric-eye apps
electric-eye app <name-or-id>
electric-eye process <pid-or-stable-id>
electric-eye tree <pid-or-stable-id>
electric-eye file /absolute/path
electric-eye why /absolute/path
electric-eye network
electric-eye flows
electric-eye netns
electric-eye flows --netns vopono --role listener
electric-eye explain network <app>
electric-eye focus
electric-eye investigate <incident-id>
electric-eye summaries
electric-eye noise
electric-eye incidents --since 1h --severity high
electric-eye incidents --unacked
electric-eye activity --follow
electric-eye doctor
electric-eye db status
electric-eye ack <incident-id>
electric-eye mute curl novel_network --for 1h
electric-eye tui
```

Use `--json` whenever you need complete evidence. Human output intentionally
summarizes long lists and truncates summary evidence.

To configure the daemon's MCP server in OpenCode:

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

`electric-eye mcp` is a stdio bridge to the daemon's Unix-socket MCP endpoint.
The daemon starts MCP by default. The default tool profile is intentionally
compact: `status`, `activity`, `apps`, `flows`, `incidents`, `focus` and
`investigate`. Set `mcp_tools = ["all"]` (or a custom list) in the daemon config,
or start it with `--mcp-tools all` / `--mcp-tools status,incidents,flows`, when
an agent needs `app`, `process`, `tree`, `file`, `network`, `summaries`, `why`
or `noise`. Start with `--no-mcp` to disable MCP, or use `--mcp-socket <path>` /
`ELECTRIC_EYE_MCP_SOCKET` to move it. The bridge accepts `--mcp-socket <path>`
too. If the MCP tools disappear after a daemon restart, run `opencode reload`
or use `/mcps` in the TUI to reconnect the bridge.

## Investigation workflow

1. **Health and coverage**
   - Run `status` first.
   - Check `capture_loss`, `store.dropped`, `events_total`, attached/skipped
     probes, uptime, and the effective config.
   - High loss or drops mean the history is incomplete.

2. **Incidents first**
   - Run `incidents --limit 200` (or MCP `incidents`).
   - Read the incident `details`, `severity`, `comm`, `path`, process identity,
     and evidence.
   - Incidents are deterministic-rule findings, not malware verdicts.

3. **Recent activity**
   - Run `activity` to see the newest observations.
   - Filter by application with `app`, by process with `process`/`tree`, by file
     with `file`/`why`, and by network with `network`/`flows`.
   - Use `--limit` deliberately; very large limits can bury the signal.

4. **Drill into an actor**
   - `process <pid>` shows metadata and every retained exec generation.
   - `tree <pid>` shows retained descendants; use it to distinguish a launcher
     from the actual worker.
   - Numeric PIDs can match multiple historical generations. Prefer a stable
     identity (`boot_id:pid:start_ns`) when the answer must be unambiguous.

5. **Correlate file and network behavior**
   - `why <path>` answers who touched a path and includes attempt/outcome
     evidence.
   - `flows` shows TCP/UDP lifecycles, byte totals, duration, errors, and
     contributors for shared sockets.
   - `summaries` shows build sessions, save sequences, application startup, and
     download-like behavior with confidence labels.

6. **Write a careful finding**
   - State what was observed, when, by which process/application, and from which
     evidence.
   - Separate observation from inference.
   - Call out uncertainty labels, truncation, capture loss, and retention gaps.
   - Do not claim file contents, successful completion, or intent unless the
     evidence supports it.

## Reducing noise

Use `noise` / `electric-eye noise` before recommending a permanent filter. It
reports high-churn path prefixes, applications with repeated incidents, and
heuristic summaries that are likely noise, plus a suggested TOML snippet. The
command is read-only; review the snippet and apply only the entries that match
the user's intent. Wildcard allowlist entries are intentionally commented out:
they are broad and do not suppress bulk-mutation incidents.

Incident `ack`/`mute` commands and the TUI review keys only update a local
`incidents.json` review file; they do not alter the daemon, capture stream or
configuration. Use them for triage, not as a substitute for fixing a rule.

The TUI is capture-read-only. `h`/`[` and `l`/`]` cycle list/detail panes
(wrapping), `j`/`k` select with wrap-around, `PgUp`/`PgDn` and
`Ctrl+U`/`Ctrl+D` scroll the focused pane, the mouse wheel scrolls, and mouse
clicks select rows, focus panes, switch tabs and choose the network scope.
`Space` freezes the screen, `s` cycles network scope (All/Same machine/Local
network/Remote), and `c`/`v` cycle context and role filters. `?` opens help;
`Esc` closes help without quitting. Incident
details show the actual script name, command arguments, and changed-file list.

Built-in noise handling already allowlists `tailscaled`, `thunar`, `git` and `cargo`, and
download-like summaries ignore high-churn non-browser applications plus log,
cache, database and build-output paths. `known_hosts` is public host-key data,
not a credential store. `ssh` is not globally allowlisted; only `ssh` launched
by `git` for GitHub/GitLab is suppressed contextually. With
`known_hosts_allow = true` (default), an SSH destination present in the user's
or system known_hosts is also trusted for that process, including plain,
wildcard, port-qualified, and hashed entries. Do not treat these defaults as an
excuse to skip incident review.

Network destinations can be allowlisted per application and direction
(`outbound`, `inbound`, or `both`) using hostnames, suffixes, exact IPs, or
CIDRs. Incoming accepts are classified as same-machine, local-network, or
remote. Only remote sources produce incidents by default; local/same-machine
traffic stays visible in flows. Set `rules.incoming_local_connections = true`
to emit medium local incidents. See `rules.network_allowlist` and
`rules.incoming_connections`.

Bulk mutation severity is scope-aware: one project/directory is low, multiple
ordinary directories are medium, and home-root, filesystem-wide or system-path
mutations are high. Incident details include `scope`.

Package trust for an executable is available in incident
`details.package_trust`: pacman validation, source class, expected/actual
SHA-256 and a status such as `arch_signed_unmodified`,
`arch_signed_modified`, `unsigned_or_foreign_*`, `unowned` or `unverified`.
AUR/foreign is a trust signal, not a malware verdict.

`[[focus]]` configuration rules match applications and project paths, and
automatically attach to investigation bundles. Empty `log_paths` auto-detects
Codex/OpenCode/Hermes/Omarchy/OMP-style harness logs. `electric-eye focus`
summarises matching activity, flows, incidents and log paths.
`electric-eye investigate <incident-id>` renders a complete prompt; the MCP
`investigate` tool returns the same bundle for OpenCode/Hermes/OMP or another
harness to evaluate. Electric-eye does not call a model itself.

Flows include a `network_context` (`host`, `vopono`, `docker`, `podman`, `lxc`,
`kubernetes`, or `namespace`) with unit, cgroup, VPN flag and published ports
where available. For vopono only the `VOPONO_*` environment keys are read, not
the raw environment. Vopono lockfiles also provide provider, protocol, server,
application PIDs, open ports, host-forwarded ports, provider-forwarded port
renewal details and monitoring health without invoking the vopono binary.
Docker/Podman metadata supplies host-to-container published port mappings;
LXC uses configured static addresses plus host DNAT rules as a best-effort
fallback. Container metadata is under `network_context.container`.

Flows also include a conservative `role` (`listener`,
`inbound`, `outbound`, `udp_peer`, `dns`, `lpd`, `tracker`, `failed`,
`socket`) and `exposure` (`loopback`, `local_network`, `all_interfaces`,
`published`, `n/a`). These roles are heuristics; DHT, tracker and BitTorrent
payloads are not inspected. Use `electric-eye netns` for a context overview,
`electric-eye flows --netns vopono --role listener` to filter, and
`electric-eye explain network <app>` for a combined verdict. The Applications
view has a CONTEXT column and `c`/`v` context/role filters. Interpretation must
distinguish an idle exposed listener from an active data plane, and must not
treat historical flows without semantic fields as current activity.

## Interpretation rules

- `syscall_result < 0` is a failed syscall; the event may be an `.attempt`
  record. Failed attempts do not contribute written bytes or successful
  correlations.
- `path_resolution` values other than `kernel` mean the path is lexical or
  unresolved. Treat those paths as uncertain; do not use them as proof of a
  sensitive-file access. Failed opens retry at syscall exit and may show a
  relative lexical path. Synthetic paths starting with `unresolved:` include
  `dirfd`/`cwd` for failed opens and `fd`/`inode`/`dev` for pathless
  descriptor operations; use those identifiers for correlation, not as a
  claimed filename.
- Opening or listing a sensitive directory (`~/.aws`, `~/.ssh`, `~/.gnupg`,
  etc.) is metadata access, not reading files inside it. Only file-level
  access produces sensitive-path incidents; do not describe a directory
  enumeration as credential theft.
- `exe`, `cwd`, `argv`, `cgroup`, and unit metadata can be absent or truncated.
  `argv_captured: false` means arguments were disabled or unavailable; known
  secret flags are redacted.
- Startup inventory rows are approximate and explicitly labeled. Exact kernel
  observations supersede them.
- `flows` byte totals are application I/O, not wire bytes. They exclude packet
  headers and retransmissions. Shared sockets list contributors separately.
- A flow ending in `observation_ended` or a partial segment means the daemon did
  not observe the close or the beginning of the flow. Do not invent a close
  time.
- `summaries` distinguish observed sequences, correlations, and heuristics.
  Confidence is part of the result; preserve it in your report.
- Raw events are retained for a short period (default 5 minutes); activity,
  process history, flows, summaries, and incidents have separate retention.
  High incidents default to 365 days, medium to 90, low to 30; heuristic
  summaries default to 7 days while correlated/observed summaries use the
  general summary window. Incidents embed journal, actor and file evidence, so
  high-severity context can outlive raw events. Old raw detail may still be
  unavailable even when history exists.
- Baseline suppression is conservative. A missing incident does not prove a
  behavior is safe; it may be known, allowlisted, below a threshold, or outside
  the retention window.

## Useful review questions

- Which application started or changed during the review window?
- Did any process read credentials and then make a network connection?
- Which files were written or renamed by a build, editor, or downloader?
- Did a process contact a new destination, and was the destination resolved?
- Are there repeated failures, suspicious execution paths, persistence writes,
  or bulk mutations?
- Does a summary's evidence actually support its claim, or is it only timing?

## Installation

In this repository, the skill is auto-discovered at
`.opencode/skills/electric-eye/SKILL.md`. Install it for every project with:

```bash
just install-skill
```

That copies it to `~/.config/opencode/skills/electric-eye/` (respecting
`XDG_CONFIG_HOME`). The Arch package installs the source under
`/usr/share/electric-eye/skills/electric-eye/`; copy it into your agent's skill
directory if your client does not read that path.

See `references/queries.md` for a command and MCP argument cheat sheet.
