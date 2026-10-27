# Electric Eye query cheat sheet

All commands are read-only. Add `--json` for complete structured evidence and
`--limit 1..1000` to control list size. MCP tool arguments mirror the CLI
selectors.

## Daemon health

```bash
electric-eye status
electric-eye --json status
```

Look for `capture_loss`, `store.dropped`, `attached_probes`,
`skipped_probes`, `uptime_secs`, `events_total`, and `mcp_socket`.

MCP: `status` (no arguments).

## Incidents

```bash
electric-eye incidents
electric-eye --limit 200 incidents
electric-eye --json incidents
```

MCP: `incidents` with optional `limit`.

Incident titles cover sensitive-path access, credential sweeps, bulk mutation,
suspicious execution locations, sensitive-access-then-egress, novel network
destinations, and persistence paths. Read `details` and `evidence` before
drawing conclusions.

## Activity

```bash
electric-eye activity
electric-eye --limit 500 activity
electric-eye --json activity
```

MCP: `activity` with optional `limit`.

The response includes `activity` (newest first), `overview` groups for observed
file writes, and `persisted_activities` when SQLite is enabled.

## Applications and tasks

```bash
electric-eye apps
electric-eye app firefox
electric-eye app <stable-application-id-or-task-id>
electric-eye --json app firefox
```

MCP: `apps`; `app` with required `app` and optional `limit`.

Attribution includes its reason and confidence. A terminal task stays separate
from the application that launched it, and interpreter/script tasks can get
their own IDs.

## Processes and trees

```bash
electric-eye process 1234
electric-eye process boot-id:1234:123456789
electric-eye tree 1234
electric-eye tree
```

MCP: `process` with required `process`; `tree` with optional `process`; optional
`limit`.

`process` includes metadata and exec history. `tree` follows retained
descendants. Numeric PIDs can match old and current generations; use a stable
identity when exactness matters.

## Files

```bash
electric-eye file /home/alice/project/out.bin
electric-eye why /home/alice/project/out.bin
electric-eye --json why /home/alice/project/out.bin
```

MCP: `file` or `why` with required `path` and optional `limit`.

`file` returns activity for the path. `why` returns evidence and syscall
outcomes. Negative `syscall_result` values are failed attempts; `path_resolution`
other than `kernel` means the path is uncertain.

## Network

```bash
electric-eye network
electric-eye flows
electric-eye --json flows
```

MCP: `network`; `flows`; optional `limit`.

`network` shows recent connect/accept/listen/traffic observations. `flows`
shows lifecycle state, duration, sent/received bytes, errors, and contributors.
Byte totals are application I/O, not wire bytes.

## Summaries

```bash
electric-eye summaries
electric-eye --json summaries
```

MCP: `summaries` with optional `limit`.

Summaries cover build sessions, save/rename sequences, application startup, and
download-like behavior. Each has a confidence label and evidence references.
Evidence is bounded and may be truncated; use `--json` for the complete record.

## Interactive and operational checks

```bash
electric-eye tui
electric-eye doctor
electric-eye db status
electric-eye config show
electric-eye config validate /etc/electric-eye/config.toml
```

The TUI is read-only. `doctor` checks systemd, socket/group access, BTF,
tracefs, probes, capture loss, storage headroom and configuration. `db status`
reports database/WAL size, retention and disk headroom; `db compact` is an
explicit maintenance action.

## Filtering and export

```bash
electric-eye incidents --since 1h --severity high
electric-eye incidents --since 24h --rule egress --app curl
electric-eye activity --follow
electric-eye --json --limit 100 activity
electric-eye export incidents --since 24h > incidents.jsonl
```

`--since`/`--before` accept relative values such as `15m`, `1h`, `24h`, `7d` or
an epoch timestamp. `--jsonl` emits one object per line. Activity and incident
JSON responses include `next_cursor`; pass it back with `--cursor` to continue
without duplicating same-millisecond rows.

Local incident review:

```bash
electric-eye ack <incident-id>
electric-eye unack <incident-id>
electric-eye mute curl novel_network --for 1h
electric-eye unmute curl novel_network
electric-eye incidents --unacked
```

These update a user-owned review file only; they do not modify daemon state.

## Noise candidates

```bash
electric-eye noise
electric-eye --json noise
```

MCP: `noise` with optional `limit`.

Returns high-churn path prefixes, repeated-incident applications, and noisy
heuristics (currently `download_like`) with a suggested TOML snippet. It is
read-only; review and merge the suggestions into the daemon configuration, then
restart the service.

Built-ins already allowlist `tailscaled` and `thunar`. `known_hosts` is not
treated as SSH credential access. Download-like summaries skip common log,
cache, database and build-output paths.

## MCP configuration

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

The daemon exposes MCP at `/run/electric-eye/mcp.sock` by default. Disable it
with `--no-mcp` on `electric-eyed`; override the path with `--mcp-socket` or
`ELECTRIC_EYE_MCP_SOCKET`. The CLI bridge also accepts `--mcp-socket`.

## Quick triage recipe

```bash
electric-eye status
electric-eye incidents --limit 200
electric-eye activity --limit 200
electric-eye summaries --limit 100
```

Then drill into the most interesting actor or path:

```bash
electric-eye process <pid>
electric-eye tree <pid>
electric-eye why /path/from/incident
electric-eye app <application>
electric-eye flows --limit 200
```
