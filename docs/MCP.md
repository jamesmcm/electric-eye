# MCP and agent integration

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
[`.opencode/skills/electric-eye/SKILL.md`](../.opencode/skills/electric-eye/SKILL.md)
and is auto-discovered when working in this repository. Install it into your
global OpenCode configuration with:

```bash
just install-skill
```

That copies `SKILL.md` and `references/queries.md` to
`~/.config/opencode/skills/electric-eye/` (respecting `XDG_CONFIG_HOME`). The
Arch package also installs the source under
`/usr/share/electric-eye/skills/electric-eye/`.

## Investigation bundles

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
