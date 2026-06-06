# kovra-mcp

The agent-facing MCP server for [kovra](../) — exposes the scoped secrets surface
(spec §9.4) to Claude Code over stdio. It is a thin [FastMCP](https://github.com/modelcontextprotocol/python-sdk)
wrapper over the `kovra_ffi` PyO3 bindings; **all policy lives in the Rust core**,
not here.

## Tools

`list` · `status` · `fingerprint` · `set` · `generate` · `delete` ·
`edit_metadata` · `reveal` · `inject_run`

Reveal returns a value **only** for a secret explicitly marked `revealable` that
is non-`prod` and non-`high` (I11); `prod`/`high`/`inject-only` are never returned
to the model (I14). Out-of-scope coordinates are unaddressable (I13). There is no
unattended-mode tool — real `high`/`prod` delivery routes through the CLI +
`kovra approve` broker, which `inject_run` drives but the model cannot bypass.

## Build & run

The server needs the `kovra_ffi` native module (built from `../crates/ffi-python`
by maturin). With [uv](https://docs.astral.sh/uv/):

```bash
cd mcp
uv sync                 # builds kovra-ffi via maturin + installs mcp
uv run kovra-mcp        # serve over stdio
```

## Configuration

The vault and keyring come from the bindings' own env (`KOVRA_VAULT_DIR`,
`KOVRA_PASSPHRASE`). The session scope is set at launch:

| Variable | Default | Meaning |
|---|---|---|
| `KOVRA_MCP_OPERATIONS` | `metadata,reveal,inject` | Operation axes granted |
| `KOVRA_MCP_ENVIRONMENTS` | `*` | Addressable environments (`*` = any) |
| `KOVRA_MCP_PROJECTS` | `*` | Addressable projects (`*` = any) |

The scope is a *containment*, not the security boundary — the core denies a
`prod`/`high` reveal to an agent even when its environment is in scope.

## Register with Claude Code

```json
{
  "mcpServers": {
    "kovra": {
      "command": "uv",
      "args": ["run", "--directory", "/abs/path/to/kovra/mcp", "kovra-mcp"],
      "env": { "KOVRA_MCP_ENVIRONMENTS": "dev,test" }
    }
  }
}
```
