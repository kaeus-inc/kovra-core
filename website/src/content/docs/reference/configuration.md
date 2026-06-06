---
title: Configuration
description: Every environment variable and config file kovra reads, in one place.
---

This is the complete reference for how kovra is configured: the environment
variables it reads, and the files it uses.

## Environment variables

| Variable | Default | What it does |
| --- | --- | --- |
| `KOVRA_VAULT_DIR` | `~/.vaults` | Override the vault registry root. |
| `KOVRA_PASSPHRASE` | *(unset)* | Switch to [passphrase mode](/operations/headless-ci/): derive the master key with Argon2id instead of using the OS keyring. |
| `KOVRA_CONFIRMER` | `biometric` (falls back to `file`) | Confirmation channel: `biometric` (Touch ID / Windows Hello) or `file` (the `kovra approve` broker). |
| `KOVRA_UI_NO_CONFIRM` | *(unset)* | Skip the Web UI launch confirmation (same as `kovra ui --no-confirm`). |
| `KOVRA_RECIPIENT_KEY` | *(unset)* | Private ed25519 key used by `kovra unpack` (instead of `--identity-file`); kept out of argv. |
| `KOVRA_MCP_ENVIRONMENTS` | `*` | MCP session scope — addressable environments (comma list, or `*` for any). |
| `KOVRA_MCP_PROJECTS` | `*` | MCP session scope — addressable projects (comma list, or `*` for any). |

## The vault directory

The registry root (default `~/.vaults`, or `KOVRA_VAULT_DIR`) holds:

```text
~/.vaults/
  global/            # the global vault — sealed per-secret records + a sealed index
  projects/
    <name>/          # one directory per project vault, same layout
  kdf.salt           # passphrase-mode only: the non-secret Argon2 salt
```

Every record is sealed at rest; coordinates aren't exposed as plaintext
filenames. See **[Cryptography](/security/cryptography/)** for the at-rest format.

## `.mcp.json`

`kovra setup` registers the MCP server here so your agent can launch it. The
`env` block carries the **MCP session scope**:

```json
{
  "mcpServers": {
    "kovra": {
      "command": "kovra-mcp",
      "env": {
        "KOVRA_MCP_ENVIRONMENTS": "dev,test",
        "KOVRA_MCP_PROJECTS": "my-app"
      }
    }
  }
}
```

This is what bounds what an agent over MCP can address (`*` = any). It's distinct
from `agent.toml`, which scopes the **ssh-agent**.

## `agent.toml` — the ssh-agent scope

The [governed ssh-agent](/guides/ssh-agent/) reads its scope from
`<vault-root>/agent.toml`. The format is intentionally tiny — two array keys, with
`#` comments:

```toml
# <vault-root>/agent.toml — kovra ssh-agent scope
environments = ["dev", "test"]   # omit (or []) → any environment
projects     = ["api"]           # omit (or []) → global + any project
```

Two things are **not** configurable here, by design: the operation set is fixed to
*metadata + inject* (an ssh-agent **never** reveals a private key), and when the
file is absent the agent serves any environment/project — still never revealing,
and still requiring a [bioProve](/operations/attended-confirmation/) on every
`high`/`prod` signature.

## The `.env.refs` grammar

`.env.refs` maps local environment-variable names to **sources**. It holds
addresses, never values, so it's safe to commit. One mapping per line:

| Form | Meaning |
| --- | --- |
| `project = <name>` | Bind the file to a project vault (resolution targets it). |
| `NAME=secret:<env>/<comp>/<key>` | A **vault coordinate**. May use `${ENV}`; an optional `\| fallback` applies if it doesn't resolve. |
| `NAME=secret://global/<env>/<comp>/<key>` | Force resolution against the **global** vault, bypassing the project. |
| `NAME=${env:VAR}` | A **passthrough** from the execution environment. Supports `${env:VAR \| fallback}`. |
| `NAME=literal` | A **literal** value (not a secret), e.g. `PORT=8080`. |

Rules that keep it safe:

- **No values, ever** — addresses only, so a leaked `.env.refs` exposes nothing.
- **`${ENV}`** is substituted by `kovra run --env <e>` inside a coordinate's
  environment segment; **`${env:VAR}`** reads from the surrounding environment.
- **Cross-variable interpolation is rejected** — you can't compose one secret
  inside another variable's string (that composed string would get logged).
- **Resolution is a single ordered pass** over the file.

See **[The .env.refs contract](/concepts/env-refs/)** for the narrative version.
