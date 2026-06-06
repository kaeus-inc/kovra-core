---
title: FAQ
description: Short, direct answers to the questions people ask before adopting kovra.
---

## Does kovra send anything to the cloud?

No. kovra is a **local** tool — the vault lives on your machine and nothing is
transmitted as a side effect of normal use. The only network calls happen when
*you* use a [cloud reference](/guides/references/) (kovra resolves it under your
own provider identity) or deliberately [share a package](/guides/sharing/). There
is no telemetry and no phone-home.

## Does it work offline?

Yes. Everything except [cloud references](/guides/references/) (which, by
definition, call your cloud provider) works with no network at all.

## What actually leaves my machine?

By default, nothing. A secret only moves when you explicitly **share** it (a
sealed package, encrypted to the recipient) or when a **cloud reference** resolves
against your provider. Even then, the plaintext is never written to disk, argv, or
an agent's context.

## Is `.env.refs` safe to commit?

Yes — that's the point. It holds **addresses, not values**. A leaked `.env.refs`
exposes where secrets live, never the secrets. Add a
[git hook](/operations/git-hooks/) as a backstop against committing real values by
accident.

## Can an AI agent read my secrets?

It can *use* them, not *see* the sensitive ones. An agent over MCP runs under a
[scope](/concepts/agent-scope/) and never receives the plaintext of a `high`,
`prod`, or `inject-only` secret. The only thing it can read back is an ordinary
secret you explicitly marked revealable.

## Where are my secrets stored?

In an encrypted vault under `~/.vaults` (or `KOVRA_VAULT_DIR`). Every entry is
sealed; see [Configuration](/reference/configuration/) and
[Cryptography](/security/cryptography/).

## Is it free? What's the license?

It's **source-available** under the Business Source License 1.1, and each version
becomes Apache-2.0 four years after release. See [License](/project/license/).

## Is kovra a server or a daemon?

No. It's a local CLI. The [Web UI](/guides/web-ui/) is **on-demand and loopback
only** — it isn't exposed to the network and shuts down when idle.

## Do I need the MCP server?

Only to use kovra from an AI agent. The CLI and vault work on their own; `kovra-mcp`
is the optional bridge for Claude Code and other MCP clients.

## What if I lose my machine or my Keychain?

Restore from a key backup — see [Backup & recovery](/operations/backup-recovery/).
Make that backup *before* you need it.

## Which platforms are supported?

macOS on Apple Silicon is the reference platform today. Windows (Windows Hello +
Credential Manager) and Linux are on the roadmap.
