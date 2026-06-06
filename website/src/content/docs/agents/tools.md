---
title: MCP tool reference
description: The complete set of tools kovra exposes over MCP, what each returns, and the policy that governs it.
---

These are the tools kovra exposes to an MCP client such as Claude Code. Each one
runs through kovra's single policy decision; the table notes what comes back and the
rule that governs it. **No tool ever returns a sensitive plaintext** — `reveal` is the
only value-returning tool, and only within a narrow exception.

Coordinates follow the [coordinate grammar](/concepts/coordinates/); anything outside
the session [scope](/concepts/agent-scope/) is **unaddressable** and never appears.

## Read metadata

| Tool | Returns | Governing rule |
| --- | --- | --- |
| `list` | Metadata for every addressable secret — coordinate, sensitivity, mode, fingerprint, flags | Values never returned; out-of-scope secrets are absent |
| `status` | Metadata for one coordinate | Errors if the coordinate isn't addressable in this session |
| `fingerprint` | A short, **truncated** fingerprint of a value | Truncated by design — enough to compare, never to reconstruct |

## Use a value

| Tool | Returns | Governing rule |
| --- | --- | --- |
| `inject_run` | `{status, stdout, stderr}` with vault values **masked** | Values go into the child process's environment, never the caller's context. `high`/`prod` requires an allowlisted executable **and** an attended `kovra approve` |
| `reveal` | The plaintext value, into context | Permitted **only** for a secret marked revealable that is non-`prod` and non-`high`. `prod` / `high` / `inject-only` are never returned |

## Create and manage

| Tool | Returns | Governing rule |
| --- | --- | --- |
| `set` | The new metadata (not the value) | A `prod` secret is born `high` |
| `generate` | Metadata only | Value is generated server-side and stored; never returned |
| `edit_metadata` | Updated metadata | Edits sensitivity / description / `revealable` / reference; **lowering** sensitivity is separately audited |
| `delete` | Confirmation | Errors if the coordinate isn't addressable in this session |

## The pattern behind the table

Three properties hold across every row, and they're worth naming because they're the
reason an agent can be trusted with these tools at all:

1. **Reading metadata is always safe** — listing, diagnosing, and fingerprinting
 never touch a value.
2. **Using a value never reveals it** — `inject_run` delivers a secret *through* a
 process and masks it on the way out.
3. **Creating a value never exposes it** — `set` and `generate` return only metadata,
 so a freshly generated credential never passes through the model's context.

The single exception — `reveal` — is deliberately the most constrained tool of all.
See [kovra over MCP](/agents/mcp/) for the narrative version and
[the decision process](/security/decision/) for exactly how each call is judged.
