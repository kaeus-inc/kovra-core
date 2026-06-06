---
title: Glossary
description: The kovra vocabulary in one place.
---

**bioProve** — kovra's word for an attended biometric check (Touch ID on macOS,
Windows Hello on Windows) that authorizes a sensitive action. Used as a verb:
"kovra asks you to bioProve it."

**Coordinate** — a secret's address, `secret:<env>/<component>/<key>` (e.g.
`secret:dev/db/password`). See [Coordinates](/concepts/coordinates/).

**Environment / component / key** — the three segments of a coordinate: the
deployment stage (`dev`, `prod`, …), the part of the system, and the specific
secret.

**Vault** — the local, encrypted store for your secrets. Global plus one per
project. See [The vault](/concepts/vault/).

**Master key** — the 256-bit key that encrypts every vault entry; custodied in the
OS keyring (or derived in passphrase mode). The root of trust.

**Sensitivity** — how protective kovra is with a secret: `low`, `medium`, `high`,
or `inject-only`. See [Sensitivity tiers](/concepts/sensitivity/).

**Scope** — the capability boundary a session (especially an agent) operates
under: which operations, projects, and environments it may address. See
[Agent scope](/concepts/agent-scope/).

**Operation** — what a caller may do with a value: read **metadata**, **inject**
(deliver through a process), or **reveal** (return plaintext to the caller).

**Reveal** — bring a plaintext value back into the caller's hands. The guarded
path; never allowed for `inject-only`, and never to an agent for `high`/`prod`.

**Injection** — deliver a value *through* an operation into a child process's
environment; the value never returns to the caller. See
[The .env.refs contract](/concepts/env-refs/).

**Literal** — a vault entry that holds an actual value (as opposed to a reference
or a typed credential).

**Reference** — a vault entry that points to a value in a cloud secret manager
(`azure-kv://`, `aws-sm://`), resolved at runtime under your own identity. See
[Cloud references](/guides/references/).

**Fingerprint** — a short, truncated BLAKE3 hash of a value, shown in `list` to
confirm "is this the same value?" without revealing it.

**Package** — an encrypted bundle of non-production secrets, sealed to a
recipient's key for sharing. See [Sealed packages](/guides/sharing/).

**Access token** — a separate, second-channel credential that authorizes
unattended consumption of a package's sensitive entries.

**Allowlist** — the set of reviewed executables a `high`/`prod` value may be
injected into. Independent of the confirmation prompt.

**Broker** — kovra's confirmation channel: a biometric prompt, or the
cross-process `kovra approve` file broker when biometrics is unavailable.

**`.env.refs`** — the committable file mapping env-var names to coordinates —
addresses, never values.

**`agent.toml`** — the file at the vault root that scopes the
[governed ssh-agent](/guides/ssh-agent/).

**MCP** — the Model Context Protocol; how kovra exposes governed tools to AI
agents. See [kovra over MCP](/agents/mcp/).
