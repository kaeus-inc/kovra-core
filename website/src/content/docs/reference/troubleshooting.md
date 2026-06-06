---
title: Troubleshooting
description: Common issues and how to resolve them — PATH, the allowlist gate, biometrics fallback, and the keychain prompt.
---

## `high`/`prod` injection refused — "not on the executor allowlist"

A `high` or `prod` value can only be injected into a **reviewed, allowlisted**
executable. Add it for the run with `--allow`:

```bash
kovra run --env prod --allow./deploy --./deploy
```

This is separate from the <span class="bioprove">bioProve</span> prompt — it governs *where* the value may go,
not *whether you were asked*. See [the decision process](/security/decision/).

## the <span class="bioprove">bioProve</span> prompt never appears

On a host without biometrics (no hardware, not enrolled, or a headless/CI
session), kovra falls back to the **file broker**. The command waits and prints
instructions; approve it from another terminal:

```bash
kovra approve --list
kovra approve <id>
```

You can force the channel with `KOVRA_CONFIRMER=biometric|file`.

## macOS re-prompts for your login password on every run

If a freshly rebuilt `kovra` keeps asking for your **login keychain** password to
read the master key, grant the binary standing access: in **Keychain Access**,
find the `kovra` / `master-key` item, and under **Access Control** allow the
`kovra` application (or "Allow all applications"). This happens because an
ad-hoc-signed binary gets a new code identity each rebuild; a release-signed build
is stable.

Alternatively, run in **passphrase mode** (no keychain at all) by setting
`KOVRA_PASSPHRASE` — kovra then derives the key with Argon2 from your passphrase
and a stored salt.

## `command not found: kovra` (or `kovra-mcp`)

The binary isn't on your `PATH`. After a Homebrew install it should be automatic;
from source, copy it: `cp target/release/kovra /usr/local/bin/`. For `kovra-mcp`,
confirm with `which kovra-mcp` — and remember it's an MCP **stdio server** your
agent launches, not something you run by hand.

## The agent doesn't see kovra's tools

After `kovra setup`, **reload your agent** so it re-reads `.mcp.json`. Confirm the
server is registered there and that `kovra-mcp` is on your `PATH`. The agent only
ever sees scoped metadata — if a coordinate is out of its
[scope](/concepts/agent-scope/), it's *unaddressable*, by design.

## A secret won't reveal

`inject-only` secrets are **never** revealed — they can only be injected. `high`
and `prod` secrets never reveal to an agent, and reveal at the CLI only after a <span class="bioprove">bioProve</span>. This is the policy working as intended, not a bug; see
[Sensitivity tiers](/concepts/sensitivity/).
