---
title: How it works
description: The main flows in kovra, end to end and at a high level — storing, using, delegating to an agent, revealing, and sharing a secret.
---

kovra has only a handful of flows. This page walks through each one **at a high
level** — what happens, conceptually, without the internals. For the detailed
account of how a request is *decided*, see
[The decision process](/security/decision/) in the security model.

## Storing a secret

You hand kovra a value once. It seals the value in the [vault](/concepts/vault/)
and remembers only its [metadata](/concepts/coordinates/) — the coordinate, the
[sensitivity](/concepts/sensitivity/), an optional description. From that moment
the value is never printed back to you as a side effect of normal work; it lives
encrypted and is only ever *delivered*, never *displayed*.

## Using a secret in a process

This is the everyday path. You describe the wiring once in an
[`.env.refs`](/concepts/env-refs/) file — variable names mapped to coordinates,
addresses but no values — and then ask kovra to run your command. Conceptually:

1. You run your tool *through* kovra.
2. kovra reads the wiring and looks up each address.
3. It checks the policy for every value (is this allowed, on this channel, at this
 sensitivity?).
4. It hands the resolved values **straight to your command's process** and starts
 it.

The command works with the real values; nothing was written to a file, shown on
screen, or left in your shell history. The secret was *used*, not *seen*.

## Letting an agent use a secret

When an AI agent is involved, the same idea holds with one boundary added. The
agent connects under a [scope](/concepts/agent-scope/) — a statement of what it's
allowed to address and do. Conceptually:

1. The agent sees **metadata** — that a secret exists, its name and sensitivity —
 and reasons about your project.
2. When it needs a secret to actually run something, kovra **injects** the value
 into that command, the same way as above.
3. The sensitive **plaintext never enters the agent's context** — it can use the
 secret without ever reading it.

## Revealing a secret to yourself

Sometimes *you* genuinely need to see a value. You ask for it explicitly, and
kovra treats that as the guarded path:

1. You request one specific coordinate.
2. kovra checks its sensitivity. For an ordinary secret it shows it; for a
 sensitive one it first asks you to <span class="bioprove">bioProve</span>.
3. The most protected secrets are never shown at all — they can only be injected.

Revealing is always a deliberate, attended act — never something that happens on
its own, and never something an agent can trigger for you.

## Sharing a secret with someone else

To hand a set of secrets to another person or machine, kovra **seals** them to the
recipient's public key as a portable package (or, for a brand-new machine, a USB
kit that bootstraps everything). Conceptually:

1. You choose a non-production environment to share.
2. kovra seals those values so that **only the intended recipient** can open them,
 and prints a separate one-time access token to deliver through another channel.
3. The recipient opens the package **with their own identity**; production secrets
 are never shareable this way.

Authorization is anchored to *who the recipient is*, not to whoever happens to
hold the file.

---

Each of these flows runs the same underlying check before a value moves. That
check — and exactly how it decides — is the subject of
[the security model](/security/decision/).
