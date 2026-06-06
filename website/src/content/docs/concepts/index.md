---
title: Concepts
description: The handful of ideas that make kovra work — the vault, coordinates, sensitivity tiers, agent scope, and the .env.refs contract.
---

kovra is built from a small set of ideas that fit together. Learn these five and
the rest of the tool follows.

- **[The vault](/concepts/vault/)** — where secrets live: an encrypted local
 store, per-project or global, with its master key in the OS keychain.
- **[Coordinates](/concepts/coordinates/)** — how you address a secret:
 `secret:<env>/<component>/<key>`, never by its value.
- **[Sensitivity tiers](/concepts/sensitivity/)** — how protective kovra is with
 each secret: `low`, `medium`, `high`, and `inject-only` — plus what the `prod`
 environment adds on top.
- **[Agent scope](/concepts/agent-scope/)** — the capability boundary that lets
 an AI agent *use* secrets without *seeing* the sensitive ones.
- **[The `.env.refs` contract](/concepts/env-refs/)** — the committable file that
 maps your env-var names to coordinates, holding addresses but never values.

## The one-sentence model

You **address** a secret by its coordinate, the vault **custodies** it, its
**sensitivity** decides how it can be delivered, your **scope** decides who can
ask, and `.env.refs` **wires** it into the processes that need it — so a value is
*used* without ever being *seen*.
