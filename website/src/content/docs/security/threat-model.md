---
title: Threat model
description: What kovra protects, who it protects against, and — honestly — what is out of scope.
---

kovra is built around one job: let your tools and AI agents **use** secrets
without **seeing** the sensitive ones. This page states that plainly — the assets
it guards, the adversaries it's designed against, and the limits it does **not**
cross. A security tool that overstates its guarantees is worse than one that's
honest about them.

## Assets

- **Secret values** — literals, the private halves of [keypairs](/guides/keypairs/),
  and [TOTP](/guides/totp/) seeds.
- **The master key** — the root of trust that encrypts the whole vault.
- **The integrity of the audit trail** — a faithful record of what happened.

## What kovra is designed to stop

- **A prompt-injected or hijacked AI agent exfiltrating secrets.** An agent runs
  under a [scope](/concepts/agent-scope/) and never receives the plaintext of a
  `high`, `prod`, or `inject-only` secret. Out-of-scope coordinates are
  *unaddressable* — they don't exist for that session, so a manipulated agent
  can't reach what it was never granted.
- **A program reading back a value it was given.** Sending a `high`/`prod` value
  into a program the agent itself wrote would defeat the point, so those
  injections are only allowed into a **reviewed, allowlisted** executable.
- **Plaintext leaking into the places it usually leaks.** Values never land in a
  log, on disk, in argv, in shell history, or in a model's context window.
- **A secret committed by accident.** A [pre-commit hook](/operations/git-hooks/)
  scans staged changes and blocks the commit.
- **A shared bundle falling into the wrong hands.** A
  [sealed package](/guides/sharing/) is encrypted to the recipient's key, and its
  sensitive entries additionally need an out-of-band token — possession of the
  file is not access.
- **A lost or stolen laptop, or casual disk inspection.** Every record is
  encrypted at rest under the master key (custodied in the OS keyring, or derived
  with Argon2id), and coordinates aren't exposed as plaintext filenames.

## In-scope guarantees

- Sensitive **reveals** and **injections** require a deliberate <span class="bioprove">bioProve</span> — they never
  happen on their own, and never at an agent's request for `high`/`prod`.
- The confirmation prompt is built by kovra from the **real** request, so it can't
  be faked by a caller.
- The audit trail records every outcome **without** storing a value or a full
  fingerprint.

## Out of scope — the honest limits

- **The last mile.** Once a value is delivered to the process that needs it, it
  lives in that process's memory under that program's rules. kovra secures
  *custody and delivery*, not what a program does with a value after it has it.
- **A compromised host.** kovra trusts the operating system's keyring and
  biometric subsystem and the machine's own integrity. A root-level compromise, a
  kernel keylogger, or malware reading another process's memory is outside what a
  user-space tool can defend.
- **A human (or program) you authorize.** kovra makes a sensitive action
  **deliberate and attributable** — it does not make it impossible. If you <span class="bioprove">bioProve</span> a
  bad action, or allowlist a malicious program, kovra will carry it out and record
  it.
- **Sender authenticity of packages.** A [sealed package](/guides/sharing/) proves
  *who can read it*, not *who wrote it* — it's confidentiality, not a signature.
- **Cloud provider trust.** A [cloud reference](/guides/references/) resolves under
  your provider identity; the provider still sees what it always would.

## Trust assumptions

kovra assumes: your machine and OS are not already compromised; the OS keyring and
biometric prompt behave as the platform intends; and the vetted cryptographic
libraries it builds on are sound. It rolls **no cryptography of its own** — see
[Cryptography](/security/cryptography/).
