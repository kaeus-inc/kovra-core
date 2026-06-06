# Security Policy

`kovra` is a secrets manager — we take reports seriously and we'd rather hear
from you. Thank you for helping keep kovra users safe.

## Reporting a vulnerability

**Please report privately. Do _not_ open a public issue, PR, or discussion for a
security problem.**

Two private channels (use either):

1. **GitHub Security Advisories** — *Security → Report a vulnerability* on this
   repository (preferred; lets us coordinate a fix and a CVE privately).
2. **Email** — `security@kaeusanalytics.com` (or `info@kaeusanalytics.com`).
   Encrypt if you can; otherwise just send what you have.

Please include: affected version, platform, a description, and ideally a minimal
reproduction. **Never include real secret values** in a report — redact them.

### What to expect

kovra is **early-stage** and maintained by a small team at **Kaeus Inc** on a
**best-effort** basis. There is **no guaranteed response SLA** at this stage.
What you can expect:

- We **acknowledge and triage as soon as we reasonably can**, worst things first.
- We'll confirm the issue and work out a disclosure timeline **with you** — we
  ask for reasonable time (typically up to ~90 days) to ship a fix before public
  disclosure — then fix it and credit you (if you wish) when the fix ships. We
  may request a CVE.
- Please bear with a small team; good-faith patience is appreciated and
  reciprocated.

## Supported versions

kovra is pre-1.0; security fixes land on the **latest `0.x`** release. Pin to a
recent version and update when fixes ship.

## Scope & threat model (what kovra does and does not defend)

kovra's job is to stop a secret's **plaintext** from leaking — to a log, a file,
argv, your shell history, a browser, or an AI agent's context — and to gate
sensitive operations behind an attended human approval.

**In scope** (we want these reports):

- Plaintext of a `high` / `prod` / inject-only secret reaching a log, disk, argv,
  the audit trail, an agent's context, or the Web UI.
- Bypassing the sensitivity / confirmation / executor-allowlist policy.
- An agent addressing a secret outside its scope.
- Parser / URI / `.env.refs` handling flaws, supply-chain issues.

**Out of scope** (by design — these are honest limits, not bugs):

- An attacker who already has your machine **unlocked**, or root/admin on it, or
  your logged-in OS keychain — kovra protects against leakage, not a fully
  compromised host.
- What a program does with a secret **after** kovra legitimately injects it, or
  what an SSH session does after an authorized, broker-gated auth event.
- "It refuses without Touch ID / an allowlisted executor" — that's the design.

When in doubt, report it — we'd rather triage an out-of-scope report than miss an
in-scope one.

## Safe harbor

We will not pursue or support legal action against good-faith security research
that respects this policy, avoids privacy violations and service disruption, and
gives us reasonable time to remediate before public disclosure.
