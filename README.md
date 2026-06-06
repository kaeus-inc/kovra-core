<h1 align="center">kovra</h1>
<p align="center"><strong>Highly secure convenience.</strong></p>
<p align="center">Secrets your AI agents can <em>use</em>, but never <em>see</em>.</p>

---

You point an AI coding agent at your repo to move faster — and now it can read
**every secret in it**: the `.env` files, the keys pasted into terminals, the
tokens in your shell history. kovra closes that gap. It custodies your keys,
passwords, and tokens in an encrypted local vault and lets your tools — **and your
AI agents** — *use* them without ever *seeing* the plaintext: not in a log, not on
disk, not in argv, not in your shell history, and **never in an AI agent's
context**.

Every sensitive action waits for you to **bioProve** it — kovra's word for a
one-gesture biometric check (Touch ID on macOS, Windows Hello on Windows):
**kovra does the work, you authorize it.**

## The problem

Secrets sprawl. They sit in plaintext `.env` files, get pasted into terminals,
copied into a dozen `export` lines, and end up in shell history and logs. Then
you point an AI coding agent at the repo — and now **the agent can read every one
of them**. The usual "fix" is to hand the developer a checklist of careful
commands and hope they follow it. People don't; convenience wins.

kovra flips that: the safe path *is* the convenient path.

## How it works

You store a secret once. After that, nothing prints it back to you:

- **Agents get metadata, not secrets.** kovra exposes an **MCP server**: Claude
  Code (or any MCP client), running under a scope, sees that a secret *exists* —
  its coordinate and sensitivity — and can run commands through the wrapper, but
  the plaintext of your `high` / `prod` / inject-only secrets never enters its
  context. This is kovra's reason for being.
- **Tools get it through injection.** `kovra run` resolves an `.env.refs` file
  (which maps env-var names to *coordinates*, never values) and injects the
  resolved values straight into a child process. Nothing touches disk or argv.
- **You authorize, kovra acts.** Revealing or injecting a sensitive secret, or
  lowering its protection, asks you to **bioProve** it (with a device-password
  fallback). kovra never hands you a list of commands to run by hand — it performs
  the action behind the biometric gate.

Under the hood: a per-vault master key (custodied in the OS keychain) encrypts
every entry at rest (ChaCha20-Poly1305); secret-bearing memory is zeroized;
and a policy layer enforces **sensitivity tiers** (`low → medium → high → prod`,
plus `inject-only`) and an **executor allowlist** for privileged injection.

## What you get

- 🤖 **MCP server for AI agents** — kovra's reason for being: scoped metadata +
  run orchestration, so an agent can *use* your secrets while sensitive plaintext
  is never revealed into the model's context.
- 🔐 **Encrypted local vault** — per-project or global, master key in the OS
  keychain, everything zeroized in memory.
- 🚀 **Process injection** — `kovra run` feeds secrets to a child via `.env.refs`,
  never to disk/argv/history.
- ☁️ **Cloud references, not copies** — `azure-kv://` and `aws-sm://` secrets
  resolve at runtime with *your own* ambient identity; the reference is a pointer,
  the value is never stored locally.
- 🧩 **Typed credentials** — TOTP (codes derived on demand, seed never revealed),
  asymmetric keypairs (sign / verify / encrypt / decrypt — the private half is
  never exported), and a **governed ssh-agent** that signs in-memory with
  per-signature policy.
- 🖥️ **On-demand Web UI** — a loopback admin UI, launched behind a **bioProve**,
  with per-action confirmation; sensitive values are never rendered into the page.
- 🤝 **Offline sharing** — seal a non-`prod` secret set to a recipient's public
  key as a portable package, plus a **USB offline-exchange kit** that bootstraps a
  brand-new machine end-to-end, each destructive step **bioProve**-gated.
- 🧰 **Developer accelerators** — `kovra scaffold` (propose an `.env.refs` from
  your repo), `kovra doctor` (validate config), pre-commit secret scanning, and a
  surfaced `audit` log.

## Quick start (macOS)

```bash
# install (Homebrew tap)
brew install kaeus-inc/kovra/kovra

# initialize the vault registry + master key
kovra init

# add a secret — the value comes from a hidden prompt (or --stdin), never argv
kovra add secret:dev/db/url        # paste the value at the prompt

# map env vars to coordinates in .env.refs, then run a command with the values
# injected into the child process (nothing touches disk, argv, or shell history)
echo 'DATABASE_URL=secret:dev/db/url' > .env.refs
kovra run --env dev -- your-app
```

### With Claude Code

```bash
kovra setup    # registers the kovra MCP server in ./.mcp.json + a CLAUDE.md block
```

The agent then sees scoped *metadata* and can run commands through the wrapper,
but never the plaintext of your `high` / `prod` / inject-only secrets.

## Platform support

**macOS (Apple Silicon) is the reference platform** — native Touch ID and
Keychain integration. Windows (Windows Hello + Credential Manager) and Linux are
on the roadmap, behind the same traits, so the security model carries over
unchanged.

## Documentation

Full guides — concepts, the security model, the CLI reference, providers, the MCP
surface, sharing, and the Web UI — live at **<https://kovra.sh>**.

## Security

kovra is a security tool; we take reports seriously. **Please report
vulnerabilities privately** — see [`SECURITY.md`](./SECURITY.md). Never open a
public issue for a security problem, and never paste a real secret into one.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md). (At this early stage the project is
source-available and read-only for external code; bug reports, security reports,
and discussion are very welcome.)

---

<sub>kovra is a product of <strong>Kaeus Inc</strong>. Source-available under the
Business Source License 1.1; each version converts to Apache-2.0 four years after
its release. See <a href="./LICENSE">LICENSE</a> and <a href="./NOTICE">NOTICE</a>.</sub>
