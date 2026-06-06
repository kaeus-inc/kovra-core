# kovra

A **local secrets manager for development**, exposed over MCP for AI coding
agents. kovra custodies keys, passwords, and tokens and delivers them to
processes **without leaking plaintext** — never into a log, a commit, a process
argument, or an agent's context window.

```bash
cargo install kovra
```

This installs the `kovra` binary. From there:

- `kovra set` / `kovra list` / `kovra show` — manage and inspect the vault;
- `kovra run -- <cmd>` — run a process with secrets injected into its
  environment, never its argv;
- `kovra ui` — an on-demand, loopback-only Web UI that visualizes the vault
  under the sensitivity policy;
- typed credentials (TOTP, asymmetric keypairs, a governed ssh-agent), cloud
  references (`azure-kv://`, `aws-sm://`), encrypted packages, and an offline
  USB exchange kit.

Higher-sensitivity actions are gated by an **attended confirmation** — a Touch ID
prompt (or a cross-process approval) that happens at the sensor, outside the
calling process. A secret marked `high` or `inject-only` is never returned into
model context.

Full documentation: <https://kovra.sh/docs>.
Source: <https://github.com/kaeus-inc/kovra-core>. Licensed under BUSL-1.1.
