# Changelog

Notable changes to kovra's public open-core releases. The format follows
[Keep a Changelog](https://keepachangelog.com/); versions track the workspace
version published to crates.io, PyPI, and the Homebrew tap.

kovra is source-available under the Business Source License 1.1; each version
converts to Apache-2.0 four years after its release.

## [0.8.0] — 2026-06-06

First public release of kovra's open core — a local secrets manager that lets
your tools and AI agents *use* your secrets without ever *seeing* them.

### Added

- **Encrypted local vault** — per-project or global; per-vault master key in the
  OS keychain; ChaCha20-Poly1305 at rest; secret-bearing memory zeroized.
- **MCP server for AI agents** (`kovra-mcp`) — scoped metadata + run
  orchestration over [MCP](https://modelcontextprotocol.io); the plaintext of
  `high` / `prod` / inject-only secrets never enters the model's context.
- **Process injection** — `kovra run` resolves an `.env.refs` (coordinates, not
  values) and injects secrets straight into a child process — never to disk,
  argv, or shell history.
- **Biometric-gated actions** — revealing, injecting, or lowering the protection
  of a sensitive secret waits for a one-gesture biometric check (Touch ID on
  macOS), with a device-password fallback.
- **Cloud references, not copies** — `azure-kv://` and `aws-sm://` secrets
  resolve at runtime with your own ambient identity; the reference is a pointer,
  the value is never stored locally.
- **Typed credentials** — TOTP (codes on demand, seed never revealed),
  asymmetric keypairs (private half never exported), and a governed ssh-agent.
- **On-demand Web UI** — a loopback admin UI launched behind a biometric gate,
  with per-action confirmation; sensitive values are never rendered.
- **Offline sharing** — sealed portable packages plus a USB offline-exchange kit
  that bootstraps a brand-new machine end to end, each destructive step gated.
- **Developer accelerators** — `kovra scaffold`, `kovra doctor`, pre-commit
  secret scanning, and a surfaced `audit` log.

### Install

- Homebrew tap: `brew install kaeus-inc/kovra/kovra`
- crates.io: `cargo install kovra`
- PyPI (MCP server): `pip install kovra-mcp`

### Platforms

macOS (Apple Silicon) is the reference platform. Windows (Windows Hello +
Credential Manager) and Linux are on the roadmap, behind the same traits.

[0.8.0]: https://github.com/kaeus-inc/kovra-core/releases/tag/v0.8.0
