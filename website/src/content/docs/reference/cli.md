---
title: CLI reference
description: Every kovra command, grouped by what it does. Run `kovra <command> --help` for the full flags.
---

This is the map of the `kovra` CLI. Each command runs through the same
[policy decision](/security/decision/); run `kovra <command> --help` for its
exact flags and arguments.

## Setup & vault

| Command | What it does |
| --- | --- |
| `kovra init` | Initialize the vault registry and master key. |
| `kovra setup` | Onboard the current repo: ensure the vault, register the MCP server in `.mcp.json`, insert the conventions block in `CLAUDE.md`. |

## Secrets

| Command | What it does |
| --- | --- |
| `kovra add <coord>` | Create a secret (value via hidden prompt or `--stdin`; never argv). |
| `kovra set <coord>` | Update a secret's value. |
| `kovra edit <coord>` | Edit metadata (sensitivity / description / reference); lowering sensitivity is a guarded downgrade. |
| `kovra rm <coord>` | Delete a secret. |
| `kovra list` | List secrets — metadata only, never values. |
| `kovra show <coord>` | Reveal one value to stdout (`high` needs <span class="bioprove">bioProve</span>; `inject-only` never). |
| `kovra generate <coord>` | Generate a random value server-side; never printed. |
| `kovra import <coord> --from op://…` | Copy a value from 1Password into the vault as a literal. |

## Injection

| Command | What it does |
| --- | --- |
| `kovra run --env <e> -- <cmd>` | Resolve an `.env.refs` and run a command with values injected into the child process. `--allow` allowlists an executable for `high`/`prod`. |

## Typed credentials

| Command | What it does |
| --- | --- |
| `kovra code <coord>` | Print the current TOTP code (never the seed). |
| `kovra keygen <coord>` | Generate and custody an asymmetric keypair (private half never on disk). |
| `kovra pubkey <coord>` | Print a keypair's OpenSSH public key (free). |
| `kovra sign / verify` | Sign data with the private key / verify a signature. |
| `kovra encrypt / decrypt` | Encrypt to / decrypt with an `ed25519` keypair. |
| `kovra ssh-add <coord>` | Load a custodied key into the running ssh-agent, in memory only. |
| `kovra ssh-agent` | Run kovra as a governed ssh-agent (signs in memory; `high`/`prod` confirm per signature). |

## Providers

| Command | What it does |
| --- | --- |
| `kovra add <coord> --reference azure-kv://…` | Store a pointer to Azure Key Vault. |
| `kovra add <coord> --reference aws-sm://…` | Store a pointer to AWS Secrets Manager. |

References resolve at runtime under your own identity. See
[Cloud references](/guides/references/).

## Sharing & USB exchange

| Command | What it does |
| --- | --- |
| `kovra package` | Seal a non-`prod` env to a recipient's key; writes the package + a separate access token. |
| `kovra unpack` | Open a sealed package with your private identity. |
| `kovra exchange init / seal / register-token / open` | USB offline bootstrap of a kovra-less machine (macOS only). |

## Confirmation

| Command | What it does |
| --- | --- |
| `kovra confirm <text>` | Request an attended human confirmation (exit 0 if approved) — for a host/app to gate its own action. |
| `kovra approve [id]` | Approve/deny a pending confirmation from another session (the file-broker fallback to biometrics). |

## Web UI

| Command | What it does |
| --- | --- |
| `kovra ui` | Bring up the on-demand loopback admin UI (`--docker` to run it in a container). |

## Hygiene & maintenance

| Command | What it does |
| --- | --- |
| `kovra scaffold` | Scan source for env-var references and propose an `.env.refs` (reads names only, never values). |
| `kovra doctor` (`lint`) | Validate a project's secret config; coordinates + status only, never a value. |
| `kovra hooks` | Manage git hooks that keep secrets out of commits. |
| `kovra audit` | Query the audit trail — coordinates, truncated fingerprints, timestamps, origin; never a value. |
| `kovra key export / import` | Back up / restore the vault master key (disaster recovery). |
