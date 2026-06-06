# kovra-core

The core of **kovra** — a local secrets manager for development that custodies
keys, passwords, and tokens and delivers them to processes without leaking
plaintext.

This crate holds the logic that everything else builds on:

- the encrypted **vault** (per-record sealing, fingerprints, the registry of
  global and per-project vaults);
- the **sensitivity policy** (`low` / `medium` / `high` / `inject-only`) and the
  rules that govern reveal, injection, allowlisting, and attended confirmation;
- the **provider** abstraction for resolving external references behind a
  mockable trait;
- the security boundary the rest of the workspace is held to — secret-bearing
  types are zeroized and never implement `Debug`/`Display` over their value.

OS-specific and cloud pieces (biometrics, keyring, cloud CLIs, the subprocess
runner, the clock) sit behind traits so the core is tested with deterministic
mocks. `kovra-core` never depends on the higher layers — the dependency arrow
always points inward.

Part of the kovra workspace: <https://github.com/kaeus-inc/kovra-core>.
Licensed under BUSL-1.1.
