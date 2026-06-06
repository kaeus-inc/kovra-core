# kovra-providers-azure

The **Azure Key Vault** secret provider for [kovra](https://kovra.sh). It
resolves `azure-kv://` references at injection time using the host's ambient
`az` CLI identity.

- A reference is a pointer, not a copy — the secret value lives in Azure Key
  Vault and is fetched on demand, held in a zeroizing buffer, and handed to the
  core without being logged or written to disk.
- The real `az` subprocess runs under a bounded per-invocation timeout.
- `kovra-core` knows only the provider trait; this crate is the only place that
  knows about Azure. It is injected into kovra's scheme router by the CLI/FFI.

Part of the kovra workspace: <https://github.com/kaeus-inc/kovra-core>.
Licensed under BUSL-1.1.
