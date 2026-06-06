# kovra-agent

A **governed ssh-agent** for [kovra](https://kovra.sh). It serves SSH
signatures from keypairs held in the vault — the private key material never
leaves kovra's custody and is never written to `~/.ssh`.

- Keys are stored as kovra credentials and served over the ssh-agent protocol,
  so `ssh`/`git` use them transparently.
- Each signature is subject to kovra's sensitivity policy; higher-sensitivity
  keys can require an attended confirmation per signature, with the requesting
  process named in the prompt.
- A thin face over `kovra-core`: the dependency points inward only (agent →
  core), preserving the same security boundary as the rest of the workspace.

Part of the kovra workspace: <https://github.com/kaeus-inc/kovra-core>.
Licensed under BUSL-1.1.
