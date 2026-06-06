# kovra-webui

The on-demand, loopback-only **Web UI** for [kovra](https://kovra.sh), launched
with `kovra ui`. It visualizes the vault — coordinates, sensitivity tiers, modes,
projects, and metadata — without ever exposing what the policy protects.

- The plaintext of a `high` or `inject-only` secret is **never rendered**; those
  are shown masked. A browser tab is treated as just another surface and held to
  the same boundary that protects an agent.
- The server binds to loopback only and is gated by an attended confirmation at
  launch.
- This crate also ships the **`kovra-ui` container entrypoint**, the binary that
  runs inside the published `kovra-ui` image for `kovra ui --docker`. In the
  container the master key arrives only as a Docker secret in tmpfs — never baked
  into an image layer.

Part of the kovra workspace: <https://github.com/kaeus-inc/kovra-core>.
Licensed under BUSL-1.1.
