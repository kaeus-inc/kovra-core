<!--
⚠️ Contribution posture: kovra is currently READ-ONLY for external contributors
(see CONTRIBUTING.md). PRs from outside the maintainers may be closed without
review. Thanks for understanding — please open an issue/discussion instead.

🔒 Never include a real secret value in a PR. Security issues go to SECURITY.md
(private), not a PR.
-->

## What & why

<!-- Describe the change and the motivation. Link any related issue. -->

## Checklist

- [ ] No real secret values anywhere in the diff (tests use mocks/throwaway).
- [ ] `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` are green.
- [ ] A test exists for any affected security invariant.
- [ ] I have read `CONTRIBUTING.md` and understand the read-only posture.
