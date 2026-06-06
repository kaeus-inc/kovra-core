# Contributing to kovra

Thanks for your interest. `kovra` is a **product of Kaeus Inc**, published
**source-available** under BSL 1.1 so you can read, audit, build, and fork it.

## Contribution posture (at launch): read-only

To keep a security-critical, single-maintainer project safe and its open-core
licensing clean, **we are not accepting external code pull requests right now.**
PRs from outside the maintainers may be closed without review. This may change as
the project grows — watch this file.

**What is very welcome:**

- 🐛 **Bug reports** — open an issue with a clear reproduction.
- 🔒 **Security reports** — **privately**, per [`SECURITY.md`](./SECURITY.md)
  (never a public issue).
- 💬 **Questions, ideas, feedback** — open a discussion or issue.
- 🍴 **Forks** — permitted under [`LICENSE`](./LICENSE) (BSL 1.1).

## Non-negotiable rule: no real secrets, ever

kovra is the tool that keeps secrets out of code. Hold the project to its own
standard: **never put a real credential** in an issue, a discussion, a fork's
commits, or a test. All tests use **mocks and throwaway values**; redact any
secret in a bug report.

## Building & testing (for forks / auditing)

macOS (Apple Silicon), stable Rust toolchain, and `uv` for the Python MCP layer.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
# Python MCP layer:
cd mcp && uv sync && uv run ruff check . && uv run pytest -q
```

The gate must be green, and there is **one test per security invariant** — please
keep it that way in any fork you publish.

## If/when PRs open later

We would accept contributions under a sign-off (DCO) or a CLA so Kaeus Inc can
keep the open-core/commercial model coherent. Until this file says otherwise,
the posture above (read-only) is in effect.
