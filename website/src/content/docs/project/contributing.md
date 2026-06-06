---
title: Contributing
description: How to contribute to kovra.
---

Contributions are welcome — bug reports, ideas, docs, and code. kovra is a
security tool, so a few ground rules matter more than usual.

## Ground rules

- **Never include a real secret.** Not in code, tests, issues, screenshots, or
  discussion. All tests use throwaway values and mocks — the tool that protects
  secrets must never ingest one.
- **Report security issues privately.** Don't open a public issue for a
  vulnerability — see [Support & community](/project/support/) for how.
- **Keep the security boundary intact.** kovra's invariants are deliberate; a
  change that weakens one to make a feature easier won't be accepted. If a task
  seems to require it, raise it for discussion first.

## Reporting a bug or proposing a change

1. Search the [issue tracker](https://github.com/kaeus-inc/kovra-core/issues)
   first.
2. Open an issue describing the behavior (steps, expected vs. actual) or the idea.
3. For code, open a pull request against
   [`kaeus-inc/kovra-core`](https://github.com/kaeus-inc/kovra-core). Keep the
   change focused and explain the *why*.

## Working on the code

kovra is Rust (core/CLI/wrapper/Web UI) with a Python MCP server. Before opening a
PR, make the standard gate green:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

New behavior should come with tests — and security-relevant behavior with a test
that pins the guarantee it provides.
