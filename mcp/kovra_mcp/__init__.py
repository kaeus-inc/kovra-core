"""Kovra MCP server — the agent-facing secrets surface (spec §9.4).

A thin FastMCP wrapper over the ``kovra_ffi`` PyO3 bindings. **No policy lives
here**: every scope/reveal/inject rule is enforced by the Rust core through the
bindings (spec §2/§15). This package only registers tools and marshals results.
"""

from .server import create_server, main

__all__ = ["create_server", "main"]
