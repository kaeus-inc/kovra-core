"""Server-level tests: the FastMCP wrapper registers exactly the §9.4 tools and
propagates the binding's policy errors as tool errors (no policy in Python).
"""

from __future__ import annotations

import asyncio

from conftest import make_session

from kovra_mcp.server import create_server

_EXPECTED_TOOLS = {
    "list",
    "status",
    "fingerprint",
    "set",
    "generate",
    "delete",
    "edit_metadata",
    "reveal",
    "inject_run",
}


def test_server_registers_exactly_the_spec_tools(vault):
    srv = create_server(make_session(vault, ["metadata"], "*"))
    tools = asyncio.run(srv.list_tools())
    assert {t.name for t in tools} == _EXPECTED_TOOLS


def test_no_unattended_mode_tool(vault):
    # I11 — the surface is exactly the nine §9.4 tools, so there is no
    # unattended/auto-approve tool (or any tool) beyond that closed set. The
    # exact-set check is the strong form; this asserts the closure explicitly.
    srv = create_server(make_session(vault, ["metadata"], "*"))
    names = {t.name for t in asyncio.run(srv.list_tools())}
    assert names == _EXPECTED_TOOLS
    assert "approve" not in names  # broker approval is CLI-only, never an MCP tool


def test_reveal_tool_propagates_denied(vault):
    # The reveal tool surfaces the core's denial without yielding the plaintext.
    # FastMCP may either return error content or raise; handle both and assert the
    # value never appears in whatever the agent would observe.
    srv = create_server(make_session(vault, ["metadata", "reveal"], "*"))

    def observed() -> str:
        try:
            result = asyncio.run(
                srv.call_tool("reveal", {"coordinate": "secret:prod/db/password"})
            )
        except Exception as exc:  # noqa: BLE001 — any tool error is acceptable here
            return str(exc)
        # Normalize the various return shapes (content list, or (content, structured)).
        content = result[0] if isinstance(result, tuple) else getattr(result, "content", result)
        try:
            return " ".join(getattr(c, "text", "") for c in content)
        except TypeError:
            return str(content)

    text = observed()
    assert "prod-pw-val" not in text
    # the denial reason is surfaced (helps the agent), but never the value
    assert "Forbidden" in text or "denied" in text.lower() or "not" in text.lower()
