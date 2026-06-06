"""The Kovra FastMCP server (spec §9.4).

Registers the agent-facing tools 1:1 over ``kovra_ffi.KovraSession``. Each tool
is a thin marshaller: it calls the binding and returns the result. The binding
(and the Rust core beneath it) is the sole authority on scope and sensitivity —
this module decides nothing. There is deliberately **no unattended-mode tool**
(I11): real delivery of ``high``/``prod``/``inject-only`` goes through the CLI +
``kovra approve`` broker, which ``inject_run`` drives but the model cannot bypass.
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

import kovra_ffi

from .conventions import setup_prompt
from .scope import scope_from_env


def build_session() -> kovra_ffi.KovraSession:
    """Open a session from the environment (scope + ``KOVRA_VAULT_DIR`` / passphrase)."""
    return kovra_ffi.KovraSession(scope_from_env())


def create_server(session: kovra_ffi.KovraSession | None = None) -> FastMCP:
    """Build the FastMCP server. A session may be injected (tests); otherwise one
    is opened lazily from the environment on first use.

    The session is built lazily so the server still starts (and lists its tools)
    when the vault is not yet initialized — the first tool call then surfaces a
    clear error instead of the whole server failing to register."""
    mcp = FastMCP("kovra")
    holder: dict[str, kovra_ffi.KovraSession | None] = {"session": session}

    def get() -> kovra_ffi.KovraSession:
        if holder["session"] is None:
            holder["session"] = build_session()
        return holder["session"]

    @mcp.tool(name="list")
    def list_secrets() -> list[dict[str, Any]]:
        """List metadata for every secret addressable in this session. Returns
        coordinates, sensitivity, mode, fingerprint and flags — never values.
        Out-of-scope secrets do not appear."""
        return get().list()

    @mcp.tool()
    def status(coordinate: str, project: str | None = None) -> dict[str, Any]:
        """Metadata for one coordinate (diagnose). Errors if the coordinate is
        not addressable in this session (out of scope or absent)."""
        return get().status(coordinate, project)

    @mcp.tool()
    def fingerprint(coordinate: str, project: str | None = None) -> str:
        """The truncated fingerprint of a coordinate's value (not the value)."""
        return get().fingerprint(coordinate, project)

    @mcp.tool(name="set")
    def set_secret(coordinate: str, value: str, project: str | None = None) -> dict[str, Any]:
        """Create or update a literal secret value. Returns the new metadata (not
        the value). A ``prod`` secret is born ``high``."""
        return get().set(coordinate, value, project)

    @mcp.tool()
    def generate(
        coordinate: str,
        length: int = 32,
        sensitivity: str | None = None,
        description: str | None = None,
        project: str | None = None,
    ) -> dict[str, Any]:
        """Generate a random value server-side and store it. Returns metadata
        only — the value is never returned."""
        return get().generate(coordinate, length, sensitivity, description, project)

    @mcp.tool()
    def delete(coordinate: str, project: str | None = None) -> str:
        """Delete a secret. Errors if not addressable in this session."""
        get().delete(coordinate, project)
        return f"deleted {coordinate}"

    @mcp.tool()
    def edit_metadata(
        coordinate: str,
        sensitivity: str | None = None,
        description: str | None = None,
        revealable: bool | None = None,
        reference: str | None = None,
        project: str | None = None,
    ) -> dict[str, Any]:
        """Edit a secret's metadata (sensitivity / description / revealable /
        reference). Lowering sensitivity is separately audited."""
        return get().edit_metadata(
            coordinate, sensitivity, description, revealable, reference, project
        )

    @mcp.tool()
    def reveal(coordinate: str, project: str | None = None) -> str:
        """Reveal a value into context. Permitted **only** for a secret explicitly
        marked revealable that is non-``prod`` and non-``high``; otherwise denied.
        ``prod``/``high``/``inject-only`` are never returned."""
        value = get().reveal(coordinate, project)
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                "value is binary and not representable as text over MCP"
            ) from exc

    @mcp.tool()
    def inject_run(
        refs: str,
        env: str,
        program: str,
        args: list[str] | None = None,
        project: str | None = None,
    ) -> dict[str, Any]:
        """Resolve an inline ``.env.refs`` and run ``program`` with the values
        injected into the child's environment (never into your context). High/prod
        injection requires an allowlisted executor and an attended ``kovra approve``.
        Returns ``{status, stdout, stderr}`` with vault values masked."""
        out = get().inject_run(refs, env, program, args or [], project)
        return {
            "status": out["status"],
            "stdout": out["stdout"].decode("utf-8", "replace"),
            "stderr": out["stderr"].decode("utf-8", "replace"),
        }

    @mcp.prompt()
    def setup_kovra_conventions() -> str:
        """Return the kovra conventions block plus idempotent-merge instructions
        for inserting/updating it in this repository's CLAUDE.md. The agent
        performs the edit; `kovra setup` does the same merge from the CLI."""
        return setup_prompt()

    return mcp


def main() -> None:
    """Console-script entry point: serve over stdio (Claude Code transport)."""
    create_server().run(transport="stdio")


if __name__ == "__main__":
    main()
