"""Build the session ``AgentScope`` for the MCP server from the environment.

The scope is fixed when the server starts and is **never** widened by the model
(I13). The Rust core enforces the real sensitivity boundaries regardless of the
scope (a `prod`/`high` value is never revealed to an agent even if its
environment is in scope), so these knobs are a *containment*, not the boundary.

Environment variables:
- ``KOVRA_MCP_OPERATIONS``  — comma list of ``metadata,reveal,inject`` (default all three).
- ``KOVRA_MCP_ENVIRONMENTS`` — comma list, or ``*`` for any (default ``*``).
- ``KOVRA_MCP_PROJECTS``     — comma list, or ``*`` for any (default ``*``).

The vault location and keyring backend come from ``KOVRA_VAULT_DIR`` /
``KOVRA_PASSPHRASE`` (read by the bindings themselves).
"""

from __future__ import annotations

import os

_DEFAULT_OPERATIONS = "metadata,reveal,inject"


def _axis(value: str) -> list[str] | None:
    """A comma list, or ``None`` (any) for empty / ``*``."""
    value = value.strip()
    if value in ("", "*"):
        return None
    return [part.strip() for part in value.split(",") if part.strip()]


def scope_from_env(environ: dict[str, str] | None = None) -> dict:
    """The ``scope`` dict passed to ``kovra_ffi.KovraSession``."""
    env = environ if environ is not None else os.environ
    operations = env.get("KOVRA_MCP_OPERATIONS", _DEFAULT_OPERATIONS)
    return {
        "operations": [op.strip() for op in operations.split(",") if op.strip()],
        "environments": _axis(env.get("KOVRA_MCP_ENVIRONMENTS", "*")),
        "projects": _axis(env.get("KOVRA_MCP_PROJECTS", "*")),
    }
