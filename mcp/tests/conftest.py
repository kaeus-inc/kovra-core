"""Pytest fixtures: a throwaway vault + a session, built with deterministic
mocks (passphrase/Argon2 backend, no OS keychain, no real secrets).

The vault is initialized and seeded via the real `kovra` CLI binary (built from
the workspace), so the tests exercise the same on-disk format the bindings read.
Every value here is a throwaway test string.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import kovra_ffi

# Workspace root is two levels up from this file (mcp/tests/ -> repo root).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_PASSPHRASE = "pytest-throwaway-passphrase"


def _kovra_bin() -> str:
    """Locate the debug `kovra` binary, building it once if necessary."""
    candidate = _REPO_ROOT / "target" / "debug" / "kovra"
    if not candidate.exists():
        subprocess.run(
            ["cargo", "build", "-p", "kovra"],
            cwd=_REPO_ROOT,
            check=True,
        )
    return str(candidate)


def _run(bin_: str, env: dict[str, str], *args: str, stdin: str | None = None) -> None:
    subprocess.run(
        [bin_, *args],
        cwd=_REPO_ROOT,
        env=env,
        input=stdin,
        text=True,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def vault(tmp_path: Path) -> dict[str, str]:
    """An initialized, seeded vault. Returns the env (VAULT_DIR + PASSPHRASE) the
    bindings read. Seeds, in the global vault:

    - ``dev/app/token``    medium, **revealable**   (the one MCP-revealable secret)
    - ``dev/app/locked``   medium, not revealable
    - ``prod/db/password`` born high (I5)
    """
    bin_ = _kovra_bin()
    env = {
        **os.environ,
        "KOVRA_VAULT_DIR": str(tmp_path),
        "KOVRA_PASSPHRASE": _PASSPHRASE,
    }
    _run(bin_, env, "init")
    _run(bin_, env, "add", "secret:dev/app/token", "--stdin", "--revealable", stdin="dev-token-val")
    _run(bin_, env, "add", "secret:dev/app/locked", "--stdin", stdin="locked-val")
    _run(bin_, env, "add", "secret:prod/db/password", "--stdin", stdin="prod-pw-val")
    return {"KOVRA_VAULT_DIR": str(tmp_path), "KOVRA_PASSPHRASE": _PASSPHRASE}


def make_session(vault: dict[str, str], operations: list[str], environments) -> kovra_ffi.KovraSession:
    """Open a `KovraSession` over the fixture vault with an explicit scope."""
    return kovra_ffi.KovraSession(
        {"operations": operations, "environments": environments},
        vault["KOVRA_VAULT_DIR"],
        vault["KOVRA_PASSPHRASE"],
    )
