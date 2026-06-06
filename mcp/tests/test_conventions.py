"""Tests for the kovra conventions prompt (KOV-9).

Covers: the prompt is registered on the server; the vendored block does not
drift from the canonical template in the repo; the block carries the key rules.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from conftest import make_session

from kovra_mcp.conventions import BEGIN, END, conventions_block, setup_prompt
from kovra_mcp.server import create_server

# Repo root is two levels up from mcp/tests/.
_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_vendored_block_matches_canonical_template():
    # The package copy must stay byte-identical to templates/kovra-conventions.md
    # (the CLI compiles that same file in via include_str!).
    canonical = (_REPO_ROOT / "templates" / "kovra-conventions.md").read_text()
    assert conventions_block() == canonical, "vendored block drifted from the template"


def test_block_has_markers_and_key_rules():
    block = conventions_block()
    assert BEGIN in block and END in block
    assert "kovra run" in block
    assert ".env.refs" in block


def test_setup_prompt_includes_block_and_merge_instructions():
    text = setup_prompt()
    assert BEGIN in text and END in text
    assert "idempotent" in text.lower()
    assert "CLAUDE.md" in text


def test_prompt_is_registered_on_server(vault):
    srv = create_server(make_session(vault, ["metadata"], "*"))
    prompts = asyncio.run(srv.list_prompts())
    assert any(p.name == "setup_kovra_conventions" for p in prompts)
