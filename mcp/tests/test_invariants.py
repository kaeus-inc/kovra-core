"""Invariant tests at the Python / MCP boundary.

These complement the Rust-side tests in ``crates/ffi-python``: they prove the
invariants still hold *as the agent sees them* — through the bindings and, for
the reveal path, through the FastMCP server. One test per applicable invariant
(I5, I6, I11, I12, I13, I14, I15/I16), all with throwaway values.
"""

from __future__ import annotations

import pytest
from conftest import make_session

import kovra_ffi


# ── I13 — scope is enforced first; out-of-scope is unaddressable, not denied ──

def test_i13_list_omits_out_of_scope(vault):
    s = make_session(vault, ["metadata"], ["dev"])  # prod out of scope
    coords = {r["coordinate"] for r in s.list()}
    assert "dev/app/token" in coords
    assert "prod/db/password" not in coords


def test_i13_status_out_of_scope_is_not_found(vault):
    s = make_session(vault, ["metadata"], ["dev"])
    with pytest.raises(kovra_ffi.KovraNotFound):
        s.status("secret:prod/db/password")


def test_i13_absent_is_same_error_as_out_of_scope(vault):
    s = make_session(vault, ["metadata"], ["dev"])
    # A genuinely absent in-scope coordinate raises the *same* error as an
    # out-of-scope one — the two are indistinguishable to the agent.
    with pytest.raises(kovra_ffi.KovraNotFound):
        s.status("secret:dev/nope/missing")


# ── I11 — MCP reveals only a revealable, non-prod, non-high literal ──

def test_i11_reveal_allows_revealable_nonprod(vault):
    s = make_session(vault, ["metadata", "reveal"], "*")
    assert s.reveal("secret:dev/app/token") == b"dev-token-val"


def test_i11_reveal_denies_non_revealable(vault):
    s = make_session(vault, ["metadata", "reveal"], "*")
    with pytest.raises(kovra_ffi.KovraDenied):
        s.reveal("secret:dev/app/locked")


# ── I14 — prod plaintext is never returned to an agent ──

def test_i14_reveal_prod_is_denied(vault):
    s = make_session(vault, ["metadata", "reveal"], "*")
    with pytest.raises(kovra_ffi.KovraDenied):
        s.reveal("secret:prod/db/password")


# ── I5 — prod is born high ──

def test_i5_prod_set_is_born_high(vault):
    s = make_session(vault, ["metadata"], "*")
    meta = s.set("secret:prod/new/secret", "x")
    assert meta["sensitivity"] == "high"


# ── I6 — generate never returns the value ──

def test_i6_generate_returns_metadata_not_value(vault):
    s = make_session(vault, ["metadata"], "*")
    meta = s.generate("secret:dev/app/gen", 24)
    assert "value" not in meta
    assert meta["fingerprint"]


# ── I12 — writes are audited without the value ──

def test_i12_audit_has_no_plaintext(vault):
    s = make_session(vault, ["metadata"], "*")
    s.set("secret:dev/app/audited", "p@ssw0rd-not-logged")
    audit = (
        __import__("pathlib").Path(vault["KOVRA_VAULT_DIR"]) / "audit.log"
    ).read_text()
    assert "p@ssw0rd-not-logged" not in audit
    assert "dev/app/audited" in audit


# ── I15/I16 — high inject needs an allowlisted executor + confirmation ──

def test_i15_high_inject_without_allowlist_is_denied(vault):
    # Mark a dev secret high so its injection is gated, then try to run an
    # executable that is not on the allowlist: refused before launch (I15).
    s = make_session(vault, ["metadata", "inject"], "*")
    s.edit_metadata("secret:dev/app/token", sensitivity="high")
    with pytest.raises(kovra_ffi.KovraDenied):
        s.inject_run("T=secret:dev/app/token", "dev", "/usr/bin/deploy", ["--now"])


def test_low_inject_runs_and_masks_output(vault):
    # A low/dev injection runs ungated and the value is masked in the output.
    s = make_session(vault, ["inject"], "*")
    s2 = make_session(vault, ["metadata"], "*")
    s2.edit_metadata("secret:dev/app/token", sensitivity="low")
    out = s.inject_run(
        "T=secret:dev/app/token", "dev", "/bin/sh", ["-c", "echo using $T"]
    )
    assert out["status"] == 0
    assert b"dev-token-val" not in out["stdout"]
    assert b"***" in out["stdout"]
