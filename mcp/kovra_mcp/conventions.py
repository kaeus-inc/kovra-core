"""The kovra conventions block, exposed to the agent as an MCP prompt.

The block is the same canonical text the CLI ships (`templates/kovra-conventions.md`),
vendored into the package so it is available at runtime. A drift test asserts the
two copies stay byte-identical. This module holds no policy — the prompt only
hands the agent the block plus instructions to merge it into the repo's
`CLAUDE.md` (the agent performs the edit).
"""

from __future__ import annotations

from importlib import resources

BEGIN = "<!-- kovra:begin -->"
END = "<!-- kovra:end -->"


def conventions_block() -> str:
    """The canonical conventions block (between and including the markers)."""
    return resources.files("kovra_mcp").joinpath("kovra-conventions.md").read_text()


def setup_prompt() -> str:
    """The text returned by the `setup_kovra_conventions` MCP prompt: the block
    plus idempotent-merge instructions for the agent to apply to `CLAUDE.md`."""
    block = conventions_block().rstrip("\n")
    return (
        "Add (or update) the kovra conventions in this repository's CLAUDE.md so "
        "the secure secrets path is the default convention.\n\n"
        "Apply this block **idempotently**:\n"
        f"- If CLAUDE.md has no `{BEGIN}` … `{END}` markers, append the block "
        "(leave the rest of the file untouched).\n"
        "- If those markers already exist, replace only the text between them "
        "(preserve everything outside).\n"
        "- Never duplicate the block; there must be exactly one marker pair.\n\n"
        "Tip: `kovra setup` performs this same merge from the CLI.\n\n"
        "----- BEGIN BLOCK -----\n"
        f"{block}\n"
        "----- END BLOCK -----\n"
    )
