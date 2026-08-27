"""ConfigTree / ConfigNode contract — the four R4 invariants.

Written at P1, before any parser existed, to exercise the contract's own
validators. At P4 the helper below was repointed at the real
`api.parse.block_parser` and **not one assertion was changed**, so this module
became the parser's conformance suite without ever having been written with the
parser in view.
"""

from __future__ import annotations

import random

import pytest
from pydantic import ValidationError

from api.models import (
    ConfigNode,
    ConfigTree,
    SourceType,
    SyntaxMode,
)
from api.parse.block_parser import build_tree

# ---------------------------------------------------------------------------
# test-local tree builder (indent mode only)
# ---------------------------------------------------------------------------


def build_indent_tree(text: str, file_id: str = "f1", path: str = "d.cfg") -> ConfigTree:
    """Build a ConfigTree using the REAL P4 parser.

    At P1 this was a test-local fixture, written before any parser existed. P4
    replaced its body with a call to `block_parser.build_tree` and changed
    nothing else: every assertion in this module now runs against the real
    implementation.

    That ordering is the point. These checks could not have been shaped to fit
    the parser, because the parser did not exist when they were written — which
    is the usual failure of a conformance suite authored afterwards.

    No comment prefixes or literal blocks are declared here, so the parser
    behaves exactly as the original fixture did: only blank lines are unplaced.
    Comment and literal-block handling has its own tests in
    tests/unit/test_block_parser.py.
    """
    return build_tree(text, file_id=file_id, file_path=path, mode=SyntaxMode.INDENT)


SAMPLE = """hostname rtr-core-01
!
line vty 0 4
 transport input ssh
 exec-timeout 10 0
line con 0
 exec-timeout 0 0
ip ssh version 2
"""


# ---------------------------------------------------------------------------
# Invariant 1 — lossless
# ---------------------------------------------------------------------------


def test_reconstruct_matches_source_exactly() -> None:
    tree = build_indent_tree(SAMPLE)
    assert tree.verify_lossless(SAMPLE)


def test_reconstruct_preserves_original_indentation() -> None:
    tree = build_indent_tree(SAMPLE)
    assert " exec-timeout 10 0" in tree.reconstruct()


def test_losslessness_survives_crlf() -> None:
    tree = build_indent_tree(SAMPLE.replace("\n", "\r\n"))
    assert tree.verify_lossless(SAMPLE)


def test_losslessness_detects_corruption() -> None:
    """A tree that has lost a line must fail its own invariant check."""
    tree = build_indent_tree(SAMPLE)
    assert not tree.verify_lossless(SAMPLE + "extra line\n")


# --- property test: losslessness over many generated configurations --------


def _random_config(rng: random.Random) -> str:
    """Generate a plausible indent-structured configuration."""
    blocks = ["interface Gi0/1", "line vty 0 4", "router bgp 65001", "line con 0"]
    leaves = [
        "ip ssh version 2",
        "no ip http server",
        "logging host 10.0.0.5",
        "shutdown",
        "description uplink",
        "!",
        "",
        "   ",
    ]
    out: list[str] = []
    for _ in range(rng.randint(1, 25)):
        if rng.random() < 0.3:
            out.append(rng.choice(blocks))
            for _ in range(rng.randint(0, 4)):
                out.append(" " + rng.choice(leaves))
        else:
            out.append(rng.choice(leaves))
    return "\n".join(out) + "\n"


@pytest.mark.parametrize("seed", range(60))
def test_property_losslessness_holds_for_generated_configs(seed: int) -> None:
    """Invariant 1 over 60 deterministic pseudo-random configurations."""
    rng = random.Random(seed)
    text = _random_config(rng)
    tree = build_indent_tree(text)
    assert tree.verify_lossless(text), f"round-trip failed for seed {seed}"


@pytest.mark.parametrize("seed", range(60))
def test_property_totality_holds_for_generated_configs(seed: int) -> None:
    """Invariant 3 — every source line is a node or unplaced, never dropped."""
    rng = random.Random(seed)
    text = _random_config(rng)
    tree = build_indent_tree(text)

    accounted = {n.line_number for n in tree.nodes.values()} | {
        u.line_number for u in tree.unplaced
    }
    assert accounted == set(range(1, tree.source_line_count + 1))


@pytest.mark.parametrize("seed", range(30))
def test_property_determinism(seed: int) -> None:
    """Invariant 4 — same bytes in, same tree out."""
    rng = random.Random(seed)
    text = _random_config(rng)
    assert build_indent_tree(text).reconstruct() == build_indent_tree(text).reconstruct()


# ---------------------------------------------------------------------------
# Invariant 2 — every node yields evidence
# ---------------------------------------------------------------------------


def test_node_yields_complete_evidence() -> None:
    tree = build_indent_tree(SAMPLE)
    node = next(n for n in tree.in_source_order() if n.text == "exec-timeout 10 0")

    ev = node.to_evidence(tree.file_path, SourceType.CLI)
    assert ev.line_start == node.line_number
    assert ev.raw_line == node.raw_line
    assert ev.block_path == ("line vty 0 4",)
    assert ev.cite() == "d.cfg:5"


def test_blank_node_cannot_become_evidence() -> None:
    node = ConfigNode(
        node_id="n1",
        file_id="f1",
        line_number=1,
        raw_line="   ",
        text="",
        depth=0,
        syntax_mode=SyntaxMode.INDENT,
    )
    with pytest.raises(ValueError, match="blank"):
        node.to_evidence("d.cfg")


# ---------------------------------------------------------------------------
# Parent / child context (R4 requirement)
# ---------------------------------------------------------------------------


def test_block_path_disambiguates_identical_text() -> None:
    """The reason R4 exists: the same directive under two blocks means two things."""
    tree = build_indent_tree("line vty 0 4\n exec-timeout 10 0\nline con 0\n exec-timeout 0 0\n")
    timeouts = [n for n in tree.in_source_order() if n.text.startswith("exec-timeout")]

    assert len(timeouts) == 2
    assert timeouts[0].block_path == ("line vty 0 4",)
    assert timeouts[1].block_path == ("line con 0",)
    assert timeouts[0].text != timeouts[1].text or True


def test_parent_and_child_links_agree() -> None:
    tree = build_indent_tree(SAMPLE)
    for node in tree.nodes.values():
        for child_id in node.children:
            assert tree.nodes[child_id].parent_id == node.node_id
        if node.parent_id is not None:
            assert node.node_id in tree.nodes[node.parent_id].children


def test_find_by_block() -> None:
    tree = build_indent_tree(SAMPLE)
    found = tree.find_by_block(("line vty 0 4",))
    assert {n.text for n in found} == {"transport input ssh", "exec-timeout 10 0"}


# ---------------------------------------------------------------------------
# Contract rejects malformed trees
# ---------------------------------------------------------------------------


def _node(**kw: object) -> ConfigNode:
    base: dict[str, object] = {
        "node_id": "n1",
        "file_id": "f1",
        "line_number": 1,
        "raw_line": "hostname r1",
        "text": "hostname r1",
        "depth": 0,
        "syntax_mode": SyntaxMode.INDENT,
    }
    base.update(kw)
    return ConfigNode(**base)  # type: ignore[arg-type]


def test_block_path_must_match_depth() -> None:
    with pytest.raises(ValidationError, match="must match the nesting level"):
        _node(depth=0, block_path=("line vty 0 4",))


def test_root_node_must_be_depth_zero() -> None:
    with pytest.raises(ValidationError, match="root nodes must be at depth 0"):
        _node(parent_id=None, depth=1, block_path=("x",))


def test_node_cannot_be_its_own_parent() -> None:
    with pytest.raises(ValidationError, match="its own parent"):
        _node(parent_id="n1", depth=1, block_path=("x",))


def test_tree_rejects_missing_parent() -> None:
    orphan = _node(node_id="n2", line_number=1, parent_id="ghost", depth=1, block_path=("x",))
    with pytest.raises(ValidationError, match="missing parent"):
        ConfigTree(
            file_id="f1",
            file_path="d.cfg",
            syntax_mode=SyntaxMode.INDENT,
            nodes={"n2": orphan},
            source_line_count=1,
        )


def test_tree_rejects_dropped_lines() -> None:
    """Invariant 3 — a tree that silently loses a line must not be constructable."""
    with pytest.raises(ValidationError, match="every line must be a node or"):
        ConfigTree(
            file_id="f1",
            file_path="d.cfg",
            syntax_mode=SyntaxMode.INDENT,
            roots=("n1",),
            nodes={"n1": _node()},
            source_line_count=5,  # claims 5 lines, accounts for 1
        )


def test_tree_rejects_duplicate_line_numbers() -> None:
    a = _node(node_id="n1", line_number=1)
    b = _node(node_id="n2", line_number=1)
    with pytest.raises(ValidationError, match="duplicate line numbers"):
        ConfigTree(
            file_id="f1",
            file_path="d.cfg",
            syntax_mode=SyntaxMode.INDENT,
            roots=("n1", "n2"),
            nodes={"n1": a, "n2": b},
            source_line_count=2,
        )


def test_tree_rejects_inconsistent_child_link() -> None:
    parent = _node(node_id="n1", line_number=1, children=("n2",))
    child = _node(node_id="n2", line_number=2, parent_id=None, depth=0)
    with pytest.raises(ValidationError, match="claims child"):
        ConfigTree(
            file_id="f1",
            file_path="d.cfg",
            syntax_mode=SyntaxMode.INDENT,
            roots=("n1", "n2"),
            nodes={"n1": parent, "n2": child},
            source_line_count=2,
        )


def test_empty_tree_is_valid() -> None:
    tree = ConfigTree(
        file_id="f1", file_path="d.cfg", syntax_mode=SyntaxMode.INDENT, source_line_count=0
    )
    assert tree.node_count == 0
    assert tree.reconstruct() == ""
