"""Structural parsing — comments, literal blocks, deferred modes, edge shapes.

The P1 conformance suite in test_config_tree.py already runs the four invariants
against this parser. What is tested here is the behaviour P4 adds on top:
which lines become nodes, which deliberately do not, and what happens when the
parser is asked for something it does not implement.
"""

from __future__ import annotations

import pytest

from api.models import LiteralBlock, SyntaxMode
from api.parse.block_parser import (
    REASON_BLANK,
    REASON_COMMENT,
    REASON_LITERAL,
    build_tree,
)
from api.parse.errors import UnsupportedSyntaxModeError, UnterminatedLiteralBlockError

BANNER = LiteralBlock(name="banner", open=r"^banner \S+ (\S+)$", terminator_group=1)
CERTIFICATE = LiteralBlock(
    name="certificate", open=r"^crypto pki certificate chain \S+$", terminator="quit"
)


def tree(text: str, **kw):
    return build_tree(text, file_id="f" * 64, file_path="d.cfg", **kw)


def texts(t) -> list[str]:
    return [n.text for n in t.in_source_order()]


def reasons(t) -> list[str]:
    return [u.reason for u in t.unplaced]


# ---------------------------------------------------------------------------
# Comments — a safety property, not tidiness
# ---------------------------------------------------------------------------


def test_comments_are_not_nodes() -> None:
    t = tree("hostname r1\n! a comment\nip ssh version 2\n", comment_prefixes=("!",))
    assert texts(t) == ["hostname r1", "ip ssh version 2"]
    assert reasons(t) == [REASON_COMMENT]


def test_commented_out_directive_cannot_become_a_fact() -> None:
    """The reason comments are excluded at all.

    A commented-out command is not in effect. If it were a node, a pattern would
    match it and NIRIKSHAK would report a security fact that is not true of the
    device — with a citation, which makes it more convincing, not less.
    """
    t = tree("hostname r1\n!ip ssh version 1\n", comment_prefixes=("!",))

    assert "ip ssh version 1" not in texts(t)
    assert all("ssh" not in n.text for n in t.nodes.values())


def test_indented_comment_is_still_a_comment() -> None:
    t = tree("line vty 0 4\n ! disabled for now\n transport input ssh\n", comment_prefixes=("!",))
    assert texts(t) == ["line vty 0 4", "transport input ssh"]


def test_comments_are_preserved_losslessly() -> None:
    source = "hostname r1\n! keep me\nip ssh version 2\n"
    assert tree(source, comment_prefixes=("!",)).verify_lossless(source)


def test_no_comment_prefix_means_comments_are_nodes() -> None:
    """Comment syntax is pack data, not a parser assumption."""
    t = tree("hostname r1\n! not declared as a comment\n")
    assert "! not declared as a comment" in texts(t)


# ---------------------------------------------------------------------------
# Literal blocks — generalised, not banner-specific (D7)
# ---------------------------------------------------------------------------


def test_banner_body_is_not_a_node() -> None:
    source = "banner motd ^C\nAuthorised access only.\n^C\nip ssh version 2\n"
    t = tree(source, literal_blocks=(BANNER,))

    assert texts(t) == ["banner motd ^C", "ip ssh version 2"]
    assert reasons(t) == [REASON_LITERAL, REASON_LITERAL]
    assert t.verify_lossless(source)


def test_banner_opener_remains_a_node_so_it_can_be_cited() -> None:
    t = tree("banner motd ^C\ntext\n^C\n", literal_blocks=(BANNER,))
    opener = t.in_source_order()[0]
    assert opener.text == "banner motd ^C"
    assert opener.to_evidence("d.cfg").line_start == 1


def test_banner_body_cannot_be_matched_by_a_pattern() -> None:
    """A banner quoting a command must not produce that command as a fact."""
    source = "banner motd ^C\nip ssh version 1 is prohibited\n^C\n"
    t = tree(source, literal_blocks=(BANNER,))

    assert all("prohibited" not in n.text for n in t.nodes.values())
    assert t.verify_lossless(source)


def test_fixed_terminator_literal_block() -> None:
    """D7 — not special-cased to banners. A certificate closes on `quit`."""
    source = (
        "crypto pki certificate chain TP-self\n"
        "  certificate self-signed 01\n"
        "  30820330 A0030201\n"
        "  quit\n"
        "ip ssh version 2\n"
    )
    t = tree(source, literal_blocks=(CERTIFICATE,))

    assert texts(t) == ["crypto pki certificate chain TP-self", "ip ssh version 2"]
    assert reasons(t) == [REASON_LITERAL] * 3
    assert t.verify_lossless(source)


def test_empty_literal_body() -> None:
    """An opener immediately followed by its terminator."""
    source = "banner motd ^C\n^C\nip ssh version 2\n"
    t = tree(source, literal_blocks=(BANNER,))

    assert texts(t) == ["banner motd ^C", "ip ssh version 2"]
    assert reasons(t) == [REASON_LITERAL]
    assert t.verify_lossless(source)


def test_blank_lines_inside_a_literal_body_stay_in_the_body() -> None:
    source = "banner motd ^C\nline one\n\nline three\n^C\n"
    t = tree(source, literal_blocks=(BANNER,))

    assert reasons(t) == [REASON_LITERAL] * 4
    assert t.verify_lossless(source)


def test_comment_inside_a_literal_body_is_body_not_comment() -> None:
    source = "banner motd ^C\n! this is banner text, not a comment\n^C\n"
    t = tree(source, comment_prefixes=("!",), literal_blocks=(BANNER,))
    assert reasons(t) == [REASON_LITERAL, REASON_LITERAL]


def test_unterminated_literal_block_raises() -> None:
    with pytest.raises(UnterminatedLiteralBlockError, match="never closed"):
        tree("banner motd ^C\nsome text\n", literal_blocks=(BANNER,))


@pytest.mark.parametrize(
    "source",
    [
        "banner motd ^C\nbody\n^C\n",
        "banner motd ^C\n^C\n",
        "banner login #\nbody\n#\n",
        "banner motd ^C\nbody\n^C\nbanner login #\nmore\n#\n",
    ],
)
def test_property_literal_blocks_stay_lossless(source: str) -> None:
    assert tree(source, literal_blocks=(BANNER,)).verify_lossless(source)


# ---------------------------------------------------------------------------
# Deferred syntax modes (D8)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode", [SyntaxMode.BRACE, SyntaxMode.XML, SyntaxMode.JSON])
def test_deferred_modes_raise_rather_than_returning_an_empty_tree(mode: SyntaxMode) -> None:
    """D8 — an empty tree would look like a cleanly parsed empty configuration.

    Every field would read UNKNOWN, the file would appear handled, and nothing
    would say the parser had simply declined.
    """
    with pytest.raises(UnsupportedSyntaxModeError) as exc:
        tree("anything at all\n", mode=mode)

    assert exc.value.mode is mode
    assert "not implemented" in str(exc.value)
    assert "empty tree" in str(exc.value)


def test_deferred_mode_error_names_the_phase() -> None:
    with pytest.raises(UnsupportedSyntaxModeError, match="P6"):
        tree("<config/>", mode=SyntaxMode.XML)


def test_xml_deferral_mentions_the_holdout_constraint() -> None:
    """The reason XML waits is corpus discipline, and the error says so."""
    with pytest.raises(UnsupportedSyntaxModeError, match="PAN-OS holdout"):
        tree("<config/>", mode=SyntaxMode.XML)


# ---------------------------------------------------------------------------
# Structural shapes
# ---------------------------------------------------------------------------


def test_nested_blocks() -> None:
    t = tree("a\n b\n  c\nd\n")
    by_text = {n.text: n for n in t.nodes.values()}

    assert by_text["b"].block_path == ("a",)
    assert by_text["c"].block_path == ("a", "b")
    assert by_text["d"].block_path == ()
    assert by_text["d"].depth == 0


def test_dedent_to_root() -> None:
    t = tree("interface Gi0/1\n description x\nhostname r1\n")
    by_text = {n.text: n for n in t.nodes.values()}
    assert by_text["hostname r1"].depth == 0
    assert by_text["hostname r1"].parent_id is None


def test_inconsistent_indent_widths() -> None:
    """Nesting follows relative indent, not a fixed step.

    `d` sits at indent 3. That is shallower than `c` at 6 but still deeper than
    `b` at 2, so it is `b`'s child rather than `a`'s — which is what a device
    means by it, and what an operator reading the file would conclude.
    """
    t = tree("a\n  b\n      c\n   d\n")
    by_text = {n.text: n for n in t.nodes.values()}
    assert by_text["b"].block_path == ("a",)
    assert by_text["c"].block_path == ("a", "b")
    assert by_text["d"].block_path == ("a", "b")


def test_dedent_past_a_level_closes_it() -> None:
    """Returning to an earlier indent closes everything deeper."""
    t = tree("a\n  b\n    c\n  d\n")
    by_text = {n.text: n for n in t.nodes.values()}
    assert by_text["c"].block_path == ("a", "b")
    assert by_text["d"].block_path == ("a",)


def test_tabs_are_indentation() -> None:
    source = "line vty 0 4\n\ttransport input ssh\n"
    t = tree(source)
    child = [n for n in t.nodes.values() if n.text == "transport input ssh"][0]
    assert child.block_path == ("line vty 0 4",)
    assert t.verify_lossless(source)


def test_deep_nesting() -> None:
    source = "".join(" " * i + f"level{i}\n" for i in range(12))
    t = tree(source)
    deepest = max(t.nodes.values(), key=lambda n: n.depth)
    assert deepest.depth == 11
    assert len(deepest.block_path) == 11
    assert t.verify_lossless(source)


def test_leading_indented_line_is_a_root() -> None:
    """A child with no parent above it still has to be somewhere."""
    t = tree("   orphan\nhostname r1\n")
    orphan = [n for n in t.nodes.values() if n.text == "orphan"][0]
    assert orphan.depth == 0
    assert orphan.parent_id is None


def test_blank_lines_are_unplaced() -> None:
    t = tree("a\n\n\nb\n")
    assert texts(t) == ["a", "b"]
    assert reasons(t) == [REASON_BLANK, REASON_BLANK]


def test_empty_file() -> None:
    t = tree("")
    assert t.node_count == 0
    assert t.source_line_count == 0
    assert t.reconstruct() == ""


# ---------------------------------------------------------------------------
# set_path mode
# ---------------------------------------------------------------------------


def test_set_path_is_flat() -> None:
    source = (
        "set system host-name srx-01\n"
        "set system services ssh protocol-version v2\n"
        "set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/30\n"
    )
    t = tree(source, mode=SyntaxMode.SET_PATH)

    assert t.node_count == 3
    assert all(n.depth == 0 and n.block_path == () for n in t.nodes.values())
    assert t.verify_lossless(source)


def test_set_path_preserves_line_numbers() -> None:
    t = tree("set a\n\nset b\n", mode=SyntaxMode.SET_PATH)
    assert [(n.line_number, n.text) for n in t.in_source_order()] == [(1, "set a"), (3, "set b")]


# ---------------------------------------------------------------------------
# Real corpus
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["rtr-core-01.cfg", "sw-access-02.cfg"])
def test_cisco_dev_files_round_trip(name: str) -> None:
    from pathlib import Path

    path = Path("corpus/cisco/dev") / name
    source = path.read_text(encoding="utf-8")
    t = tree(source, comment_prefixes=("!",), literal_blocks=(BANNER,))

    assert t.verify_lossless(source), f"{name} does not round-trip"
    accounted = {n.line_number for n in t.nodes.values()} | {u.line_number for u in t.unplaced}
    assert accounted == set(range(1, t.source_line_count + 1))


def test_juniper_dev_files_round_trip() -> None:
    from pathlib import Path

    for path in sorted(Path("corpus/juniper/dev").glob("*.conf")):
        source = path.read_text(encoding="utf-8")
        assert tree(source, mode=SyntaxMode.SET_PATH).verify_lossless(source), path.name
