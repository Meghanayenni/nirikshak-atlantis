"""Structural parsing — configuration text to a ConfigTree (decision R4).

This module knows nothing about what any command means. It knows how a platform
expresses nesting, which lines are commands, and which are not. Meaning arrives
later, from a vendor pack, applied to the structure built here.

The four invariants the P1 contract requires, and which its conformance suite
checks against this implementation:

  1. Lossless   — reconstructing reproduces the source exactly
  2. Evidence   — every node yields a complete Evidence object
  3. Total      — every line is a node or an UnplacedLine; never dropped
  4. Deterministic — same bytes in, same tree out

Three kinds of line are deliberately **not** nodes:

**Comments.** A commented-out directive must never produce a PRESENT field. If
`! ip ssh version 1` were a node, a pattern would match it and NIRIKSHAK would
report a fact that is not in effect — with a citation, which makes it worse.
Identity extraction is unaffected because it runs over raw lines, which is how
`! device: sw-leaf-01 (DCS-7050SX3-48YC8, EOS-4.29.2F)` still yields a model and
an OS version: metadata legitimately lives in comments, active security
configuration never does.

The asymmetry holds only for lines the *platform* writes. A pack pointing it at
a comment a human typed gets the worst of both — see ADR 0037, which removed
one such pattern.

**Blank lines.** No command, and they would otherwise flood the training queue.

**Literal block bodies.** Banner text, certificates, keys — content, not
commands. Same reasoning as comments, and the same consequence if ignored: a
banner reading "ip ssh version 1 is prohibited" would otherwise become a fact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from api.ingest.lines import split_lines
from api.models.config_tree import ConfigNode, ConfigTree, UnplacedLine
from api.models.enums import SyntaxMode
from api.models.pack import LiteralBlock
from api.parse.errors import UnsupportedSyntaxModeError, UnterminatedLiteralBlockError

IMPLEMENTED_MODES: frozenset[SyntaxMode] = frozenset(
    {SyntaxMode.INDENT, SyntaxMode.SET_PATH, SyntaxMode.BRACE}
)
"""Modes with real corpus files behind them.

`BRACE` was deferred "to the phase whose corpus contains a brace-structured
platform". `corpus/juniper/dev/core-rtr-01.conf` has been that file since P15,
and it was implemented at P18 (ADR 0043) once it became the thing standing
between a registered corpus file and any part of the pipeline.

`JSON` still has no corpus example at all. `XML` has only the held-out vendor,
so building it now would mean either testing against files we have committed not
to open, or building blind — see decision D8. Each unimplemented mode raises;
none returns an empty tree."""

DEFERRED_MODE_PHASE: dict[SyntaxMode, str] = {
    SyntaxMode.XML: "P6, and only once an XML sample independent of the PAN-OS holdout exists",
    SyntaxMode.JSON: "the phase whose corpus contains a JSON export",
}

REASON_BLANK = "blank line"
REASON_COMMENT = "comment"
REASON_LITERAL = "literal block body"


@dataclass(frozen=True)
class _OpenLiteral:
    name: str
    terminator: str
    opened_at: int


def _literal_opener(line: str, blocks: tuple[LiteralBlock, ...]) -> _OpenLiteral | None:
    """Does this line open a literal block, and what closes it?"""
    for block in blocks:
        found = re.match(block.open, line)
        if not found:
            continue
        if block.terminator_group is not None:
            terminator = found.group(block.terminator_group)
        else:
            terminator = block.terminator or ""
        return _OpenLiteral(name=block.name, terminator=terminator, opened_at=0)
    return None


def _is_comment(line: str, prefixes: tuple[str, ...]) -> bool:
    stripped = line.lstrip()
    return any(stripped.startswith(p) for p in prefixes if p)


def build_tree(
    text: str,
    *,
    file_id: str,
    file_path: str,
    mode: SyntaxMode = SyntaxMode.INDENT,
    comment_prefixes: tuple[str, ...] = (),
    literal_blocks: tuple[LiteralBlock, ...] = (),
) -> ConfigTree:
    """Build a ConfigTree. Raises for any mode not yet implemented."""
    if mode not in IMPLEMENTED_MODES:
        raise UnsupportedSyntaxModeError(mode, DEFERRED_MODE_PHASE.get(mode, "a later phase"))

    lines = split_lines(text)

    if mode is SyntaxMode.BRACE:
        return _build_braced(
            lines,
            file_id=file_id,
            file_path=file_path,
            comment_prefixes=comment_prefixes,
        )

    if mode is SyntaxMode.SET_PATH:
        return _build_flat(
            lines,
            file_id=file_id,
            file_path=file_path,
            mode=mode,
            comment_prefixes=comment_prefixes,
        )

    return _build_indented(
        lines,
        file_id=file_id,
        file_path=file_path,
        comment_prefixes=comment_prefixes,
        literal_blocks=literal_blocks,
    )


def _build_indented(
    lines: list[str],
    *,
    file_id: str,
    file_path: str,
    comment_prefixes: tuple[str, ...],
    literal_blocks: tuple[LiteralBlock, ...],
) -> ConfigTree:
    """Significant leading whitespace opens a block; lesser indent closes it."""
    nodes: dict[str, ConfigNode] = {}
    children: dict[str, list[str]] = {}
    unplaced: list[UnplacedLine] = []
    roots: list[str] = []
    stack: list[tuple[int, str]] = []

    open_literal: _OpenLiteral | None = None

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()

        # Inside a literal block: everything is body until the terminator, and
        # the terminator itself belongs to the block rather than to the tree.
        if open_literal is not None:
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_LITERAL))
            if stripped == open_literal.terminator:
                open_literal = None
            continue

        if not stripped:
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_BLANK))
            continue

        if _is_comment(raw, comment_prefixes):
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_COMMENT))
            continue

        indent = len(raw) - len(raw.lstrip())
        while stack and stack[-1][0] >= indent:
            stack.pop()

        parent_id = stack[-1][1] if stack else None
        node_id = f"n{number}"
        block_path = tuple(nodes[pid].text for _, pid in stack)

        nodes[node_id] = ConfigNode(
            node_id=node_id,
            file_id=file_id,
            line_number=number,
            raw_line=raw,
            text=stripped,
            depth=len(stack),
            parent_id=parent_id,
            children=(),
            block_path=block_path,
            syntax_mode=SyntaxMode.INDENT,
        )
        children.setdefault(node_id, [])
        if parent_id is None:
            roots.append(node_id)
        else:
            children.setdefault(parent_id, []).append(node_id)
        stack.append((indent, node_id))

        # The opener stays a node — `banner_present` cites it — while everything
        # after it becomes body until the terminator.
        opener = _literal_opener(stripped, literal_blocks)
        if opener is not None:
            open_literal = _OpenLiteral(
                name=opener.name, terminator=opener.terminator, opened_at=number
            )

    if open_literal is not None:
        raise UnterminatedLiteralBlockError(
            open_literal.name, open_literal.opened_at, open_literal.terminator
        )

    return _assemble(
        nodes, children, roots, unplaced, file_id, file_path, SyntaxMode.INDENT, len(lines)
    )


C_COMMENT_OPEN = "/*"
C_COMMENT_CLOSE = "*/"
REASON_C_COMMENT = "block comment"
REASON_TERMINATOR = "block terminator"
REASON_UNMATCHED_BRACE = "unmatched closing brace"


def _build_braced(
    lines: list[str],
    *,
    file_id: str,
    file_path: str,
    comment_prefixes: tuple[str, ...],
) -> ConfigTree:
    """A line ending `{` opens a block; a line that is `}` closes one.

    JunOS in its hierarchical form, and the second of the two surfaces that
    platform ships. The same configuration written with `set` commands parses
    through `_build_flat`; which one a file uses is a property of how it was
    exported, not of the platform, so the mode is chosen from the text (see
    `api/parse/service.py`) rather than from the vendor pack.

    Three shapes, and each is read exactly as written:

        system {              -> a block node, text `system`
            host-name r1;     -> a leaf node, text `host-name r1`
        }                     -> closes, and is not a node

    **The braces and the terminating semicolon are stripped from `text` and kept
    in `raw_line`.** A pattern author writes `^host-name (\\S+)$` and matches
    what they see in the file; requiring them to write `;?$` on every pattern
    would move punctuation into every regex in the pack, and the first one
    written without it would fail silently.

    `/* … */` block comments are removed as comment lines rather than nodes, on
    the same rule as `#`: a commented-out directive must never produce a PRESENT
    field. JunOS writes its file header that way, and `## SECRET-DATA` markers
    are trailing annotations on otherwise ordinary statements, so those are
    stripped from `text` and preserved in `raw_line`.

    A `}` with no open block does not raise. The tree is built from an operator's
    file, and refusing to read the rest of a configuration because one brace is
    unbalanced would turn a cosmetic defect into a device nobody can audit; the
    line is recorded as unplaced instead, where it is visible.
    """
    nodes: dict[str, ConfigNode] = {}
    children: dict[str, list[str]] = {}
    unplaced: list[UnplacedLine] = []
    roots: list[str] = []
    stack: list[str] = []

    in_block_comment = False

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()

        if in_block_comment:
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_C_COMMENT))
            if C_COMMENT_CLOSE in stripped:
                in_block_comment = False
            continue

        if not stripped:
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_BLANK))
            continue

        if stripped.startswith(C_COMMENT_OPEN):
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_C_COMMENT))
            if C_COMMENT_CLOSE not in stripped[len(C_COMMENT_OPEN) :]:
                in_block_comment = True
            continue

        if _is_comment(raw, comment_prefixes):
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_COMMENT))
            continue

        if stripped in ("}", "};"):
            # Recorded either way: `ConfigTree` requires every source line to be
            # a node or an unplaced line, never dropped, so that "the parser read
            # your whole file" is a checkable claim rather than an assurance.
            reason = REASON_TERMINATOR if stack else REASON_UNMATCHED_BRACE
            if stack:
                stack.pop()
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=reason))
            continue

        text = _brace_text(stripped)
        if not text:
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_BLANK))
            continue

        parent_id = stack[-1] if stack else None
        node_id = f"n{number}"

        nodes[node_id] = ConfigNode(
            node_id=node_id,
            file_id=file_id,
            line_number=number,
            raw_line=raw,
            text=text,
            depth=len(stack),
            parent_id=parent_id,
            children=(),
            block_path=tuple(nodes[pid].text for pid in stack),
            syntax_mode=SyntaxMode.BRACE,
        )
        children.setdefault(node_id, [])
        if parent_id is None:
            roots.append(node_id)
        else:
            children.setdefault(parent_id, []).append(node_id)

        if stripped.endswith("{"):
            stack.append(node_id)

    return _assemble(
        nodes, children, roots, unplaced, file_id, file_path, SyntaxMode.BRACE, len(lines)
    )


def _brace_text(stripped: str) -> str:
    """The statement, without its structural punctuation or trailing annotation.

    `host-name r1;` -> `host-name r1`
    `system {`      -> `system`
    `encrypted-password "…"; ## SECRET-DATA` -> `encrypted-password "…"`

    The annotation is dropped rather than kept because it is JunOS metadata
    about the line, not part of the statement, and leaving it on would make
    every pattern matching such a line carry it too.
    """
    text = stripped
    marker = text.find("##")
    if marker != -1:
        text = text[:marker].rstrip()
    if text.endswith("{"):
        text = text[:-1].rstrip()
    elif text.endswith(";"):
        text = text[:-1].rstrip()
    return text


def _build_flat(
    lines: list[str],
    *,
    file_id: str,
    file_path: str,
    mode: SyntaxMode,
    comment_prefixes: tuple[str, ...],
) -> ConfigTree:
    """Every line is a complete statement at depth 0.

    Juniper set-style configuration carries its hierarchy inside each line's own
    token path rather than in indentation, so patterns address that path directly
    and `block_path` stays empty.
    """
    nodes: dict[str, ConfigNode] = {}
    unplaced: list[UnplacedLine] = []
    roots: list[str] = []

    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()

        if not stripped:
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_BLANK))
            continue
        if _is_comment(raw, comment_prefixes):
            unplaced.append(UnplacedLine(line_number=number, raw_line=raw, reason=REASON_COMMENT))
            continue

        node_id = f"n{number}"
        nodes[node_id] = ConfigNode(
            node_id=node_id,
            file_id=file_id,
            line_number=number,
            raw_line=raw,
            text=stripped,
            depth=0,
            parent_id=None,
            children=(),
            block_path=(),
            syntax_mode=mode,
        )
        roots.append(node_id)

    return _assemble(nodes, {}, roots, unplaced, file_id, file_path, mode, len(lines))


def _assemble(
    nodes: dict[str, ConfigNode],
    children: dict[str, list[str]],
    roots: list[str],
    unplaced: list[UnplacedLine],
    file_id: str,
    file_path: str,
    mode: SyntaxMode,
    line_count: int,
) -> ConfigTree:
    """Attach children and construct the tree, letting the contract validate it."""
    if children:
        nodes = {
            node_id: node.model_copy(update={"children": tuple(children.get(node_id, []))})
            for node_id, node in nodes.items()
        }

    return ConfigTree(
        file_id=file_id,
        file_path=file_path,
        syntax_mode=mode,
        roots=tuple(roots),
        nodes=nodes,
        unplaced=tuple(unplaced),
        source_line_count=line_count,
    )
