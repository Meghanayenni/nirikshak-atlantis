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
`! model ISR4331` still yields a model: metadata legitimately lives in comments,
active security configuration never does.

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

IMPLEMENTED_MODES: frozenset[SyntaxMode] = frozenset({SyntaxMode.INDENT, SyntaxMode.SET_PATH})
"""Modes with real corpus files behind them.

`BRACE` and `JSON` have no corpus example at all. `XML` has only the held-out
vendor, so building it now would mean either testing against files we have
committed not to open, or building blind — see decision D8. Each unimplemented
mode raises; none returns an empty tree."""

DEFERRED_MODE_PHASE: dict[SyntaxMode, str] = {
    SyntaxMode.BRACE: "the phase whose corpus contains a brace-structured platform",
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
