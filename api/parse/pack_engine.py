"""Applying a vendor pack's patterns to a ConfigTree.

Two mechanics decide correctness here.

**Patterns match `node.text`, not `raw_line`.** A pattern for an indented
directive is written `^exec-timeout (\\d+) (\\d+)$`, never `^ exec-timeout…`.
Indentation is structure, already captured by `depth` and `block_path`; making
every pattern re-encode it would be brittle and unreadable. Evidence still cites
`raw_line` verbatim, so an operator sees the line exactly as they wrote it.

**Scopes are anchored full-header matches** (decision D9). `^line vty 0 4$` and
`^line vty 0 15$` are different scopes; matching them both takes a deliberate
`^line vty \\d+ \\d+$`. Unanchored substring matching is how a console timeout
ends up reported as a management idle timeout.
"""

from __future__ import annotations

import re

from api.models.config_tree import ConfigNode, ConfigTree
from api.models.enums import MatchType, SourceType
from api.models.pack import PatternDef, VendorPack
from api.models.parsing import FieldMatch
from api.parse.casts import cast_value
from api.parse.errors import CastError, ParseError

IMPLEMENTED_PRIMITIVES: frozenset[MatchType] = frozenset({MatchType.REGEX, MatchType.BLOCK})
"""Primitives with a pack behind them.

`textfsm` targets show-command output rather than running-configs (decision R4),
and nothing in the corpus is that shape. `xpath` and `jsonpath` have no corpus
document to run against. Each arrives with the phase whose pack needs it; until
then the adapter raises rather than silently matching nothing."""

DEFERRED_PRIMITIVE_REASON: dict[MatchType, str] = {
    MatchType.TEXTFSM: (
        "TextFSM targets show-command output; the corpus holds only running-configs (R4)"
    ),
    MatchType.XPATH: "no XML document outside the PAN-OS holdout (D8)",
    MatchType.JSONPATH: "no JSON document in the corpus",
}

GROUP_REF = re.compile(r"^\$(\d+)$")


class UnsupportedPrimitiveError(ParseError):
    """A match primitive exists in the contract but is not implemented yet."""

    def __init__(self, primitive: MatchType) -> None:
        self.primitive = primitive
        reason = DEFERRED_PRIMITIVE_REASON.get(primitive, "not implemented")
        super().__init__(
            f"match primitive {primitive!s} is not implemented: {reason}. The engine "
            "refuses rather than quietly matching nothing, which would look "
            "identical to a configuration that simply lacks the directive."
        )


def _resolve_capture(spec_value: str, found: re.Match[str] | None, node: ConfigNode) -> str:
    """Resolve a capture expression to the text that becomes the value.

    A value beginning with `$` is a group reference; anything else is a literal.
    Literals are what express negation forms — `no ip http server` has nothing to
    capture, so the pattern declares the literal `false`.
    """
    if found is not None:
        parts = spec_value.split()
        resolved: list[str] = []
        for part in parts:
            ref = GROUP_REF.match(part)
            if ref is None:
                resolved.append(part)
                continue
            index = int(ref.group(1))
            if index > (found.re.groups or 0):
                raise ParseError(
                    f"capture references ${index} but the pattern has {found.re.groups} group(s)"
                )
            captured = found.group(index)
            resolved.append(captured if captured is not None else "")
        return " ".join(resolved)
    return spec_value


def _apply_regex(
    pattern: PatternDef, node: ConfigNode, file_path: str, source_type: SourceType
) -> FieldMatch | None:
    found = re.match(pattern.match.pattern, node.text)
    if found is None:
        return None

    raw = _resolve_capture(pattern.capture.value, found if found.re.groups else None, node)
    if pattern.capture.map:
        raw = pattern.capture.map.get(raw, raw)

    try:
        value = cast_value(raw, pattern.capture.cast)
    except CastError:
        # A malformed value yields no fact. Reporting a plausible substitute
        # would be worse than the gap: the operator would have no way to know.
        return None

    return FieldMatch(
        field=pattern.field,
        pattern_id=pattern.id,
        raw_capture=raw,
        value=value,
        evidence=node.to_evidence(file_path, source_type),
        node_id=node.node_id,
    )


def _apply_block(
    pattern: PatternDef, node: ConfigNode, file_path: str, source_type: SourceType
) -> FieldMatch | None:
    """Match on a node's position rather than its content.

    The scope has already selected the node, so reaching here means the block
    exists. The declared literal value is the fact.
    """
    raw = _resolve_capture(pattern.capture.value, None, node)
    try:
        value = cast_value(raw, pattern.capture.cast)
    except CastError:
        return None

    return FieldMatch(
        field=pattern.field,
        pattern_id=pattern.id,
        raw_capture=raw,
        value=value,
        evidence=node.to_evidence(file_path, source_type),
        node_id=node.node_id,
    )


_ADAPTERS = {
    MatchType.REGEX: _apply_regex,
    MatchType.BLOCK: _apply_block,
}


def apply_pattern(
    pattern: PatternDef, tree: ConfigTree, *, source_type: SourceType = SourceType.CLI
) -> list[FieldMatch]:
    """Every match this pattern produces, in source order."""
    if pattern.match.type not in IMPLEMENTED_PRIMITIVES:
        raise UnsupportedPrimitiveError(pattern.match.type)

    adapter = _ADAPTERS[pattern.match.type]
    matches: list[FieldMatch] = []

    for node in tree.in_source_order():
        if not pattern.scope.matches(node.block_path):
            continue
        if not node.raw_line.strip():
            continue  # a blank node cannot be evidence; the contract would raise
        found = adapter(pattern, node, tree.file_path, source_type)
        if found is not None:
            matches.append(found)

    return matches


def apply_pack(
    pack: VendorPack, tree: ConfigTree, *, source_type: SourceType = SourceType.CLI
) -> tuple[dict[str, list[FieldMatch]], set[str]]:
    """Run every pattern. Returns matches per field, and the ids of matched nodes.

    The matched-node set is what residue is computed from: a node no pattern
    touched is something the packs cannot yet read, which is exactly the queue
    the training loop consumes at P10.
    """
    by_field: dict[str, list[FieldMatch]] = {}
    matched_nodes: set[str] = set()

    for pattern in pack.patterns:
        for match in apply_pattern(pattern, tree, source_type=source_type):
            by_field.setdefault(match.field, []).append(match)
            matched_nodes.add(match.node_id)

    return by_field, matched_nodes
