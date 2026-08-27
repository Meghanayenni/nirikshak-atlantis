"""Residue nodes become the training queue — scrubbed, and only here.

`ParseResult.residue` is every node no pattern matched. Those lines are headed
for an embedding model at P10, so the text that travels with them is scrubbed
(decision D12). The configuration itself and every `Evidence` object are
untouched: this produces a *derived view*, and the original stays exactly as the
operator wrote it so a report can still quote it.

Line numbers and block paths survive the scrub unchanged. That is what keeps the
queue useful — a suggestion made about a scrubbed line still resolves to the real
source text, and an administrator confirming a mapping is confirming it against
something they can look at.

Comments, blank lines and literal-block bodies cannot appear here. They never
became nodes at P4, so a queue full of `!` and banner prose is impossible by
construction rather than by filtering.
"""

from __future__ import annotations

from api.models.config_tree import ConfigNode
from api.models.csm import UnknownLine
from api.security.scrub import scrub_for_inference


def to_unknown_lines(
    nodes: tuple[ConfigNode, ...],
    *,
    file_id: str,
) -> tuple[UnknownLine, ...]:
    """Convert residue nodes into the canonical model's unknown-line queue."""
    return tuple(_to_unknown_line(node, file_id=file_id) for node in nodes)


def _to_unknown_line(node: ConfigNode, *, file_id: str) -> UnknownLine:
    """One node, scrubbed, with its position preserved.

    `node.text` is used rather than `node.raw_line`: indentation is structure and
    is already carried by `block_path`, and the queue reads better without it.
    The raw line remains reachable through the tree and through evidence.
    """
    return UnknownLine(
        line_number=node.line_number,
        raw_line_scrubbed=scrub_for_inference(node.text),
        normalised_line="",  # token-shape signature is P10's clustering concern
        file_id=file_id,
        block_path=node.block_path,
    )
