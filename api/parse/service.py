"""Parsing orchestration.

Text plus a vendor pack becomes a `ParseResult`: a structural tree, canonical
fields with evidence, and the residue nothing recognised.

What this deliberately does not do is build a Canonical Security Model. That is
P5's job, because it needs the per-OS capability and default model to decide
what an absent directive means — and deciding that here would smuggle a
judgement into the parser.
"""

from __future__ import annotations

from api.models.config_tree import ConfigNode, ConfigTree
from api.models.enums import SourceType, SyntaxMode
from api.models.pack import VendorPack
from api.models.parsing import ParseResult
from api.parse import fields as field_builder
from api.parse.block_parser import build_tree
from api.parse.pack_engine import apply_pack

SYNTAX_MODE_BY_OS: dict[str, SyntaxMode] = {
    "ios": SyntaxMode.INDENT,
    "eos": SyntaxMode.INDENT,
    "nxos": SyntaxMode.INDENT,
    "junos": SyntaxMode.SET_PATH,
}
"""Which structural shape a platform uses.

Data-driven would be better and is a natural pack field later; at P4 the corpus
holds four platforms and this map is honest about being a stopgap rather than
pretending otherwise."""


def syntax_mode_for(pack: VendorPack) -> SyntaxMode:
    return SYNTAX_MODE_BY_OS.get(pack.os_family, SyntaxMode.INDENT)


def parse_configuration(
    text: str,
    pack: VendorPack,
    *,
    file_id: str,
    file_path: str,
    source_type: SourceType = SourceType.CLI,
    mode: SyntaxMode | None = None,
) -> ParseResult:
    """Parse one configuration with one pack.

    Raises for an unimplemented syntax mode or match primitive rather than
    returning a thin result: a partially parsed configuration produces fields
    that look complete and are not.
    """
    tree = build_tree(
        text,
        file_id=file_id,
        file_path=file_path,
        mode=mode or syntax_mode_for(pack),
        comment_prefixes=pack.comment_prefixes,
        literal_blocks=pack.literal_blocks,
    )

    by_field, matched_nodes = apply_pack(pack, tree, source_type=source_type)
    parsed = field_builder.build_fields(by_field, pack)
    residue = collect_residue(tree, matched_nodes)

    return ParseResult(
        file_id=file_id,
        file_path=file_path,
        vendor=pack.vendor,
        os_family=pack.os_family,
        pack_version=pack.pack_version,
        tree=tree,
        fields=parsed,
        residue=residue,
    )


def collect_residue(tree: ConfigTree, matched_nodes: set[str]) -> tuple[ConfigNode, ...]:
    """Nodes no pattern matched — what the training loop consumes at P10.

    Comments, blank lines and literal-block bodies are absent by construction:
    they never became nodes, so they cannot arrive here. That matters, because a
    residue queue full of `!` and banner prose would bury the lines an
    administrator actually needs to look at.
    """
    return tuple(node for node in tree.in_source_order() if node.node_id not in matched_nodes)
