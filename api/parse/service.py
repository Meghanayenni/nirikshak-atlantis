"""Parsing orchestration.

Text plus a vendor pack becomes a `ParseResult`: a structural tree, canonical
fields with evidence, and the residue nothing recognised.

What this deliberately does not do is build a Canonical Security Model. That is
P5's job, because it needs the per-OS capability and default model to decide
what an absent directive means — and deciding that here would smuggle a
judgement into the parser.
"""

from __future__ import annotations

import re

from api.models.config_tree import ConfigNode, ConfigTree
from api.models.enums import SourceType, SyntaxMode
from api.models.pack import VendorPack
from api.models.parsing import ParseResult
from api.parse import fields as field_builder
from api.parse import structures
from api.parse.block_parser import build_tree
from api.parse.pack_engine import apply_pack

SYNTAX_MODE_BY_OS: dict[str, SyntaxMode] = {
    "ios": SyntaxMode.INDENT,
    "eos": SyntaxMode.INDENT,
    "nxos": SyntaxMode.INDENT,
    "junos": SyntaxMode.SET_PATH,
}
"""Which structural shape a platform uses **by default**.

Data-driven would be better and is a natural pack field later; at P4 the corpus
held four platforms and this map was honest about being a stopgap rather than
pretending otherwise. P18 found its real limit, below."""

BRACE_OPENER = re.compile(r"^\S.*\{\s*$", re.MULTILINE)
"""A line beginning in column zero and ending in an opening brace."""

ALTERNATE_SURFACES: dict[str, SyntaxMode] = {"junos": SyntaxMode.BRACE}
"""Platforms that ship more than one surface form, and the non-default one.

**The surface is a property of the file, not of the platform.** JunOS exports
the same configuration as `set` commands or as a brace hierarchy, and a device
can be captured either way on the same afternoon. Keying the mode to
`os_family` alone meant `corpus/juniper/dev/core-rtr-01.conf` — legitimate
JunOS, registered since P15 — would have been parsed as flat `set` paths and
read as 165 unrecognised lines even after detection identified it correctly.
"""


def syntax_mode_for(pack: VendorPack, text: str | None = None) -> SyntaxMode:
    """The mode for this pack, narrowed by the file where the platform ships two.

    The discriminator is deliberately dull: a `set`-form JunOS file contains no
    opening brace at all — verified across all four in the corpus, which have
    zero between them — so one at column zero is unambiguous. No counting, no
    ratio, no threshold to tune.
    """
    default = SYNTAX_MODE_BY_OS.get(pack.os_family, SyntaxMode.INDENT)
    alternate = ALTERNATE_SURFACES.get(pack.os_family)
    if alternate is None or text is None:
        return default
    return alternate if BRACE_OPENER.search(text) else default


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
        mode=mode or syntax_mode_for(pack, text),
        comment_prefixes=pack.comment_prefixes,
        literal_blocks=pack.literal_blocks,
    )

    by_field, matched_nodes = apply_pack(pack, tree, source_type=source_type)
    parsed = field_builder.build_fields(by_field, pack)

    # Structure extraction (P16). Interfaces first: an access list records where
    # it is bound, and that binding is written inside the interface block.
    interfaces = structures.extract_interfaces(tree, pack, source_type)
    acls, acl_failures = structures.extract_acls(tree, pack, interfaces, source_type)

    # A line these read is recognised, so it must not also reach the training
    # queue — an administrator asked to classify a line the parser already
    # understood is being wasted.
    residue = collect_residue(tree, matched_nodes | structures.matched_node_ids(tree, pack))

    return ParseResult(
        file_id=file_id,
        file_path=file_path,
        vendor=pack.vendor,
        os_family=pack.os_family,
        pack_version=pack.pack_version,
        tree=tree,
        fields=parsed,
        residue=residue,
        acls=acls,
        acl_failures=acl_failures,
        interfaces=interfaces,
    )


def collect_residue(tree: ConfigTree, matched_nodes: set[str]) -> tuple[ConfigNode, ...]:
    """Nodes no pattern matched — what the training loop consumes at P10.

    Comments, blank lines and literal-block bodies are absent by construction:
    they never became nodes, so they cannot arrive here. That matters, because a
    residue queue full of `!` and banner prose would bury the lines an
    administrator actually needs to look at.
    """
    return tuple(node for node in tree.in_source_order() if node.node_id not in matched_nodes)
