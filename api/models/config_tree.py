"""ConfigTree / ConfigNode — structure before patterns (decision R4).

A configuration file is not a list of lines. `exec-timeout 10 0` means one thing
under `line vty 0 4` and something else under `line con 0`, so the parser must
preserve the enclosing chain before any pattern is allowed to run.

Four invariants, each enforced here or tested directly:

1. **Lossless**  — reconstructing from the tree reproduces the source exactly.
2. **Evidence**  — every node yields a complete Evidence object with no lookup.
3. **Total**     — every source line is a node or an unplaced line; never dropped.
4. **Deterministic** — same bytes in, same tree out.

Invariant 1 does more work than it looks like it does. If the tree round-trips
to the original bytes, then every line_number and raw_line in every piece of
evidence in the whole system is provably real source text. One property test at
the bottom of the stack underwrites the Rule 2 guarantee at the top.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import SourceType, SyntaxMode
from api.models.evidence import Evidence, sha256_hex


class ConfigNode(BaseModel):
    """One structurally meaningful line, with its position in the hierarchy."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str = Constraint(min_length=1)
    file_id: str = Constraint(min_length=1)

    line_number: int = Constraint(ge=1, description="1-based, exact — never derived")
    raw_line: str = Constraint(description="Verbatim, including original indentation")
    text: str = Constraint(description="Trimmed command text")

    depth: int = Constraint(ge=0)
    parent_id: str | None = None
    children: tuple[str, ...] = ()
    block_path: tuple[str, ...] = Constraint(
        default=(), description="Enclosing chain, outermost first"
    )

    syntax_mode: SyntaxMode

    @model_validator(mode="after")
    def _check_consistency(self) -> ConfigNode:
        if self.parent_id == self.node_id:
            raise ValueError(f"node {self.node_id!r} is its own parent")
        if self.parent_id is None and self.depth != 0:
            raise ValueError(
                f"node {self.node_id!r} has no parent but depth {self.depth}; "
                "root nodes must be at depth 0"
            )
        if self.parent_id is not None and self.depth == 0:
            raise ValueError(f"node {self.node_id!r} has parent {self.parent_id!r} but depth 0")
        if len(self.block_path) != self.depth:
            raise ValueError(
                f"node {self.node_id!r}: block_path has {len(self.block_path)} "
                f"entries but depth is {self.depth} — the enclosing chain must "
                "match the nesting level exactly"
            )
        return self

    # -- evidence ----------------------------------------------------------

    def to_evidence(self, file_path: str, source_type: SourceType = SourceType.CLI) -> Evidence:
        """Produce an Evidence object directly, with no further lookup.

        Invariant 2. Raises if the node carries no citable text — a blank line
        cannot support a security claim.
        """
        if not self.raw_line.strip():
            raise ValueError(
                f"node {self.node_id!r} at line {self.line_number} is blank and "
                "cannot be used as evidence"
            )
        return Evidence(
            file_id=self.file_id,
            file_path=file_path,
            line_start=self.line_number,
            line_end=self.line_number,
            raw_line=self.raw_line,
            line_sha256=sha256_hex(self.raw_line),
            source_type=source_type,
            block_path=self.block_path,
        )


class UnplacedLine(BaseModel):
    """A source line the parser could not attach to the hierarchy.

    Retained verbatim rather than discarded, so invariants 1 and 3 hold even
    when the parser meets something it does not understand. Silent loss is the
    failure mode this type exists to make impossible.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    line_number: int = Constraint(ge=1)
    raw_line: str
    reason: str = Constraint(default="unrecognised structure", min_length=1)


class ConfigTree(BaseModel):
    """The structural parse of one configuration file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_id: str = Constraint(min_length=1)
    file_path: str = Constraint(min_length=1)
    syntax_mode: SyntaxMode

    roots: tuple[str, ...] = ()
    nodes: dict[str, ConfigNode] = Constraint(default_factory=dict)
    unplaced: tuple[UnplacedLine, ...] = ()

    source_line_count: int = Constraint(ge=0)

    # -- structural validation --------------------------------------------

    @model_validator(mode="after")
    def _check_structure(self) -> ConfigTree:
        nodes = self.nodes

        for node_id, node in nodes.items():
            if node.node_id != node_id:
                raise ValueError(f"nodes key {node_id!r} disagrees with node_id {node.node_id!r}")
            if node.parent_id is not None and node.parent_id not in nodes:
                raise ValueError(f"node {node_id!r} references missing parent {node.parent_id!r}")
            for child in node.children:
                if child not in nodes:
                    raise ValueError(f"node {node_id!r} references missing child {child!r}")
                if nodes[child].parent_id != node_id:
                    raise ValueError(
                        f"node {node_id!r} claims child {child!r}, but that node's "
                        f"parent is {nodes[child].parent_id!r}"
                    )

        for root in self.roots:
            if root not in nodes:
                raise ValueError(f"roots references missing node {root!r}")
            if nodes[root].parent_id is not None:
                raise ValueError(f"root {root!r} has a parent")

        self._check_totality()
        return self

    def _check_totality(self) -> None:
        """Invariant 3 — every source line is accounted for exactly once."""
        node_lines = [n.line_number for n in self.nodes.values()]
        unplaced_lines = [u.line_number for u in self.unplaced]
        all_lines = node_lines + unplaced_lines

        if len(all_lines) != len(set(all_lines)):
            seen: set[int] = set()
            dupes = sorted({n for n in all_lines if n in seen or seen.add(n)})  # type: ignore[func-returns-value]
            raise ValueError(f"duplicate line numbers in tree: {dupes}")

        if len(all_lines) != self.source_line_count:
            raise ValueError(
                f"tree accounts for {len(all_lines)} lines but the source has "
                f"{self.source_line_count} — every line must be a node or "
                "unplaced, never dropped"
            )

        if all_lines:
            expected = set(range(1, self.source_line_count + 1))
            missing = sorted(expected - set(all_lines))
            if missing:
                raise ValueError(f"source lines absent from tree: {missing[:20]}")

    # -- invariant 1: losslessness ----------------------------------------

    def reconstruct(self) -> str:
        """Rebuild the source text from the tree, in line order.

        Line endings are normalised to `\\n`; comparison against an original
        should normalise the original the same way.
        """
        by_line: dict[int, str] = {n.line_number: n.raw_line for n in self.nodes.values()}
        by_line.update({u.line_number: u.raw_line for u in self.unplaced})
        return "\n".join(by_line[i] for i in sorted(by_line))

    def verify_lossless(self, original: str) -> bool:
        """Invariant 1 — does the tree round-trip to the original text?"""
        normalised = original.replace("\r\n", "\n").replace("\r", "\n")
        if normalised.endswith("\n"):
            normalised = normalised[:-1]
        return self.reconstruct() == normalised

    # -- traversal ---------------------------------------------------------

    def in_source_order(self) -> list[ConfigNode]:
        return sorted(self.nodes.values(), key=lambda n: n.line_number)

    def children_of(self, node_id: str) -> list[ConfigNode]:
        return [self.nodes[c] for c in self.nodes[node_id].children]

    def find_by_block(self, block_path: tuple[str, ...]) -> list[ConfigNode]:
        """Every node whose enclosing chain starts with `block_path`."""
        return [n for n in self.in_source_order() if n.block_path[: len(block_path)] == block_path]

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def unplaced_count(self) -> int:
        return len(self.unplaced)
