"""Contracts for the parsing layer.

Parsing produces *facts*. Whether a fact is secure is decided at P6 by an engine
that cannot import this package — which is what makes DEVELOPER_GUIDE.md Rule 1
structural rather than aspirational.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic import Field as Constraint

from api.models.acl import ACL
from api.models.config_tree import ConfigNode, ConfigTree
from api.models.csm import Interface
from api.models.evidence import Evidence
from api.models.field import Field


class FieldMatch(BaseModel):
    """One pattern firing on one node.

    Kept as an intermediate rather than collapsed straight into a `Field`,
    because a field's outcome depends on *all* its matches: two matches agreeing
    is a value with two citations, two matches disagreeing is an abstention.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1)
    pattern_id: str = Constraint(min_length=1)
    raw_capture: str
    value: Any
    evidence: Evidence
    node_id: str = Constraint(min_length=1)


class ParseResult(BaseModel):
    """Everything parsing determined about one configuration file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_id: str = Constraint(min_length=1)
    file_path: str = Constraint(min_length=1)

    vendor: str | None = None
    os_family: str | None = None
    pack_version: str | None = None

    tree: ConfigTree
    fields: dict[str, Field[Any]] = Constraint(default_factory=dict)
    residue: tuple[ConfigNode, ...] = Constraint(
        default=(), description="Nodes no pattern matched — the P10 training queue"
    )
    acls: tuple[ACL, ...] = Constraint(
        default=(), description="Access lists read from the tree (P16)"
    )
    interfaces: tuple[Interface, ...] = Constraint(
        default=(), description="Interfaces read from the tree (P16)"
    )

    @property
    def determinable(self) -> dict[str, Field[Any]]:
        return {k: v for k, v in self.fields.items() if v.is_determinable}

    @property
    def abstained(self) -> dict[str, Field[Any]]:
        return {k: v for k, v in self.fields.items() if not v.is_determinable}

    @property
    def residue_count(self) -> int:
        return len(self.residue)

    def coverage(self) -> float:
        """Fraction of declared fields that produced a value."""
        if not self.fields:
            return 0.0
        return len(self.determinable) / len(self.fields)

    def summary(self) -> str:
        return (
            f"{len(self.determinable)}/{len(self.fields)} fields determined, "
            f"{self.residue_count} residue line(s)"
        )
