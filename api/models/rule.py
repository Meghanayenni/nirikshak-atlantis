"""Compliance rules — declarative, framework-neutral, cross-mapped.

One canonical check owns the logic once; each framework contributes only a
mapping from that check to its own control identifiers. Written the other way
round, the same logic would exist four times and drift four ways.

Decision R16 shapes this contract: a rule carries control **identifiers**, our
own `rationale`, and nothing else. `extra="forbid"` means a field such as
`control_text` is rejected at load rather than merely discouraged, which makes
the content policy structural rather than a convention someone has to remember.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import (
    AbsenceAction,
    ConditionOp,
    Framework,
    MappingProvenance,
    Severity,
)

MAX_RATIONALE_CHARS = 1200
"""Generous for explaining why a check exists; tight enough to catch pasting."""

VALUELESS_OPS = frozenset({ConditionOp.IS_TRUE, ConditionOp.IS_FALSE, ConditionOp.NON_EMPTY})


class Condition(BaseModel):
    """A single comparison against a canonical field value.

    A closed operator set rather than an expression language, so a rule can
    never become a place where vendor logic or a model call reappears.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    op: ConditionOp
    value: Any = None

    @model_validator(mode="after")
    def _check(self) -> Condition:
        if self.op in VALUELESS_OPS:
            if self.value is not None:
                raise ValueError(f"operator {self.op} takes no value")
        elif self.value is None:
            raise ValueError(f"operator {self.op} requires a value to compare against")

        if self.op in (ConditionOp.IN, ConditionOp.NOT_IN) and not isinstance(
            self.value, list | tuple | set
        ):
            raise ValueError(f"operator {self.op} requires a collection")
        return self


class CheckSpec(BaseModel):
    """Which canonical field is examined, and how."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1)
    condition: Condition


class AbsencePolicy(BaseModel):
    """What to conclude when the field is not PRESENT.

    Most non-compliance is an absent line rather than a present one, and a
    hardening directive may be missing because it is the platform default or
    because someone removed it — opposite conclusions from identical evidence.
    The default for undocumented capability is UNKNOWN, and it is deliberately
    not overridable to PASS or FAIL by accident: abstention is the safe answer.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    on_absent_default: AbsenceAction = AbsenceAction.EVALUATE
    on_absent_unsupported: AbsenceAction = AbsenceAction.NOT_APPLICABLE
    on_capability_unknown: AbsenceAction = AbsenceAction.UNKNOWN


class AppliesTo(BaseModel):
    """Platform selector. Empty or '*' means every platform."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vendor: tuple[str, ...] = ("*",)
    os_family: tuple[str, ...] = ("*",)

    def matches(self, vendor: str | None, os_family: str | None) -> bool:
        def ok(patterns: tuple[str, ...], value: str | None) -> bool:
            if "*" in patterns:
                return True
            return value is not None and value in patterns

        return ok(self.vendor, vendor) and ok(self.os_family, os_family)


class FrameworkRef(BaseModel):
    """One framework's identifier for this check.

    `mapping_provenance` records whether the mapping follows a published
    crosswalk or is asserted by this project. Claiming less, verifiably, is
    worth more in an audit tool than claiming more (R16).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    framework: Framework
    control_id: str = Constraint(min_length=1)
    version: str | None = Constraint(
        default=None, description="Benchmark edition, revision or release"
    )
    citation: str | None = Constraint(default=None, description="Source document")
    mapping_provenance: MappingProvenance = MappingProvenance.PROJECT_ASSERTED


class ComplianceRule(BaseModel):
    """One deterministic check, cross-mapped to every framework it satisfies."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str = Constraint(min_length=1)
    title: str = Constraint(min_length=1, description="Our own words")
    severity: Severity
    rationale: str = Constraint(
        min_length=1,
        max_length=MAX_RATIONALE_CHARS,
        description="Why this check exists, written by the project (R16)",
    )

    applies_to: AppliesTo = Constraint(default_factory=AppliesTo)
    check: CheckSpec
    absence_policy: AbsencePolicy = Constraint(default_factory=AbsencePolicy)

    frameworks: tuple[FrameworkRef, ...] = ()
    remediation_ref: str | None = None
    references: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> ComplianceRule:
        seen: set[tuple[Framework, str]] = set()
        for ref in self.frameworks:
            key = (ref.framework, ref.control_id)
            if key in seen:
                raise ValueError(
                    f"rule {self.rule_id!r} maps to {ref.framework}:{ref.control_id} twice"
                )
            seen.add(key)
        return self

    # -- access ------------------------------------------------------------

    def framework_ids(self, framework: Framework) -> tuple[str, ...]:
        return tuple(f.control_id for f in self.frameworks if f.framework is framework)

    @property
    def frameworks_covered(self) -> frozenset[Framework]:
        return frozenset(f.framework for f in self.frameworks)

    @property
    def has_official_mapping(self) -> bool:
        return any(f.mapping_provenance is MappingProvenance.OFFICIAL for f in self.frameworks)
