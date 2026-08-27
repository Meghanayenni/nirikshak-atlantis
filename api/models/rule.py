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
    PackStatus,
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

    **`on_capability_unknown` is not configurable** (DEF-4). Until P6 this class
    only *claimed* that abstention was not overridable; nothing enforced it, so a
    rulepack could set `on_capability_unknown: pass` and the model accepted it.
    That mattered more than it looked: no platform defaults ship, so
    `capability_unknown` is the reason behind every absent field on every device,
    and one line of YAML could have turned that entire surface into passes.

    The `Finding` contract would have refused the resulting verdict for lack of
    evidence — but as a crash mid-audit, from a different contract, naming no
    rule. A guarantee documented in one place and enforced three layers away is
    not a guarantee. It is checked here now, at load.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    on_absent_default: AbsenceAction = AbsenceAction.EVALUATE
    on_absent_unsupported: AbsenceAction = AbsenceAction.NOT_APPLICABLE
    on_capability_unknown: AbsenceAction = AbsenceAction.UNKNOWN

    @model_validator(mode="after")
    def _capability_unknown_must_abstain(self) -> AbsencePolicy:
        """Undocumented capability abstains. There is no other admissible answer.

        Not PASS or FAIL, which would be a verdict on evidence we do not have.
        Not NOT_APPLICABLE either: that asserts the control does not apply to this
        platform, and not knowing whether a platform supports a control is
        precisely not knowing that. Not EVALUATE, which needs a documented default
        that by definition is absent here.
        """
        if self.on_capability_unknown is not AbsenceAction.UNKNOWN:
            raise ValueError(
                f"on_capability_unknown may only be {AbsenceAction.UNKNOWN.value!r}, got "
                f"{self.on_capability_unknown.value!r}. When platform support for a "
                "control is undocumented, the honest answer is that we do not know — "
                "any other value converts an unasked question into an answer (Rule 3)."
            )
        return self


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


class Rulepack(BaseModel):
    """A versioned set of rules, so a finding can say which ruleset produced it.

    `FindingProvenance.rulepack_version` existed from P1 with nothing to fill it.
    A report read six months later has to be able to say which rules ran, for the
    same reason `CsmSource.pack_versions` records which vendor pack read the line:
    a verdict is only reproducible if the data that produced it is identified.

    Modelled on `VendorPack` but **deliberately without its `checksum` field**.
    The P4 review established that pack checksums are declared and never verified
    against file bytes, and deferred fixing that to P11. Copying an unverified
    integrity mechanism into a second contract would double the problem rather
    than solve it, so this contract does not pretend to offer one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rulepack_id: str = Constraint(min_length=1, description="e.g. 'canonical'")
    version: str = Constraint(pattern=r"^\d+\.\d+\.\d+$")
    status: PackStatus = PackStatus.DRAFT
    created_by: str | None = None
    rules: tuple[ComplianceRule, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> Rulepack:
        ids = [r.rule_id for r in self.rules]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate rule ids in rulepack: {dupes}")
        return self

    # -- access ------------------------------------------------------------

    def rule(self, rule_id: str) -> ComplianceRule | None:
        return next((r for r in self.rules if r.rule_id == rule_id), None)

    def applicable_to(
        self, vendor: str | None, os_family: str | None
    ) -> tuple[ComplianceRule, ...]:
        """Rules whose platform selector admits this device.

        A rule that does not apply produces no finding at all, rather than an
        UNKNOWN one: "this check was never relevant here" and "we could not
        determine this check" are different statements, and only the second
        belongs in an operator's queue.
        """
        return tuple(r for r in self.rules if r.applies_to.matches(vendor, os_family))

    @property
    def frameworks_covered(self) -> frozenset[Framework]:
        """Every framework any rule maps to. Empty until a mapping is sourced (D16)."""
        return frozenset(f for r in self.rules for f in r.frameworks_covered)
