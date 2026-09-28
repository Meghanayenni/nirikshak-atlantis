"""Compliance posture — how far one device complies with one framework (ADR 0068).

The unit is the framework **control**, not the NIRIKSHAK rule. A control rolls up
from every rule mapped to it on this device; the roll-up is decided in
`api/comply/posture.py` and these contracts only carry the result.

Two properties are structural here rather than conventions:

  * **No number without the file fully read.** `DevicePosture.frameworks` is
    empty unless the gate is `ready`. A gated posture carries the gate and
    nothing that could be read as a score.
  * **A headline never travels alone, and is never a percentage.** It is
    `satisfied` of `assessed`, carried in the same object as the other three
    counts and the catalog total, so no surface can receive it without them.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from api.models.enums import MappingCoverage, UnknownReason, Verdict
from api.models.evidence import Evidence


class GateState(StrEnum):
    """Whether a device may be scored, decided server-side from stored state."""

    NOT_AUDITED = "not_audited"
    """No audit run exists, or the platform was never identified."""

    REVIEW_PENDING = "review_pending"
    """The Needs-review queue for the file still holds an undecided entry."""

    RERUN_REQUIRED = "rerun_required"
    """Every entry is decided, and a decision is newer than the latest run."""

    READY = "ready"
    """Every entry is decided, and the latest run is newer than every decision."""

    EVALUATION_FILE = "evaluation_file"
    """The corpus manifest reserves this exact file for measurement (DEF-16).

    Scored by the evaluation harness against its labels, never reviewed here:
    a decision on one of its lines is how the measurement gets contaminated."""

    SUPERSEDED = "superseded"
    """Report only: the run being rendered is not the device's latest.

    The review queue describes the latest parse, so it says nothing about an
    older run's completeness. The posture endpoint always reads the latest run
    and never returns this state."""


class ControlState(StrEnum):
    SATISFIED = "satisfied"
    """Every mapped check passed, and at least one tests the whole control."""
    NO_VIOLATION_FOUND = "no_violation_found"
    """Every mapped check passed, and each tests only part of the control."""
    VIOLATED = "violated"
    UNDETERMINED = "undetermined"


class FrameworkStatus(StrEnum):
    ASSESSED = "assessed"
    NOT_APPLICABLE = "not_applicable"
    """The edition does not describe this device. Never scored, never zero."""
    NOT_IN_SCOPE = "not_in_scope"
    """The run was scoped to other benchmarks, so this one's rules did not run."""


class ReviewProgress(BaseModel):
    """Needs-review entries for the file of the latest run, and how many are decided."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reviewed: int
    total: int


class Gate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    state: GateState
    message: str
    next_step: str | None = None
    review: ReviewProgress | None = None
    audit_id: str | None = None
    evaluated_at: str | None = None
    last_decision_at: str | None = None


class RuleContribution(BaseModel):
    """One mapped rule's verdict, as it bears on one control."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rule_id: str
    coverage: MappingCoverage = MappingCoverage.PARTIAL
    """How much of the control this rule tests — the mapping's judgement."""
    coverage_reason: str | None = None
    verdict: Verdict | None
    """None when the run holds no finding for the rule."""
    finding_id: str | None = None
    unknown_reason: UnknownReason | None = None
    absence_reason: str | None = None
    evidence: tuple[Evidence, ...] = ()


class ControlPosture(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    control_id: str
    state: ControlState
    reason: str
    """The roll-up's reasoning for this control, in a sentence."""
    rules: tuple[RuleContribution, ...]


class FrameworkPosture(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    framework: str
    document: str
    edition: str
    status: FrameworkStatus
    reason: str | None = None
    """Why the framework is not assessed, when it is not."""

    satisfied: int = 0
    """The headline's numerator: controls fully satisfied."""
    no_violation_found: int = 0
    violated: int = 0
    undetermined: int = 0

    catalog_total: int | None = None
    catalog_basis: str
    """Where the total comes from, or why there is none."""

    controls: tuple[ControlPosture, ...] = ()

    @property
    def assessed(self) -> int:
        return self.satisfied + self.no_violation_found + self.violated + self.undetermined


class DevicePosture(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    gate: Gate
    mappings_attached: bool = False
    withheld_reason: str | None = None
    frameworks: tuple[FrameworkPosture, ...] = ()
    unsourced: dict[str, str] = {}
