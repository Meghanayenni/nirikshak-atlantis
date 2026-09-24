"""Finding — one rule evaluated against one device.

Produced only by the deterministic engine reading the Canonical Security Model
(DEVELOPER_GUIDE.md Rule 1). Note what this contract does *not* have: no field accepts
model output, an explanation string that could carry a verdict, or a suggested
value. A model has nowhere to write here even if something tried.

A PASS or FAIL requires either evidence or an explicit absence citation, and an
UNKNOWN requires a stated reason. Abstention is a first-class result that
travels with its justification, not a gap in the report.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import (
    ConfidenceMethod,
    FieldState,
    Severity,
    UnknownReason,
    Verdict,
)
from api.models.evidence import Evidence
from api.models.rule import FrameworkRef


class ObservedValue(BaseModel):
    """What the canonical model actually held when the rule was evaluated."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: Any = None
    state: FieldState
    confidence: float = Constraint(ge=0.0, le=1.0)
    confidence_method: ConfidenceMethod

    @property
    def confidence_is_probability(self) -> bool:
        """R7 — deterministic confidence must not be reported as a probability."""
        return self.confidence_method.is_probability


class RemediationRef(BaseModel):
    """Pointer into the vetted snippet library. Never inline command text."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    snippet_id: str = Constraint(min_length=1)
    vendor: str = Constraint(min_length=1)
    os_family: str = Constraint(min_length=1)


class FindingProvenance(BaseModel):
    """Exactly which code and data produced this verdict, for reproducibility."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    engine_version: str = Constraint(min_length=1)
    rulepack_version: str | None = None
    rulepack_checksum: str | None = None
    """The digest of the rules that decided this verdict (ADR 0056).

    The version is a label a person chooses; this is the content. A report
    compares this, not the version, before showing today's control mappings
    beside a stored verdict. `None` on every run evaluated before P18."""
    pack_versions: dict[str, str] = Constraint(default_factory=dict)
    evaluated_at: datetime | None = None


class Finding(BaseModel):
    """The result of evaluating one rule against one device."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str = Constraint(min_length=1)
    audit_id: str = Constraint(min_length=1)
    device_id: str = Constraint(min_length=1)
    rule_id: str = Constraint(min_length=1)

    status: Verdict
    base_severity: Severity
    exposure_score: float | None = Constraint(
        default=None, ge=0.0, le=1.0, description="From P12; None when undeterminable"
    )
    priority_rank: int | None = Constraint(default=None, ge=1)

    observed: ObservedValue
    expected: str = Constraint(min_length=1, description="Human-readable, from the rule")

    evidence: tuple[Evidence, ...] = ()
    absence_reason: str | None = Constraint(
        default=None, description="Citation when the verdict rests on a documented default"
    )
    unknown_reason: UnknownReason | None = None

    frameworks: tuple[FrameworkRef, ...] = ()
    remediation: RemediationRef | None = None
    provenance: FindingProvenance

    @model_validator(mode="after")
    def _enforce_invariants(self) -> Finding:
        if self.status in (Verdict.PASS, Verdict.FAIL):
            if not self.evidence and not self.absence_reason:
                raise ValueError(
                    f"a {self.status.value.upper()} finding requires evidence or an "
                    "absence citation — no claim without justification (Rule 2)"
                )

        if self.status is Verdict.UNKNOWN and self.unknown_reason is None:
            raise ValueError(
                "an UNKNOWN finding must record why it abstained; silent "
                "uncertainty is indistinguishable from an oversight (Rule 3)"
            )

        if self.status is not Verdict.UNKNOWN and self.unknown_reason is not None:
            raise ValueError(
                f"a {self.status.value.upper()} finding must not carry an unknown_reason"
            )

        if self.status is Verdict.UNKNOWN and self.remediation is not None:
            raise ValueError(
                "an UNKNOWN finding must not carry remediation — we do not know "
                "there is anything to fix"
            )

        return self

    # -- reporting ---------------------------------------------------------

    @property
    def is_actionable(self) -> bool:
        return self.status is Verdict.FAIL

    @property
    def needs_training(self) -> bool:
        """UNKNOWN findings caused by parse gaps route to the training queue."""
        return self.status is Verdict.UNKNOWN and self.unknown_reason in (
            UnknownReason.NO_MATCH,
            UnknownReason.LOW_CONFIDENCE,
            UnknownReason.UNCALIBRATED_CONFIDENCE,
            UnknownReason.UNPARSED_BLOCK,
        )

    def citations(self) -> list[str]:
        return [e.cite() for e in self.evidence]
