"""Field — value, confidence and evidence (DEVELOPER_GUIDE.md Rules 2 and 3, decision R7).

Three guarantees are enforced here, at construction, so that violating them is
not merely discouraged but impossible:

**Evidence is mandatory.** A field claiming PRESENT without evidence cannot be
built. The check consults only `state` and `evidence` — never `confidence` — so
a high score can never stand in for a missing citation. Confidence and evidence
are separate semantics that happen to travel together (R7).

**Low confidence abstains.** Below the configured threshold, state is coerced to
UNKNOWN before invariants are checked. Coercion lives in the model rather than
at the call site, so a caller cannot forget it.

**Uncalibrated similarity cannot assert anything.** A raw similarity score is
not a confidence. A field whose method is `uncalibrated_similarity` is forced to
UNKNOWN whatever its numeric value, because no mapping from that score to an
observed accuracy has been established yet. The score is still recorded, so an
administrator can see it in the training queue — it simply cannot support a
claim.
"""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import ConfidenceMethod, FieldState, PatternSource, UnknownReason
from api.models.evidence import Evidence

T = TypeVar("T")


def abstention_threshold() -> float:
    """The confidence below which a field abstains (Rule 3).

    Read lazily from settings so tests can monkeypatch this function without
    importing configuration at module load. Provisional until the calibrator is
    fitted at P9 — see R8.
    """
    from api.config import settings

    return settings.confidence_threshold


class FieldProvenance(BaseModel):
    """Which pack and pattern produced this value, and whether a human vetted it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    pack_id: str | None = None
    pack_version: str | None = None
    pattern_id: str | None = None
    source: PatternSource | None = None


class Field(BaseModel, Generic[T]):
    """One security-relevant canonical value, with its justification.

    Construction is the enforcement point. Every path that could produce an
    unjustified security claim raises here rather than propagating.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: T | None = None
    state: FieldState
    confidence: float = Constraint(ge=0.0, le=1.0)
    confidence_method: ConfidenceMethod

    evidence: tuple[Evidence, ...] = ()
    default_ref: str | None = Constraint(
        default=None, description="Citation for the platform default, when ABSENT_DEFAULT"
    )
    unknown_reason: UnknownReason | None = None
    provenance: FieldProvenance | None = None

    raw_score: float | None = Constraint(
        default=None,
        description=(
            "Uncalibrated similarity score, retained for the training queue and "
            "for calibration fitting. Never used as a confidence."
        ),
    )

    # -- coercion (runs before invariants) ---------------------------------

    @model_validator(mode="before")
    @classmethod
    def _coerce_abstention(cls, data: Any) -> Any:
        """Force UNKNOWN where the evidence of confidence is insufficient.

        Runs before the invariant checks so that a low-confidence field arrives
        at them already abstaining, rather than being rejected outright — the
        system's job is to say UNKNOWN, not to refuse to represent uncertainty.
        """
        if not isinstance(data, dict):
            return data

        method = data.get("confidence_method")
        state = data.get("state")
        if method is None or state is None:
            return data

        try:
            method = ConfidenceMethod(method)
            state = FieldState(state)
        except ValueError:
            return data  # let normal validation report the bad enum value

        confidence = data.get("confidence")

        def abstain(reason: UnknownReason) -> dict[str, Any]:
            out = dict(data)
            out["state"] = FieldState.UNKNOWN
            out["value"] = None
            out.setdefault("unknown_reason", reason)
            if out.get("unknown_reason") is None:
                out["unknown_reason"] = reason
            return out

        # R7 — an uncalibrated model score can never support a claim, whatever
        # its magnitude. Checked before the threshold, because for this
        # population the number carries no meaning to compare against one.
        if method is ConfidenceMethod.UNCALIBRATED_SIMILARITY and state is not FieldState.UNKNOWN:
            return abstain(UnknownReason.UNCALIBRATED_CONFIDENCE)

        # Rule 3 — below threshold, abstain. Applies to every population; only
        # the interpretation of the number differs between them.
        if (
            isinstance(confidence, int | float)
            and state is FieldState.PRESENT
            and float(confidence) < abstention_threshold()
        ):
            return abstain(UnknownReason.LOW_CONFIDENCE)

        return data

    # -- invariants --------------------------------------------------------

    @model_validator(mode="after")
    def _enforce_invariants(self) -> Field[T]:
        state = self.state

        if state is FieldState.PRESENT:
            # Rule 2. Deliberately independent of self.confidence: a high score
            # must never compensate for a missing citation (R7).
            if not self.evidence:
                raise ValueError(
                    "a PRESENT field requires at least one Evidence entry — "
                    "confidence does not substitute for a citation (Rule 2)"
                )
            if self.value is None:
                raise ValueError("a PRESENT field must carry a value")

        if state is FieldState.ABSENT_DEFAULT and not self.default_ref:
            raise ValueError(
                "an ABSENT_DEFAULT field requires default_ref citing the "
                "documented platform default"
            )

        if state is FieldState.UNKNOWN:
            if self.unknown_reason is None:
                raise ValueError("an UNKNOWN field must record why it abstained")
            if self.value is not None:
                raise ValueError(
                    "an UNKNOWN field must not carry a value — that is a guess "
                    "wearing an abstention label (Rule 3)"
                )

        if state is FieldState.ABSENT_UNSUPPORTED and self.value is not None:
            raise ValueError("an ABSENT_UNSUPPORTED field must not carry a value")

        # R7, belt and braces: coercion above should make this unreachable.
        if (
            self.confidence_method is ConfidenceMethod.UNCALIBRATED_SIMILARITY
            and state is not FieldState.UNKNOWN
        ):
            raise ValueError(
                "uncalibrated similarity cannot support a claim; a raw score is "
                "not a confidence (R7)"
            )

        return self

    # -- interpretation ----------------------------------------------------

    @property
    def is_determinable(self) -> bool:
        """True when the field says something the rule engine can evaluate."""
        return self.state is not FieldState.UNKNOWN

    @property
    def is_model_derived(self) -> bool:
        return self.confidence_method.is_model_derived

    @property
    def confidence_is_probability(self) -> bool:
        """Whether `confidence` may be read as an approximate probability (R7).

        False for deterministic, admin-confirmed and platform-default values.
        The evaluation harness uses this to select the population it calibrates,
        so the two kinds of number are never pooled into one reliability curve.
        """
        return self.confidence_method.is_probability

    def evidence_citations(self) -> list[str]:
        return [e.cite() for e in self.evidence]

    # -- constructors ------------------------------------------------------

    @classmethod
    def unknown(
        cls,
        reason: UnknownReason,
        *,
        confidence_method: ConfidenceMethod = ConfidenceMethod.DETERMINISTIC,
        confidence: float = 0.0,
        raw_score: float | None = None,
        evidence: tuple[Evidence, ...] = (),
    ) -> Field[T]:
        """Build an abstaining field. The safe default when anything is unclear."""
        return cls(
            value=None,
            state=FieldState.UNKNOWN,
            confidence=confidence,
            confidence_method=confidence_method,
            unknown_reason=reason,
            raw_score=raw_score,
            evidence=evidence,
        )
