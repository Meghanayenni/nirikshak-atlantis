"""Training examples — where trust actually originates.

The administrator's confirmation is the only event in NIRIKSHAK that creates a
trusted mapping. A confidence score, however high, never does. This contract
records both what the model proposed and what the human decided, which is what
makes top-3 accuracy measurable in production rather than only on the benchmark.

`raw_line_scrubbed` is stored post-redaction. The unscrubbed line never enters
the index, because this text reaches an embedding model (Rule 6).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import ConfidenceMethod, ExampleSource, TrainingOutcome


class Suggestion(BaseModel):
    """One ranked candidate the similarity layer proposed.

    `raw_score` and `calibrated_confidence` are kept apart on purpose (R7): the
    first is what the model produced, the second is what it means — and the
    second is null until a calibrator has been fitted for this population.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rank: int = Constraint(ge=1, le=3)
    field: str = Constraint(min_length=1)
    raw_score: float = Constraint(description="Raw similarity; not a confidence")
    calibrated_confidence: float | None = Constraint(default=None, ge=0.0, le=1.0)
    confidence_method: ConfidenceMethod = ConfidenceMethod.UNCALIBRATED_SIMILARITY

    @model_validator(mode="after")
    def _check(self) -> Suggestion:
        if self.confidence_method is ConfidenceMethod.CALIBRATED_SIMILARITY:
            if self.calibrated_confidence is None:
                raise ValueError(
                    f"suggestion for {self.field!r} claims calibrated confidence but carries none"
                )
        elif self.confidence_method is ConfidenceMethod.UNCALIBRATED_SIMILARITY:
            if self.calibrated_confidence is not None:
                raise ValueError(
                    f"suggestion for {self.field!r} carries a calibrated "
                    "confidence but is marked uncalibrated — a raw score cannot "
                    "become a probability by being stored in that slot (R7)"
                )
        else:
            raise ValueError(f"a suggestion must be model-derived; got {self.confidence_method}")
        return self


class TrainingExample(BaseModel):
    """One administrator decision, and the proposals that preceded it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    example_id: str = Constraint(min_length=1)
    vendor: str = Constraint(min_length=1)
    os_family: str = Constraint(min_length=1)

    raw_line_scrubbed: str = Constraint(
        min_length=1, description="Post-redaction. The raw line is never indexed."
    )
    normalised_line: str = Constraint(default="", description="Token-shape signature")
    cluster_id: str | None = None

    field: str | None = Constraint(
        default=None, description="Canonical field confirmed; None when rejected"
    )
    value_semantics: str | None = Constraint(
        default=None, description="Which captured token carries the value"
    )
    embedding_id: int | None = Constraint(default=None, ge=0)

    suggestions_shown: tuple[Suggestion, ...] = ()
    outcome: TrainingOutcome

    confirmed_by: str = Constraint(min_length=1, description="The human who decided")
    confirmed_at: datetime | None = None
    source: ExampleSource = ExampleSource.ADMIN
    audit_seq: int | None = Constraint(default=None, ge=0)

    @model_validator(mode="after")
    def _check(self) -> TrainingExample:
        ranks = [s.rank for s in self.suggestions_shown]
        if len(ranks) != len(set(ranks)):
            raise ValueError(f"example {self.example_id!r} has duplicate suggestion ranks")

        rank = self.outcome.accepted_rank
        if rank is not None:
            match = next((s for s in self.suggestions_shown if s.rank == rank), None)
            if match is None:
                raise ValueError(
                    f"example {self.example_id!r} records accepting rank {rank}, "
                    "but no suggestion at that rank was shown"
                )
            if self.field is not None and match.field != self.field:
                raise ValueError(
                    f"example {self.example_id!r} accepted rank {rank} "
                    f"({match.field!r}) but recorded field {self.field!r}; if the "
                    "administrator changed it, the outcome is CORRECTED"
                )

        if self.outcome is TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT:
            if self.field is not None:
                raise ValueError(
                    f"example {self.example_id!r} was rejected as not security "
                    "relevant but names a canonical field"
                )
        elif self.field is None:
            raise ValueError(
                f"example {self.example_id!r} has outcome {self.outcome} but no confirmed field"
            )

        return self

    @property
    def improved_coverage(self) -> bool:
        """Whether this example adds a mapping the packs can learn from."""
        return self.field is not None

    @property
    def top3_hit(self) -> bool:
        """Did the correct field appear in the suggestions?

        Feeds top-3 mapping accuracy. That metric is not computable yet: it needs
        line-level ground truth, which decision D39 declined to author, and its
        held-out form additionally needs a parser that decision D37 deferred. The
        property is correct and waiting for a population — see ADR 0017.
        """
        return self.field is not None and any(s.field == self.field for s in self.suggestions_shown)
