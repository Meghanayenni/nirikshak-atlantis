"""Scoring outcomes into metrics. Pure arithmetic over comparison results.

This module imports nothing from `api/` except the contracts, and performs no
I/O. It is handed outcomes and returns counts, which is what lets every metric
be tested against constructed observations rather than against a corpus.

## The distinction the whole harness turns on

A field the system declined to answer is a **correct abstention** only when the
control genuinely could not be determined from the file. When a human could read
it straight off the page, the same silence is a **miss**.

Collapsing the two would turn missing parser coverage into a success rate — a
system that parses nothing would score a perfect correct-abstention rate. They
are counted separately here and never summed.

## Evidence integrity is separate from value accuracy

A field can hold the right value and cite the wrong line. Rule 2 makes that a
failure rather than a rounding error: a security fact carrying a citation that
does not support it is worse than no claim at all. So evidence is scored in its
own population, reported in its own column, and never folded into precision.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from dataclasses import field as dc_field
from enum import StrEnum
from typing import Any

from api.models.enums import Verdict


class FieldOutcome(StrEnum):
    """How one field observation compared against its label."""

    CORRECT = "correct"
    """Determinable, and the system asserted the labelled value."""

    WRONG_CONFIDENT = "wrong_confident"
    """The system asserted a value that the label contradicts.

    Includes asserting any value for a field the label marks not determinable:
    claiming to know something the file does not establish is the same failure
    as claiming the wrong thing.

    This is the figure the Concept Report says must remain near zero.
    """

    MISS = "miss"
    """Determinable, and the system abstained. A recall loss, not a success."""

    CORRECT_ABSTENTION = "correct_abstention"
    """Not determinable, and the system abstained. Honest uncertainty."""


class EvidenceOutcome(StrEnum):
    """Whether an asserted value cited the line the labeller read."""

    CORRECT = "correct"
    WRONG_LINE = "wrong_line"
    MISSING = "missing"
    """A value was asserted with no citation at all — a Rule 2 violation."""

    NOT_SCORED = "not_scored"
    """Nothing was asserted, or the label rests on absence and cites no line."""


@dataclass(frozen=True)
class FieldObservation:
    """One canonical field on one configuration, compared against its label."""

    corpus_path: str
    vendor: str
    os_family: str
    field: str

    determinable: bool
    expected_value: Any
    system_asserted: bool
    system_value: Any

    outcome: FieldOutcome
    evidence: EvidenceOutcome
    labelled_line: int | None = None
    cited_line: int | None = None

    has_parsing_pack: bool = False
    pattern_author_conflict: bool = False


@dataclass(frozen=True)
class VerdictObservation:
    """One rule on one configuration, compared against its label."""

    corpus_path: str
    vendor: str
    rule_id: str
    expected: Verdict
    actual: Verdict
    has_parsing_pack: bool = False

    @property
    def agrees(self) -> bool:
        return self.expected is self.actual


@dataclass(frozen=True)
class DetectionObservation:
    """One file's vendor detection, compared against the manifest."""

    corpus_path: str
    expected_vendor: str
    detected_vendor: str | None
    outcome_reason: str

    @property
    def correct(self) -> bool:
        return self.detected_vendor == self.expected_vendor

    @property
    def abstained(self) -> bool:
        return self.detected_vendor is None


@dataclass(frozen=True)
class FieldMetrics:
    """Counts and rates for one population of field observations.

    Every rate carries its denominator. A precision of 1.00 over two
    observations and over two thousand are different claims, and a report that
    prints only the first number invites the reader to assume the second.
    """

    population: str
    total: int
    correct: int
    wrong_confident: int
    miss: int
    correct_abstention: int

    evidence_correct: int = 0
    evidence_wrong_line: int = 0
    evidence_missing: int = 0
    evidence_scored: int = 0

    @property
    def asserted(self) -> int:
        """Observations where the system produced a value."""
        return self.correct + self.wrong_confident

    @property
    def abstained(self) -> int:
        """Observations where the system produced no value, right or wrong."""
        return self.miss + self.correct_abstention

    @property
    def precision(self) -> float | None:
        """Correct values as a fraction of values asserted. None when nothing was."""
        return self.correct / self.asserted if self.asserted else None

    @property
    def recall(self) -> float | None:
        """Correct values as a fraction of what a human could determine."""
        denominator = self.correct + self.miss + self.wrong_confident
        return self.correct / denominator if denominator else None

    @property
    def miss_rate(self) -> float | None:
        denominator = self.correct + self.miss
        return self.miss / denominator if denominator else None

    @property
    def wrong_confident_rate(self) -> float | None:
        """The safety figure. Wrong assertions over all assertions."""
        return self.wrong_confident / self.asserted if self.asserted else None

    @property
    def correct_abstention_rate(self) -> float | None:
        """Of the times the system stayed silent, how often silence was right.

        The denominator is **every** abstention, misses included. That is what
        makes the number honest: a parser with no patterns abstains on
        everything and scores near zero here, because most of its silences were
        on fields a human could read. A denominator of correct abstentions alone
        would return 1.00 for such a parser, which is the flattering nonsense
        this metric exists to avoid.
        """
        return self.correct_abstention / self.abstained if self.abstained else None

    @property
    def evidence_integrity(self) -> float | None:
        """Correct citations over assertions whose citation could be checked."""
        return self.evidence_correct / self.evidence_scored if self.evidence_scored else None


def field_metrics(observations: list[FieldObservation], population: str) -> FieldMetrics:
    """Fold a list of observations into one population's counts."""
    outcomes = Counter(o.outcome for o in observations)
    evidence = Counter(o.evidence for o in observations)
    scored = sum(1 for o in observations if o.evidence is not EvidenceOutcome.NOT_SCORED)

    return FieldMetrics(
        population=population,
        total=len(observations),
        correct=outcomes[FieldOutcome.CORRECT],
        wrong_confident=outcomes[FieldOutcome.WRONG_CONFIDENT],
        miss=outcomes[FieldOutcome.MISS],
        correct_abstention=outcomes[FieldOutcome.CORRECT_ABSTENTION],
        evidence_correct=evidence[EvidenceOutcome.CORRECT],
        evidence_wrong_line=evidence[EvidenceOutcome.WRONG_LINE],
        evidence_missing=evidence[EvidenceOutcome.MISSING],
        evidence_scored=scored,
    )


def by_vendor(observations: list[FieldObservation]) -> dict[str, list[FieldObservation]]:
    """Split observations by vendor. Never merged again (decision D34)."""
    grouped: dict[str, list[FieldObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.vendor, []).append(observation)
    return dict(sorted(grouped.items()))


def by_field(observations: list[FieldObservation]) -> dict[str, list[FieldObservation]]:
    grouped: dict[str, list[FieldObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.field, []).append(observation)
    return dict(sorted(grouped.items()))


@dataclass(frozen=True)
class VerdictMetrics:
    """A confusion matrix over verdicts, plus per-class precision and recall.

    `matrix[(expected, actual)]` counts. Classes with no observations stay in the
    matrix as zeros rather than being dropped: an absent row reads as a clean
    result, when it means the class was never exercised.
    """

    population: str
    total: int
    matrix: dict[tuple[Verdict, Verdict], int] = dc_field(default_factory=dict)

    def count(self, expected: Verdict, actual: Verdict) -> int:
        return self.matrix.get((expected, actual), 0)

    def expected_total(self, verdict: Verdict) -> int:
        return sum(n for (e, _), n in self.matrix.items() if e is verdict)

    def actual_total(self, verdict: Verdict) -> int:
        return sum(n for (_, a), n in self.matrix.items() if a is verdict)

    def precision(self, verdict: Verdict) -> float | None:
        produced = self.actual_total(verdict)
        return self.count(verdict, verdict) / produced if produced else None

    def recall(self, verdict: Verdict) -> float | None:
        expected = self.expected_total(verdict)
        return self.count(verdict, verdict) / expected if expected else None

    def exercised(self, verdict: Verdict) -> bool:
        """Whether the class appears in the labels at all.

        A class nobody labelled has no precision and no recall, and the report
        says 'not exercised' rather than printing a blank that reads as zero.
        """
        return self.expected_total(verdict) > 0

    @property
    def agreement(self) -> float | None:
        agreed = sum(n for (e, a), n in self.matrix.items() if e is a)
        return agreed / self.total if self.total else None


def verdict_metrics(observations: list[VerdictObservation], population: str) -> VerdictMetrics:
    matrix: dict[tuple[Verdict, Verdict], int] = {}
    for observation in observations:
        key = (observation.expected, observation.actual)
        matrix[key] = matrix.get(key, 0) + 1
    return VerdictMetrics(population=population, total=len(observations), matrix=matrix)


def verdicts_by_vendor(
    observations: list[VerdictObservation],
) -> dict[str, list[VerdictObservation]]:
    grouped: dict[str, list[VerdictObservation]] = {}
    for observation in observations:
        grouped.setdefault(observation.vendor, []).append(observation)
    return dict(sorted(grouped.items()))


@dataclass(frozen=True)
class DetectionMetrics:
    """Four outcomes, kept apart.

    "Below threshold" and "ambiguous" both produce UNKNOWN but say different
    things about the signature set: the first is thin evidence, the second is two
    platforms that genuinely look alike and need a discriminating pattern rather
    than more patterns.
    """

    total: int
    correct: int
    wrong: int
    abstained: int
    reasons: dict[str, int] = dc_field(default_factory=dict)

    @property
    def accuracy(self) -> float | None:
        return self.correct / self.total if self.total else None


def detection_metrics(observations: list[DetectionObservation]) -> DetectionMetrics:
    reasons = Counter(o.outcome_reason for o in observations if o.abstained)
    return DetectionMetrics(
        total=len(observations),
        correct=sum(1 for o in observations if o.correct),
        wrong=sum(1 for o in observations if not o.correct and not o.abstained),
        abstained=sum(1 for o in observations if o.abstained),
        reasons=dict(sorted(reasons.items())),
    )
