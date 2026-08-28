"""Calibration — the machinery, and the refusal to use it yet.

The Concept Report §4:

    Raw similarity scores are not confidence. Scores are calibrated against a
    hand-labelled corpus so that a stated confidence corresponds to observed
    accuracy, which makes the abstention threshold defensible rather than
    arbitrary.

A calibrator maps a raw similarity score to P(the suggestion is correct), fitted
on `(score, was_correct)` pairs drawn from labelled ground truth.

**No calibrator is fitted at P10, and none ships** (decision D42).

The population that would be needed is line-level ground truth — *this unknown
line means `ssh_version`* — and none exists. P9 labelled canonical **fields**,
not lines, and D39 declined to author line-level labels for the purpose of
making this metric computable. The development split holds roughly a dozen
security-relevant unknown lines in any case, which is far below what a
defensible curve requires.

So this module implements the fitting and the reliability arithmetic, refuses to
fit below a minimum sample, and is exercised entirely against constructed score
distributions. Every suggestion the system produces stays
`UNCALIBRATED_SIMILARITY`, which forces the field to UNKNOWN.

**Why build it at all.** The refusal has to be enforced by something. A phase
that shipped no calibration code would leave the next author to invent one under
deadline, and the guard that matters — *fitting below a minimum sample raises* —
would not exist to stop them.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.learn.errors import CalibrationError
from api.models.enums import ConfidenceMethod

MIN_CALIBRATION_SAMPLES = 200
"""Below this, `fit` refuses.

Not a statistically derived figure and not presented as one — it is a floor
chosen to be plainly above what this corpus can supply, so the refusal is
unambiguous rather than marginal. A calibration curve is a claim about how often
the system is right at a given score, and a claim like that made from a dozen
observations is an unsourced confidence assertion: the same failure as an
unsourced platform default, wearing a probability.

When real training data exists the number should be revisited against the
observed score distribution, and that revision belongs in a decision record.
"""

MIN_POSITIVE_SAMPLES = 20
"""A curve fitted on scores that were never once correct is not a curve."""


@dataclass(frozen=True)
class ScoreOutcome:
    """One observation: a raw similarity score, and whether it was right.

    `was_correct` comes from a human label, never from the pipeline. There is no
    constructor path here that derives it from a parser result.
    """

    score: float
    was_correct: bool


@dataclass(frozen=True)
class ReliabilityBin:
    """One bucket of a reliability diagram."""

    lower: float
    upper: float
    count: int
    mean_score: float
    observed_accuracy: float

    @property
    def gap(self) -> float:
        """How far the stated confidence sits from the observed accuracy."""
        return abs(self.mean_score - self.observed_accuracy)


@dataclass(frozen=True)
class Calibrator:
    """A fitted score-to-probability mapping.

    Only a `Calibrator` may licence `ConfidenceMethod.CALIBRATED_SIMILARITY`.
    None is fitted at P10, so nothing licences it, so every suggestion abstains.
    """

    thresholds: tuple[float, ...]
    probabilities: tuple[float, ...]
    sample_size: int
    fitted_on: str

    def probability(self, score: float) -> float:
        """P(correct) for a raw score, by isotonic step lookup."""
        result = self.probabilities[0] if self.probabilities else 0.0
        for threshold, probability in zip(self.thresholds, self.probabilities, strict=True):
            if score >= threshold:
                result = probability
        return result

    @property
    def method(self) -> ConfidenceMethod:
        return ConfidenceMethod.CALIBRATED_SIMILARITY


def _isotonic(observations: list[ScoreOutcome]) -> tuple[tuple[float, ...], tuple[float, ...]]:
    """Pool-adjacent-violators, ascending in score.

    Isotonic rather than Platt because it assumes only monotonicity — that a
    higher similarity is not less likely to be correct — and does not impose a
    sigmoid shape the data may not have.
    """
    ordered = sorted(observations, key=lambda o: o.score)
    scores = [o.score for o in ordered]
    values = [1.0 if o.was_correct else 0.0 for o in ordered]
    weights = [1.0] * len(values)

    i = 0
    while i < len(values) - 1:
        if values[i] <= values[i + 1]:
            i += 1
            continue
        total = weights[i] + weights[i + 1]
        pooled = (values[i] * weights[i] + values[i + 1] * weights[i + 1]) / total
        values[i : i + 2] = [pooled]
        weights[i : i + 2] = [total]
        scores[i : i + 2] = [scores[i]]
        i = max(i - 1, 0)

    return tuple(scores), tuple(values)


def fit(observations: list[ScoreOutcome], *, fitted_on: str) -> Calibrator:
    """Fit a calibrator, or refuse.

    Refusal is the expected outcome for the foreseeable future, and it is not a
    failure state — it is the module declining to make a claim it cannot support.
    """
    if len(observations) < MIN_CALIBRATION_SAMPLES:
        raise CalibrationError(
            f"refusing to fit a calibrator on {len(observations)} observations; "
            f"the floor is {MIN_CALIBRATION_SAMPLES}. A curve fitted on fewer is a "
            "statement about how often the system is right, made from a sample too "
            "small to support one. Until then every suggestion stays uncalibrated "
            "and the field abstains (decision D42)."
        )

    positives = sum(1 for o in observations if o.was_correct)
    if positives < MIN_POSITIVE_SAMPLES:
        raise CalibrationError(
            f"refusing to fit: only {positives} of {len(observations)} observations "
            f"were correct, below the floor of {MIN_POSITIVE_SAMPLES}. A curve fitted "
            "on scores that were almost never right describes noise."
        )

    thresholds, probabilities = _isotonic(observations)
    return Calibrator(
        thresholds=thresholds,
        probabilities=probabilities,
        sample_size=len(observations),
        fitted_on=fitted_on,
    )


def reliability(observations: list[ScoreOutcome], *, bins: int = 10) -> tuple[ReliabilityBin, ...]:
    """A reliability diagram, as data.

    Useful before a calibrator exists: it shows whether the raw scores carry any
    monotone signal at all. Empty bins are dropped rather than reported as zero
    accuracy — a bucket nobody landed in is not a bucket the system got wrong.
    """
    if not observations:
        return ()

    width = 1.0 / bins
    out: list[ReliabilityBin] = []
    for index in range(bins):
        lower, upper = index * width, (index + 1) * width
        members = [
            o
            for o in observations
            if lower <= o.score < upper or (index == bins - 1 and o.score == upper)
        ]
        if not members:
            continue
        out.append(
            ReliabilityBin(
                lower=lower,
                upper=upper,
                count=len(members),
                mean_score=sum(o.score for o in members) / len(members),
                observed_accuracy=sum(1 for o in members if o.was_correct) / len(members),
            )
        )
    return tuple(out)


def expected_calibration_error(observations: list[ScoreOutcome], *, bins: int = 10) -> float | None:
    """Weighted mean gap between stated score and observed accuracy.

    `None` on an empty population rather than 0.0: a perfect score over nothing
    is not a perfect score.
    """
    diagram = reliability(observations, bins=bins)
    if not diagram:
        return None
    total = sum(b.count for b in diagram)
    return sum(b.count * b.gap for b in diagram) / total


def active_calibrator() -> Calibrator | None:
    """The calibrator in force. Always `None` at P10.

    A function rather than a constant so the answer has one home, and so the
    test asserting it stays `None` fails loudly on the day someone fits one
    without revisiting D42.
    """
    return None
