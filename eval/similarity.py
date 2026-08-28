"""Top-3 mapping accuracy — the metric, and why it has nothing to run on.

The Concept Report §6 defines generalisation as

    the proportion of its commands for which the similarity layer proposes the
    correct field within its top three suggestions

This module implements that arithmetic and reports, honestly, that it cannot be
computed. Two independent reasons, and closing either one alone is not enough:

**SEQ-2 — the held-out population is unreachable.** The metric is defined over
the held-out vendor's commands. Obtaining them means parsing PAN-OS XML.
`SyntaxMode.XML` raises, and its own deferral note says it waits for *"an XML
sample independent of the PAN-OS holdout"* — because building the parser from
the holdout would destroy the experiment the holdout exists for. No independent
sample exists. This is circular, and no code closes it.

**No line-level ground truth exists.** Even on a non-holdout population the
metric needs labels saying *this unknown line means `ssh_version`*. P9 labelled
canonical **fields**, not lines. Decision D39 declined to author line-level
labels for the purpose of making a metric computable, which is the right call:
manufacturing evaluation data to fill a metric is the failure this project has
refused at every phase.

So the arithmetic is here, tested against constructed observations, and the
report says NOT MEASURED with the reason. It is not a placeholder — it is the
metric, waiting for a population it is allowed to have.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum


class MetricStatus(StrEnum):
    """Why a similarity metric does or does not have a number."""

    MEASURED = "measured"
    BLOCKED_NO_PARSER = "blocked_no_parser"
    """The population cannot be read at all — SEQ-2."""

    BLOCKED_NO_LABELS = "blocked_no_labels"
    """The population is readable but nobody has labelled it — D39."""


@dataclass(frozen=True)
class SuggestionOutcome:
    """One unknown line, its true field, and the fields that were proposed.

    `true_field` comes from a human label. There is no constructor path deriving
    it from the pipeline, for the same reason `eval/labels.py` cannot import the
    parser: a metric scored against its own subject measures nothing.
    """

    line: str
    true_field: str | None
    proposed: tuple[str, ...]

    @property
    def is_scoreable(self) -> bool:
        """Whether this line belongs in the denominator.

        A line that maps to no canonical field has no right answer, so including
        it would deflate the metric by counting cases the layer was never meant
        to serve. Excluding them is the honest denominator — the layer is scored
        on the work it exists to do.
        """
        return self.true_field is not None

    @property
    def top1_hit(self) -> bool:
        return bool(self.proposed) and self.proposed[0] == self.true_field

    @property
    def top3_hit(self) -> bool:
        return self.true_field is not None and self.true_field in self.proposed[:3]


@dataclass(frozen=True)
class SimilarityMetrics:
    """Top-1 and top-3 accuracy over one labelled population."""

    population: str
    status: MetricStatus
    scoreable: int = 0
    top1: int = 0
    top3: int = 0
    unscoreable: int = 0
    blocked_reason: str = ""

    @property
    def top1_accuracy(self) -> float | None:
        return self.top1 / self.scoreable if self.scoreable else None

    @property
    def top3_accuracy(self) -> float | None:
        return self.top3 / self.scoreable if self.scoreable else None

    @property
    def measured(self) -> bool:
        return self.status is MetricStatus.MEASURED


def score_suggestions(outcomes: list[SuggestionOutcome], *, population: str) -> SimilarityMetrics:
    """Fold labelled outcomes into top-1 and top-3 accuracy.

    An empty population returns `BLOCKED_NO_LABELS` rather than an accuracy of
    zero. Zero is a measurement; this is the absence of one, and a report that
    printed 0.0% here would say the layer failed when nobody has tested it.
    """
    counts = Counter()
    for outcome in outcomes:
        if not outcome.is_scoreable:
            counts["unscoreable"] += 1
            continue
        counts["scoreable"] += 1
        counts["top1"] += int(outcome.top1_hit)
        counts["top3"] += int(outcome.top3_hit)

    if not counts["scoreable"]:
        return SimilarityMetrics(
            population=population,
            status=MetricStatus.BLOCKED_NO_LABELS,
            unscoreable=counts["unscoreable"],
            blocked_reason=(
                "no line-level ground truth exists for this population; P9 labelled "
                "canonical fields, not lines, and decision D39 declined to author "
                "line labels to make this metric computable"
            ),
        )

    return SimilarityMetrics(
        population=population,
        status=MetricStatus.MEASURED,
        scoreable=counts["scoreable"],
        top1=counts["top1"],
        top3=counts["top3"],
        unscoreable=counts["unscoreable"],
    )


def generalisation_status() -> SimilarityMetrics:
    """The held-out vendor experiment. Always blocked at P10 (SEQ-2, decision D37).

    Returns a status object rather than raising, so the report can render the
    row as *not attempted* with its reason. A raise would make the report fail
    to generate over a state that is expected and documented.

    **Nothing in this function reads the holdout.** It reports on an experiment
    that has not been run, which is the only honest thing to say about it.
    """
    return SimilarityMetrics(
        population="held-out vendor",
        status=MetricStatus.BLOCKED_NO_PARSER,
        blocked_reason=(
            "the metric is defined over the held-out vendor's commands, which requires "
            "parsing its configuration format. That parser is deferred until an "
            "independent sample of the format exists, because building it from the "
            "held-out files would destroy the experiment they exist for. The holdout "
            "was not opened (decision D37)"
        ),
    )
