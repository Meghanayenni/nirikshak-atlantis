"""Evaluation arithmetic (P9).

Every metric here is exercised against **constructed** observations rather than
against the corpus. That is deliberate: a metric tested only on real data is
tested only on the cases that happen to occur, and the cases that matter most
for honesty — a wrong-confident answer, a citation pointing at the wrong line —
do not occur at all right now.

The sharpest tests are the ones that would pass if the arithmetic were
flattering. `test_a_parser_that_reads_nothing_scores_badly` is the whole design
in one assertion.
"""

from __future__ import annotations

from api.models.enums import Verdict
from eval.metrics import (
    DetectionObservation,
    EvidenceOutcome,
    FieldObservation,
    FieldOutcome,
    VerdictObservation,
    by_field,
    by_vendor,
    detection_metrics,
    field_metrics,
    verdict_metrics,
)


def observation(
    outcome: FieldOutcome,
    *,
    vendor: str = "cisco",
    field: str = "ssh_version",
    evidence: EvidenceOutcome = EvidenceOutcome.NOT_SCORED,
    has_pack: bool = True,
) -> FieldObservation:
    determinable = outcome in (FieldOutcome.CORRECT, FieldOutcome.MISS)
    return FieldObservation(
        corpus_path="constructed/eval/device.cfg",
        vendor=vendor,
        os_family="os",
        field=field,
        determinable=determinable,
        expected_value=2 if determinable else None,
        system_asserted=outcome in (FieldOutcome.CORRECT, FieldOutcome.WRONG_CONFIDENT),
        system_value=2 if outcome is FieldOutcome.CORRECT else None,
        outcome=outcome,
        evidence=evidence,
        has_parsing_pack=has_pack,
    )


# ---------------------------------------------------------------------------
# Counting
# ---------------------------------------------------------------------------


def test_an_empty_population_has_no_rates_rather_than_zero_rates() -> None:
    """A rate over nothing is not zero; it does not exist.

    Rendering it as 0.0 would put a number where there is no measurement, and a
    reader has no way to tell the two apart.
    """
    metrics = field_metrics([], "empty")

    assert metrics.total == 0
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.wrong_confident_rate is None
    assert metrics.correct_abstention_rate is None
    assert metrics.evidence_integrity is None


def test_outcomes_are_counted_into_their_own_buckets() -> None:
    metrics = field_metrics(
        [
            observation(FieldOutcome.CORRECT),
            observation(FieldOutcome.CORRECT),
            observation(FieldOutcome.WRONG_CONFIDENT),
            observation(FieldOutcome.MISS),
            observation(FieldOutcome.CORRECT_ABSTENTION),
        ],
        "mixed",
    )

    assert (metrics.correct, metrics.wrong_confident) == (2, 1)
    assert (metrics.miss, metrics.correct_abstention) == (1, 1)
    assert metrics.asserted == 3
    assert metrics.abstained == 2


def test_precision_is_correct_over_asserted() -> None:
    metrics = field_metrics(
        [observation(FieldOutcome.CORRECT)] * 3 + [observation(FieldOutcome.WRONG_CONFIDENT)],
        "p",
    )
    assert metrics.precision == 0.75


def test_recall_counts_a_wrong_answer_against_it() -> None:
    """Asserting the wrong value is not the same as staying silent, but it is
    not recall either. Both belong in the denominator."""
    metrics = field_metrics(
        [
            observation(FieldOutcome.CORRECT),
            observation(FieldOutcome.MISS),
            observation(FieldOutcome.WRONG_CONFIDENT),
        ],
        "r",
    )
    assert metrics.recall == 1 / 3


def test_correct_abstentions_never_inflate_recall() -> None:
    """A field nobody could determine is not a field the system failed to read."""
    with_abstentions = field_metrics(
        [observation(FieldOutcome.CORRECT)] + [observation(FieldOutcome.CORRECT_ABSTENTION)] * 20,
        "a",
    )
    assert with_abstentions.recall == 1.0


# ---------------------------------------------------------------------------
# The assertion the whole design rests on
# ---------------------------------------------------------------------------


def test_a_parser_that_reads_nothing_scores_badly() -> None:
    """The flattering-arithmetic trap, closed.

    A system with no patterns abstains on everything. If correct abstention were
    counted over the not-determinable population alone it would score 100% and
    look excellent. Counting over *every* abstention makes it score by how much
    of what a human could read it actually read.
    """
    reads_nothing = field_metrics(
        [observation(FieldOutcome.MISS) for _ in range(8)]
        + [observation(FieldOutcome.CORRECT_ABSTENTION) for _ in range(2)],
        "silent",
    )

    assert reads_nothing.correct_abstention_rate == 0.2
    assert reads_nothing.recall == 0.0
    assert reads_nothing.precision is None


def test_a_system_that_asserts_nothing_has_no_wrong_confident_rate() -> None:
    """And the report must not print it as a perfect zero.

    None renders as n/a. A 0.0 would read as "measured, and flawless".
    """
    silent = field_metrics([observation(FieldOutcome.CORRECT_ABSTENTION)] * 5, "silent")
    assert silent.wrong_confident_rate is None


def test_wrong_confident_rate_is_over_assertions_not_over_everything() -> None:
    """Diluting it with abstentions would let a quiet system hide a bad answer."""
    metrics = field_metrics(
        [observation(FieldOutcome.WRONG_CONFIDENT), observation(FieldOutcome.CORRECT)]
        + [observation(FieldOutcome.CORRECT_ABSTENTION)] * 98,
        "diluted",
    )
    assert metrics.wrong_confident_rate == 0.5


# ---------------------------------------------------------------------------
# Evidence integrity
# ---------------------------------------------------------------------------


def test_evidence_integrity_is_separate_from_value_accuracy() -> None:
    """Rule 2 — the right value with the wrong citation is a failure.

    Both observations below are value-correct. Only one cites the line the
    labeller read, and precision must not notice the difference while evidence
    integrity must.
    """
    metrics = field_metrics(
        [
            observation(FieldOutcome.CORRECT, evidence=EvidenceOutcome.CORRECT),
            observation(FieldOutcome.CORRECT, evidence=EvidenceOutcome.WRONG_LINE),
        ],
        "e",
    )

    assert metrics.precision == 1.0
    assert metrics.evidence_integrity == 0.5


def test_a_missing_citation_counts_against_integrity() -> None:
    metrics = field_metrics(
        [
            observation(FieldOutcome.CORRECT, evidence=EvidenceOutcome.CORRECT),
            observation(FieldOutcome.CORRECT, evidence=EvidenceOutcome.MISSING),
        ],
        "e",
    )
    assert metrics.evidence_integrity == 0.5
    assert metrics.evidence_missing == 1


def test_unscoreable_evidence_is_excluded_rather_than_failed() -> None:
    """A label resting on absence has no line to point at.

    Counting it as a missing citation would penalise the system for a citation
    the ground truth never had.
    """
    metrics = field_metrics(
        [
            observation(FieldOutcome.CORRECT, evidence=EvidenceOutcome.CORRECT),
            observation(FieldOutcome.MISS, evidence=EvidenceOutcome.NOT_SCORED),
        ],
        "e",
    )
    assert metrics.evidence_scored == 1
    assert metrics.evidence_integrity == 1.0


# ---------------------------------------------------------------------------
# Populations stay apart (decision D34)
# ---------------------------------------------------------------------------


def test_vendors_are_grouped_and_not_merged() -> None:
    grouped = by_vendor(
        [
            observation(FieldOutcome.CORRECT, vendor="cisco"),
            observation(FieldOutcome.MISS, vendor="arista", has_pack=False),
            observation(FieldOutcome.MISS, vendor="juniper", has_pack=False),
        ]
    )
    assert sorted(grouped) == ["arista", "cisco", "juniper"]
    assert all(len(v) == 1 for v in grouped.values())


def test_grouping_by_field_preserves_every_observation() -> None:
    grouped = by_field(
        [
            observation(FieldOutcome.CORRECT, field="ssh_version"),
            observation(FieldOutcome.MISS, field="ssh_version"),
            observation(FieldOutcome.CORRECT, field="telnet_enabled"),
        ]
    )
    assert len(grouped["ssh_version"]) == 2
    assert len(grouped["telnet_enabled"]) == 1


def test_pack_status_travels_with_the_observation() -> None:
    """So the renderer can label a row without re-deriving it."""
    detection_only = observation(FieldOutcome.MISS, vendor="arista", has_pack=False)
    assert detection_only.has_parsing_pack is False


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


def verdict(expected: Verdict, actual: Verdict, vendor: str = "cisco") -> VerdictObservation:
    return VerdictObservation(
        corpus_path="constructed/eval/device.cfg",
        vendor=vendor,
        rule_id="NRK-TEST-001",
        expected=expected,
        actual=actual,
    )


def test_the_matrix_counts_every_pairing() -> None:
    metrics = verdict_metrics(
        [
            verdict(Verdict.FAIL, Verdict.FAIL),
            verdict(Verdict.FAIL, Verdict.UNKNOWN),
            verdict(Verdict.PASS, Verdict.PASS),
        ],
        "v",
    )

    assert metrics.count(Verdict.FAIL, Verdict.FAIL) == 1
    assert metrics.count(Verdict.FAIL, Verdict.UNKNOWN) == 1
    assert metrics.count(Verdict.PASS, Verdict.PASS) == 1
    assert metrics.total == 3


def test_fail_precision_and_recall_are_computed_independently() -> None:
    """A missed FAIL and a false FAIL are different failures.

    Three devices genuinely fail; the system catches two and never claims a
    failure that is not there. Recall suffers, precision does not.
    """
    metrics = verdict_metrics(
        [
            verdict(Verdict.FAIL, Verdict.FAIL),
            verdict(Verdict.FAIL, Verdict.FAIL),
            verdict(Verdict.FAIL, Verdict.UNKNOWN),
        ],
        "v",
    )

    assert metrics.precision(Verdict.FAIL) == 1.0
    assert metrics.recall(Verdict.FAIL) == 2 / 3


def test_an_unexercised_class_is_reported_as_such_not_as_zero() -> None:
    """An absent row reads as a clean result. It means nobody tested the class."""
    metrics = verdict_metrics([verdict(Verdict.PASS, Verdict.PASS)], "v")

    assert metrics.exercised(Verdict.PASS) is True
    assert metrics.exercised(Verdict.FAIL) is False
    assert metrics.recall(Verdict.FAIL) is None


def test_agreement_counts_only_the_diagonal() -> None:
    metrics = verdict_metrics(
        [
            verdict(Verdict.PASS, Verdict.PASS),
            verdict(Verdict.FAIL, Verdict.UNKNOWN),
        ],
        "v",
    )
    assert metrics.agreement == 0.5


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detection(detected: str | None, reason: str = "identified") -> DetectionObservation:
    return DetectionObservation(
        corpus_path="constructed/eval/device.cfg",
        expected_vendor="cisco",
        detected_vendor=detected,
        outcome_reason=reason,
    )


def test_detection_keeps_the_two_abstention_reasons_apart() -> None:
    """Thin evidence and genuine ambiguity say different things.

    The first means the signature set is sparse; the second means two platforms
    look alike and need a discriminating pattern rather than more patterns.
    """
    metrics = detection_metrics(
        [
            detection("cisco"),
            detection(None, "below_threshold"),
            detection(None, "ambiguous"),
            detection("arista"),
        ]
    )

    assert metrics.correct == 1
    assert metrics.wrong == 1
    assert metrics.abstained == 2
    assert metrics.reasons == {"ambiguous": 1, "below_threshold": 1}


def test_a_wrong_detection_is_not_an_abstention() -> None:
    metrics = detection_metrics([detection("juniper")])
    assert (metrics.correct, metrics.wrong, metrics.abstained) == (0, 1, 0)
    assert metrics.accuracy == 0.0
