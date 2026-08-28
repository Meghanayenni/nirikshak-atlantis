"""The ground-truth label contract (P9, decision D31).

    A label is authored from the configuration, never from parser output.

The contract is where that stops being a promise. These tests check the two
things a type can enforce: that there is nowhere to write a prediction, and that
a label cannot make a claim it does not support.

The third thing — that the person writing the label did not peek at the
parser — no type can enforce. That is what `pattern_author_conflict` and
`review_status` exist to report rather than prevent.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.models.enums import Verdict
from api.models.label import (
    Determinability,
    FieldLabel,
    FileLabels,
    LabelProvenance,
    ReviewStatus,
    VerdictLabel,
)

WHEN = "2026-08-28T00:00:00Z"


def provenance(**overrides: object) -> LabelProvenance:
    base: dict[str, object] = {
        "labelled_by": "a-person",
        "labelled_at": WHEN,
        "authored_from": "corpus/cisco/eval/device.cfg (raw configuration text)",
    }
    base.update(overrides)
    return LabelProvenance(**base)  # type: ignore[arg-type]


def determinable(**overrides: object) -> FieldLabel:
    base: dict[str, object] = {
        "field": "ssh_version",
        "determinability": Determinability.DETERMINABLE,
        "expected_value": 2,
        "evidence_line": 8,
        "evidence_text": "ip ssh version 2",
        "rationale": "The version is stated explicitly.",
    }
    base.update(overrides)
    return FieldLabel(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A label cannot hold a prediction
# ---------------------------------------------------------------------------


def test_no_field_can_carry_parser_output() -> None:
    """Extra keys are forbidden, so a prediction cannot be smuggled in."""
    with pytest.raises(ValidationError):
        FieldLabel(
            field="ssh_version",
            determinability=Determinability.DETERMINABLE,
            expected_value=2,
            evidence_line=8,
            evidence_text="ip ssh version 2",
            rationale="stated",
            predicted_value=2,  # type: ignore[call-arg]
        )


def test_a_label_must_explain_itself() -> None:
    """A rationale is what makes the judgement reviewable by someone else."""
    with pytest.raises(ValidationError):
        FieldLabel(
            field="ssh_version",
            determinability=Determinability.NOT_DETERMINABLE,
            rationale="",
        )


def test_the_rationale_is_capped_so_it_stays_a_reason() -> None:
    with pytest.raises(ValidationError):
        determinable(rationale="x" * 601)


# ---------------------------------------------------------------------------
# A label cannot claim more than it supports
# ---------------------------------------------------------------------------


def test_a_not_determinable_field_may_not_carry_a_value() -> None:
    """If a value can be stated, the field was determinable.

    Allowing both would let a labeller hedge — recording an answer while
    declining to be scored on it.
    """
    with pytest.raises(ValidationError, match="not determinable but carries an expected value"):
        FieldLabel(
            field="ssh_version",
            determinability=Determinability.NOT_DETERMINABLE,
            expected_value=2,
            rationale="hedging",
        )


def test_a_not_determinable_field_may_not_cite_a_line() -> None:
    """A citation is a claim that the file establishes the value."""
    with pytest.raises(ValidationError, match="not determinable but cites a line"):
        FieldLabel(
            field="ssh_version",
            determinability=Determinability.NOT_DETERMINABLE,
            evidence_line=8,
            evidence_text="ip ssh version 2",
            rationale="contradictory",
        )


def test_half_a_citation_is_refused() -> None:
    """A line number without its text cannot be checked against the file."""
    with pytest.raises(ValidationError, match="half an evidence pointer"):
        determinable(evidence_text=None)

    with pytest.raises(ValidationError, match="half an evidence pointer"):
        determinable(evidence_line=None)


def test_absence_is_a_legitimate_reading_with_no_line() -> None:
    """A banner that is not configured has no line to point at.

    This is the case that makes `cites_a_line` necessary: the evidence-integrity
    metric must exclude it rather than count it as a missing citation.
    """
    label = FieldLabel(
        field="banner_present",
        determinability=Determinability.DETERMINABLE,
        expected_value=False,
        rationale="The file contains no banner directive of any kind.",
    )

    assert label.is_determinable
    assert not label.cites_a_line


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_a_review_needs_a_named_reviewer() -> None:
    """An anonymous review is not a review."""
    with pytest.raises(ValidationError, match="naming the reviewer"):
        provenance(review_status=ReviewStatus.REVIEWED)


def test_a_reviewer_without_a_review_status_is_refused() -> None:
    with pytest.raises(ValidationError, match="not marked reviewed"):
        provenance(reviewed_by="someone")


def test_a_declared_conflict_must_explain_itself() -> None:
    """A reader discounting a number needs to know by how much and why."""
    with pytest.raises(ValidationError, match="must explain itself"):
        provenance(pattern_author_conflict=True)


def test_independence_requires_both_review_and_no_conflict() -> None:
    """Either condition alone leaves the ground truth correlated or unchecked."""
    unreviewed = provenance()
    assert not unreviewed.is_independent

    reviewed_but_conflicted = provenance(
        review_status=ReviewStatus.REVIEWED,
        reviewed_by="second-person",
        reviewed_at=WHEN,
        pattern_author_conflict=True,
        conflict_note="same author wrote the patterns",
    )
    assert not reviewed_but_conflicted.is_independent

    fully_independent = provenance(
        review_status=ReviewStatus.REVIEWED,
        reviewed_by="second-person",
        reviewed_at=WHEN,
    )
    assert fully_independent.is_independent


def test_provenance_records_where_the_labeller_looked() -> None:
    """`authored_from` names the artefact read, so a reviewer can repeat it."""
    assert "raw configuration" in provenance().authored_from


# ---------------------------------------------------------------------------
# The file-level contract
# ---------------------------------------------------------------------------


def labels(**overrides: object) -> FileLabels:
    base: dict[str, object] = {
        "corpus_path": "cisco/eval/device.cfg",
        "split": "eval",
        "vendor": "cisco",
        "os_family": "ios",
        "file_sha256": "a" * 64,
        "provenance": provenance(),
        "fields": (determinable(),),
    }
    base.update(overrides)
    return FileLabels(**base)  # type: ignore[arg-type]


def test_only_evaluation_files_may_be_labelled() -> None:
    """Ground truth beside the files patterns are authored from is an invitation."""
    with pytest.raises(ValidationError, match="split"):
        labels(split="dev")

    with pytest.raises(ValidationError, match="split"):
        labels(split="holdout")


def test_a_duplicate_field_label_is_refused() -> None:
    """Two answers for one field is not ground truth."""
    with pytest.raises(ValidationError, match="duplicate label for field"):
        labels(fields=(determinable(), determinable()))


def test_a_duplicate_verdict_label_is_refused() -> None:
    twice = VerdictLabel(rule_id="NRK-SSH-001", expected_verdict=Verdict.PASS, rationale="stated")
    with pytest.raises(ValidationError, match="duplicate label for rule"):
        labels(verdicts=(twice, twice))


def test_the_checksum_must_look_like_one() -> None:
    with pytest.raises(ValidationError):
        labels(file_sha256="not-a-hash")


def test_labels_must_not_be_empty() -> None:
    """A label file that labels nothing would score nothing while looking present."""
    with pytest.raises(ValidationError):
        labels(fields=())


def test_determinable_and_not_determinable_partition_the_fields() -> None:
    both = labels(
        fields=(
            determinable(),
            FieldLabel(
                field="aaa_enabled",
                determinability=Determinability.NOT_DETERMINABLE,
                rationale="No aaa directive appears.",
            ),
        )
    )

    assert len(both.determinable) == 1
    assert len(both.not_determinable) == 1
    assert len(both.determinable) + len(both.not_determinable) == len(both.fields)


def test_a_label_is_immutable_once_built() -> None:
    """Ground truth that could be edited in flight is not a reference."""
    built = labels()
    with pytest.raises(ValidationError):
        built.file_sha256 = "b" * 64  # type: ignore[misc]
