"""The evaluation harness end to end, against the real corpus (P9).

These run the shipped pipeline over the labelled evaluation split and check the
harness reports it honestly. The assertions fall into three groups:

  * **the labels agree with the files** — every citation resolves, every
    checksum matches, nothing is labelled outside the evaluation split;
  * **the numbers are what they are** — the measurements are asserted at their
    real values, so a change in parser behaviour shows up here as a diff rather
    than passing silently;
  * **the report does not oversell** — no pooled recall, no real-world claim, no
    unexercised class rendered as a zero, and the holdout untouched.

The third group is the reason this file exists. A harness that measures
correctly and then reports flatteringly has failed at the only thing it does.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.models.enums import Verdict
from eval.corpus import CORPUS_ROOT, load_manifest, scoreable_entries
from eval.errors import LabelIntegrityError, SealedSplitError
from eval.labels import load_label_file, load_labels, verify_against_configuration
from eval.metrics import EvidenceOutcome, by_vendor, field_metrics, verdict_metrics
from eval.report import render
from eval.score import score_all

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def run():
    return score_all()


@pytest.fixture(scope="module")
def report(run) -> str:
    return render(run)


# ---------------------------------------------------------------------------
# The labels agree with the configurations
# ---------------------------------------------------------------------------


def test_every_label_loads_and_verifies() -> None:
    """Citations resolve, checksums match, contracts hold."""
    labels = load_labels()
    assert len(labels) == 4


def test_every_labelled_file_is_in_the_evaluation_split() -> None:
    labels = load_labels()
    scoreable = {e.path for e in scoreable_entries()}
    assert {label.corpus_path for label in labels} == scoreable


def test_the_manifest_labelled_flag_matches_the_filesystem() -> None:
    """DEF-6 — the flag claimed labels that did not exist and nothing checked it."""
    labelled = {label.corpus_path for label in load_labels()}
    for entry in load_manifest():
        assert entry.labelled == (entry.path in labelled), (
            f"{entry.path} declares labelled={entry.labelled} but "
            f"{'has' if entry.path in labelled else 'has no'} label file"
        )


def test_a_drifted_citation_is_refused(tmp_path: Path) -> None:
    """The check that makes a citation worth requiring.

    A label pointing at line 8 and quoting text that is not on line 8 has come
    adrift from the file, and any metric computed from it describes nothing.
    """
    source = next(p for p in sorted((CORPUS_ROOT / "labels").glob("*.yaml")))
    labels = load_label_file(source)
    entry = next(e for e in load_manifest() if e.path == labels.corpus_path)

    cited = next(f for f in labels.fields if f.cites_a_line)
    broken = labels.model_copy(
        update={
            "fields": tuple(
                f.model_copy(update={"evidence_text": "a line the file does not contain"})
                if f is cited
                else f
                for f in labels.fields
            )
        }
    )

    with pytest.raises(LabelIntegrityError, match="drifted"):
        verify_against_configuration(broken, entry)


def test_a_stale_checksum_is_refused() -> None:
    """A configuration edited after labelling must not be scored silently."""
    labels = load_labels()[0]
    entry = next(e for e in load_manifest() if e.path == labels.corpus_path)
    stale = labels.model_copy(update={"file_sha256": "0" * 64})

    with pytest.raises(LabelIntegrityError, match="changed after it was labelled"):
        verify_against_configuration(stale, entry)


def test_the_labels_describe_the_files_actually_on_disk() -> None:
    """Belt and braces: recompute every checksum independently of the loader."""
    for labels in load_labels():
        path = CORPUS_ROOT / labels.corpus_path
        assert hashlib.sha256(path.read_bytes()).hexdigest() == labels.file_sha256


# ---------------------------------------------------------------------------
# The holdout stays sealed through a full run
# ---------------------------------------------------------------------------


def test_a_full_run_never_touches_the_holdout(run) -> None:
    scored = set(run.files_scored)
    sealed = {e.path for e in load_manifest() if e.is_sealed}

    assert scored & sealed == set()
    assert len(scored) == 4


def test_the_sealed_files_are_unreadable_through_the_harness() -> None:
    from eval.corpus import read_configuration

    for entry in load_manifest():
        if entry.is_sealed:
            with pytest.raises(SealedSplitError):
                read_configuration(entry)


def test_no_development_file_is_scored(run) -> None:
    dev = {e.path for e in load_manifest() if e.split == "dev"}
    assert set(run.files_scored) & dev == set()


# ---------------------------------------------------------------------------
# The measurements, at their real values
# ---------------------------------------------------------------------------


def test_vendor_detection_is_correct_on_every_scored_file(run) -> None:
    from eval.metrics import detection_metrics

    metrics = detection_metrics(run.detections)
    assert metrics.total == 4
    assert metrics.correct == 4
    assert metrics.wrong == 0


def test_cisco_field_extraction(run) -> None:
    """Asserted at real values so a parser regression shows up as a diff."""
    cisco = field_metrics(by_vendor(run.fields)["cisco"], "cisco")

    assert cisco.total == 26
    assert cisco.correct == 11
    assert cisco.wrong_confident == 0
    assert cisco.miss == 4
    assert cisco.correct_abstention == 11
    assert cisco.precision == 1.0
    assert cisco.recall == pytest.approx(11 / 15)


def test_the_wrong_confident_rate_is_zero_across_every_vendor(run) -> None:
    """The safety metric. Near zero is required; zero is what we have.

    It is not evidence of accuracy — see the miss counts — but a non-zero value
    here would be the most serious result the harness could produce.
    """
    for vendor, observations in by_vendor(run.fields).items():
        metrics = field_metrics(observations, vendor)
        assert metrics.wrong_confident == 0, f"{vendor} asserted a wrong value"


def test_detection_only_vendors_produce_no_correct_field(run) -> None:
    """Honest, and the reason D34 forbids pooling them into one recall figure."""
    for vendor in ("arista", "juniper"):
        metrics = field_metrics(by_vendor(run.fields)[vendor], vendor)
        assert metrics.correct == 0
        assert metrics.recall == 0.0
        assert metrics.miss > 0, "a human could read some of these fields"


def test_evidence_integrity_is_perfect_where_it_could_be_checked(run) -> None:
    """Every value Cisco asserted cited the line the labeller read."""
    cisco = field_metrics(by_vendor(run.fields)["cisco"], "cisco")

    assert cisco.evidence_scored == 11
    assert cisco.evidence_correct == 11
    assert cisco.evidence_wrong_line == 0
    assert cisco.evidence_missing == 0
    assert cisco.evidence_integrity == 1.0


def test_evidence_is_not_scored_where_no_line_could_be_cited(run) -> None:
    """A label resting on absence is excluded, not failed."""
    absence_backed = [
        o
        for o in run.fields
        if o.labelled_line is None and o.evidence is not EvidenceOutcome.NOT_SCORED
    ]
    assert absence_backed == []


def test_the_fail_class_is_now_exercised(run) -> None:
    """D32 — the whole reason sw-dist-11.cfg was added.

    Before it the evaluation split held no FAIL at all, so FAIL precision and
    recall were undefined for the class that matters most.
    """
    cisco = verdict_metrics([v for v in run.verdicts if v.vendor == "cisco"], "cisco")

    assert cisco.exercised(Verdict.FAIL)
    assert cisco.expected_total(Verdict.FAIL) == 6
    assert cisco.precision(Verdict.FAIL) == 1.0
    assert cisco.recall(Verdict.FAIL) == 0.5


def test_missed_failures_are_counted_as_unknown_not_as_passes(run) -> None:
    """The failure mode that would matter most.

    A FAIL the system reports as PASS is a device presented as compliant when it
    is not. A FAIL reported as UNKNOWN is an honest gap. The distinction must
    hold, and here it does: every missed failure abstained.
    """
    missed = [v for v in run.verdicts if v.expected is Verdict.FAIL and not v.agrees]

    assert missed, "this corpus should contain missed failures"
    assert all(v.actual is Verdict.UNKNOWN for v in missed)


def test_no_verdict_is_asserted_against_the_label(run) -> None:
    """No PASS where a human read a FAIL, and no FAIL where a human read a PASS."""
    contradictions = [
        v
        for v in run.verdicts
        if v.expected in (Verdict.PASS, Verdict.FAIL)
        and v.actual in (Verdict.PASS, Verdict.FAIL)
        and not v.agrees
    ]
    assert contradictions == []


def test_the_absence_branch_never_evaluates_a_documented_default(run) -> None:
    """Zero platform defaults ship, so the EVALUATE branch cannot have fired."""
    assert "absent_default" not in run.absence_branches
    assert run.absence_branches.get("unknown", 0) > 0


# ---------------------------------------------------------------------------
# The report does not oversell
# ---------------------------------------------------------------------------


def test_the_report_says_the_corpus_is_synthetic(report: str) -> None:
    assert "SYNTHETIC" in report
    assert "NOT real-world accuracy" in report


def test_every_mention_of_real_world_accuracy_is_a_denial(report: str) -> None:
    """The phrase appears in the report - always inside a refusal.

    A line either negates it outright, or sits under the heading that negates
    every bullet beneath it. Both are denials, and a substring search cannot
    tell either of them from a claim, so the section context is tracked.
    """
    disclaimer = "WHAT THIS REPORT DOES NOT CLAIM"
    in_disclaimer = False
    mentions = 0

    for line in report.splitlines():
        if disclaimer in line.upper():
            in_disclaimer = True
        if "real-world" not in line.lower():
            continue
        mentions += 1
        lowered = line.lower()
        assert "not" in lowered or "never" in lowered or in_disclaimer, (
            f"unqualified claim: {line!r}"
        )

    assert mentions >= 2, "the report should address real-world accuracy explicitly"


def test_the_report_makes_no_affirmative_accuracy_boast(report: str) -> None:
    """Wording that would turn a measurement into a claim.

    Matched on whole words: `proven` is a substring of `provenance`, which the
    report says a great deal about and must go on saying.
    """
    import re

    for word in ("achieves", "proven", "flawless", "robust", "reliable"):
        assert not re.search(rf"{word}", report, re.IGNORECASE), f"the report boasts: {word!r}"


def test_the_report_never_calls_its_labels_independent_ground_truth(report: str) -> None:
    """D35 — every label is unreviewed and the Cisco ones share an author."""
    assert "NOT INDEPENDENT GROUND TRUTH" in report
    assert "Independently reviewed labels: 0 of 4" in report


def test_the_report_flags_the_authorship_conflict(report: str) -> None:
    assert "PATTERN AUTHOR" in report
    assert report.count("PATTERN AUTHOR") == 2, "both Cisco files should carry the flag"


def test_the_report_separates_pack_bearing_from_detection_only(report: str) -> None:
    """D34 — no pooled recall figure appears anywhere."""
    assert "NEVER pooled" in report
    for vendor in ("cisco", "arista", "juniper"):
        assert vendor in report


def test_the_report_states_the_holdout_was_not_read(report: str) -> None:
    assert "NOT READ" in report
    assert "SEALED" in report


def test_the_report_states_generalisation_and_calibration_are_blocked(report: str) -> None:
    """D33, then D37 and D42 — never a zero, always a reason.

    P9 said "deferred to P10". P10 arrived, built the similarity layer, and found
    the metric blocked underneath for a different reason entirely. The report now
    names that reason rather than pointing at a phase that has been and gone.
    """
    assert "NOT MEASURED — BLOCKED" in report
    assert "NOT FITTED — decision D42" in report
    assert "UNCALIBRATED_SIMILARITY" in report
    assert "NOT opened at any point during this run" in report

    # A blocked metric must never render as a number.
    assert "top-3 mapping accuracy   NOT MEASURED" in report


def test_the_report_qualifies_the_zero_wrong_confident_rate(report: str) -> None:
    """A zero must not read as a clean bill of health."""
    assert "A zero here is NOT evidence of accuracy" in report


def test_the_report_prints_denominators_with_its_rates(report: str) -> None:
    """A rate without its sample size invites the reader to assume a big one."""
    assert "100.0% / 11" in report
    assert "Rates print as percentage / denominator" in report


def test_the_report_marks_an_unexercised_class_rather_than_blanking_it(report: str) -> None:
    assert "not exercised" in report


def test_the_report_is_deterministic_apart_from_its_timestamp(run) -> None:
    """Two runs over unchanged inputs must be diffable."""
    first = [ln for ln in render(run).splitlines() if not ln.startswith("Generated")]
    second = [ln for ln in render(run).splitlines() if not ln.startswith("Generated")]
    assert first == second


def test_the_report_names_no_framework_or_remediation_coverage(report: str) -> None:
    """Nothing here may imply coverage the project does not have."""
    assert "framework coverage       not measured" in report
    assert "remediation coverage     not measured" in report
