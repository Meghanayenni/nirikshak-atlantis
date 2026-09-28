"""The posture roll-up and the gate in front of it (ADR 0068), without a database.

The roll-up is a table, so it is tested as one: any FAIL violates the control;
every PASS satisfies it only when at least one mapping tests the whole control,
and otherwise means no violation was found; anything else — UNKNOWN,
NOT_APPLICABLE, no verdict — leaves it undetermined.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace

import pytest
import yaml

from api.comply.frameworks import FRAMEWORK_INDEX_ROOT, indexes
from api.comply.posture import (
    RERUN_REQUIRED_MESSAGE,
    REVIEW_PENDING_MESSAGE,
    catalog_basis,
    decide_gate,
    framework_posture,
    roll_up,
)
from api.comply.rulepacks import load_active_rulepack
from api.models.enums import Framework, MappingCoverage, UnknownReason, Verdict
from api.models.posture import (
    ControlState,
    FrameworkStatus,
    GateState,
    ReviewProgress,
    RuleContribution,
)

RUN = {"audit_id": "aud-1", "evaluated_at": "2026-09-28T10:00:00+00:00"}
EARLIER = "2026-09-28T09:00:00+00:00"
LATER = "2026-09-28T11:00:00+00:00"


FULL, PARTIAL = MappingCoverage.FULL, MappingCoverage.PARTIAL


def c(rule_id: str, verdict: Verdict | None, coverage=PARTIAL) -> RuleContribution:
    return RuleContribution(
        rule_id=rule_id,
        verdict=verdict,
        coverage=coverage,
        coverage_reason="tests part of it" if coverage is PARTIAL else "tests all of it",
        unknown_reason=UnknownReason.NO_MATCH if verdict is Verdict.UNKNOWN else None,
    )


# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------


P, F, U, NA = Verdict.PASS, Verdict.FAIL, Verdict.UNKNOWN, Verdict.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("mapped", "expected"),
    [
        # Any FAIL violates, whatever share of the control the rule tests.
        (((F, PARTIAL),), ControlState.VIOLATED),
        (((F, FULL),), ControlState.VIOLATED),
        (((P, FULL), (F, PARTIAL)), ControlState.VIOLATED),
        (((U, PARTIAL), (F, PARTIAL)), ControlState.VIOLATED),
        # Every PASS: satisfied only with a full mapping among them.
        (((P, FULL),), ControlState.SATISFIED),
        (((P, FULL), (P, PARTIAL)), ControlState.SATISFIED),
        (((P, PARTIAL),), ControlState.NO_VIOLATION_FOUND),
        (((P, PARTIAL), (P, PARTIAL)), ControlState.NO_VIOLATION_FOUND),
        # Otherwise undetermined — a full mapping does not rescue an abstention.
        (((P, FULL), (U, PARTIAL)), ControlState.UNDETERMINED),
        (((U, FULL),), ControlState.UNDETERMINED),
        (((P, PARTIAL), (NA, PARTIAL)), ControlState.UNDETERMINED),
        (((P, FULL), (None, PARTIAL)), ControlState.UNDETERMINED),
    ],
)
def test_the_roll_up_table(mapped: tuple, expected: ControlState) -> None:
    contributions = tuple(c(f"R-{i}", v, cov) for i, (v, cov) in enumerate(mapped))
    assert roll_up("X-01", contributions).state is expected


def test_a_partial_pass_says_it_is_not_a_satisfied_control() -> None:
    control = roll_up("X-01", (c("R-1", P),))
    assert "no violation was found, not that it is met" in control.reason


def test_an_undetermined_control_names_why_each_check_did_not_pass() -> None:
    control = roll_up("X-01", (c("R-1", Verdict.PASS), c("R-2", Verdict.UNKNOWN)))
    assert "R-2 is UNKNOWN (no_match)" in control.reason
    assert "R-1" not in control.reason


# ---------------------------------------------------------------------------
# One framework, over the real rulepack
# ---------------------------------------------------------------------------

IOS_XE_17 = ("cisco", "ios", "17.9")


def _findings(verdicts: dict[str, Verdict], default: Verdict = Verdict.PASS) -> dict:
    """Duck-typed findings: the roll-up reads status, id, reasons and evidence only."""
    out = {}
    for rule in load_active_rulepack().rules:
        status = verdicts.get(rule.rule_id, default)
        out[rule.rule_id] = SimpleNamespace(
            status=status,
            finding_id=f"fnd-{rule.rule_id}",
            unknown_reason=UnknownReason.CAPABILITY_UNKNOWN if status is Verdict.UNKNOWN else None,
            absence_reason=None,
            evidence=(),
        )
    return out


def _posture(framework: Framework, findings: dict, platform=IOS_XE_17, selection=None):
    return framework_posture(
        framework,
        indexes()[framework],
        load_active_rulepack().rules,
        findings,
        *platform,
        selection,
    )


def test_every_nist_mapping_is_partial_so_nothing_nist_is_fully_satisfied() -> None:
    """Every NIST control is broader than one configuration check (ADR 0068).

    With every rule passing, NIST reports no violation found on all ten
    controls and fully satisfies none — the figure an auditor can defend.
    """
    posture = _posture(Framework.NIST, _findings({}))
    assert posture.assessed == 10
    assert (posture.satisfied, posture.no_violation_found) == (0, 10)


def test_undetermined_and_partial_passes_count_against_the_headline() -> None:
    # CIS on an IOS XE 17 device: five of six mappings are full. The password
    # rule does not map to CIS; make the SSH rule abstain instead.
    posture = _posture(Framework.CIS, _findings({"NRK-SSH-001": Verdict.UNKNOWN}))
    assert posture.assessed == 6
    assert posture.undetermined == 1  # 2.1.1.2
    assert posture.no_violation_found == 1  # 1.2.2, a partial mapping
    assert posture.satisfied == 4
    assert not hasattr(posture, "headline_percent")


def test_every_shipped_mapping_states_its_coverage_in_our_words() -> None:
    for rule in load_active_rulepack().rules:
        for ref in rule.frameworks:
            assert ref.coverage_reason, f"{rule.rule_id} -> {ref.control_id} has no reason"
            assert len(ref.coverage_reason) <= 600


def test_a_declined_mapping_never_contributes() -> None:
    """NRK-TIMEOUT-001 declines the STIG. Failing it must not touch any STIG control."""
    rule = load_active_rulepack().rule("NRK-TIMEOUT-001")
    assert rule is not None and rule.gap_reason(Framework.STIG)

    findings = _findings({"NRK-TIMEOUT-001": Verdict.FAIL})
    stig = _posture(Framework.STIG, findings)
    assert stig.violated == 0
    assert all(
        "NRK-TIMEOUT-001" not in {r.rule_id for r in control.rules} for control in stig.controls
    )
    # ... while the framework it does map to sees the failure.
    cis = _posture(Framework.CIS, findings)
    violated = [ctl.control_id for ctl in cis.controls if ctl.state is ControlState.VIOLATED]
    assert violated == ["1.2.8"]


def test_a_framework_that_does_not_describe_the_device_is_not_applicable_not_zero() -> None:
    posture = _posture(Framework.STIG, _findings({}), platform=("cisco", "ios", "15.2"))
    assert posture.status is FrameworkStatus.NOT_APPLICABLE
    assert "does not describe" in posture.reason
    assert posture.satisfied == 0 and posture.controls == ()
    assert posture.assessed == 0 and posture.controls == ()


def test_a_run_scoped_elsewhere_leaves_a_framework_out_of_scope() -> None:
    posture = _posture(Framework.NIST, _findings({}), selection=frozenset({Framework.STIG}))
    assert posture.status is FrameworkStatus.NOT_IN_SCOPE
    assert posture.satisfied == 0 and posture.controls == ()


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("framework", [Framework.NIST, Framework.STIG, Framework.CIS])
def test_the_catalog_total_is_derived_from_the_pinned_index(framework: Framework) -> None:
    index = indexes()[framework]
    path = next(
        p
        for p in FRAMEWORK_INDEX_ROOT.glob("*.index.yaml")
        if yaml.safe_load(p.read_text(encoding="utf-8"))["framework"] == framework.value
    )
    controls = yaml.safe_load(path.read_text(encoding="utf-8"))["controls"]
    total, basis = catalog_basis(index)
    assert total == len(controls) == index.control_count
    assert str(total) in basis


def test_the_held_stig_says_where_its_total_was_read() -> None:
    _, basis = catalog_basis(indexes()[Framework.STIG])
    assert "held in this repository" in basis
    _, basis = catalog_basis(indexes()[Framework.CIS])
    assert "not held in this repository" in basis


def test_a_total_that_cannot_be_derived_is_null_with_a_reason() -> None:
    empty = SimpleNamespace(control_count=0, document="Some benchmark", held_at="", sha256="0" * 64)
    total, basis = catalog_basis(empty)  # type: ignore[arg-type]
    assert total is None
    assert "no total can be derived" in basis


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def gate(**kwargs):
    base = dict(
        run=RUN,
        platform_identified=True,
        review=ReviewProgress(reviewed=0, total=0),
        last_decision_at=None,
        is_admin=True,
    )
    return decide_gate(**{**base, **kwargs})


def test_no_run_is_not_audited() -> None:
    assert gate(run=None).state is GateState.NOT_AUDITED


def test_an_unidentified_platform_is_not_audited_and_names_the_bootstrap_page() -> None:
    result = gate(platform_identified=False)
    assert result.state is GateState.NOT_AUDITED
    assert "bootstrap" in result.next_step


def test_an_undecided_entry_holds_review_pending_with_counts() -> None:
    result = gate(review=ReviewProgress(reviewed=31, total=48))
    assert result.state is GateState.REVIEW_PENDING
    assert result.message == REVIEW_PENDING_MESSAGE
    assert (result.review.reviewed, result.review.total) == (31, 48)


def test_a_non_admin_is_told_an_administrator_must_review() -> None:
    result = gate(review=ReviewProgress(reviewed=0, total=3), is_admin=False)
    assert result.next_step == "An administrator must complete the review."


def test_a_decision_newer_than_the_run_requires_a_rerun() -> None:
    result = gate(review=ReviewProgress(reviewed=5, total=5), last_decision_at=LATER)
    assert result.state is GateState.RERUN_REQUIRED
    assert result.message == RERUN_REQUIRED_MESSAGE


def test_a_run_newer_than_every_decision_is_ready() -> None:
    assert gate(review=ReviewProgress(reviewed=5, total=5), last_decision_at=EARLIER).state is (
        GateState.READY
    )
    assert gate().state is GateState.READY  # nothing was left unrecognised


def test_the_gate_has_no_input_for_browser_review_marks() -> None:
    """Remediation review marks live in localStorage; the gate cannot see them."""
    assert set(inspect.signature(decide_gate).parameters) == {
        "run",
        "platform_identified",
        "review",
        "last_decision_at",
        "is_admin",
        "reserved_split",
    }


def test_a_file_reserved_for_measurement_is_never_scored() -> None:
    """DEF-16 — even fully reviewed and current, an evaluation file is not scored."""
    result = gate(
        review=ReviewProgress(reviewed=5, total=5),
        last_decision_at=EARLIER,
        reserved_split="evaluation",
    )
    assert result.state is GateState.EVALUATION_FILE
    assert result.message == (
        "Reserved for measurement — scored by the evaluation harness, not reviewed."
    )
    assert result.review is None
