"""The verdict table — every path from a canonical field state to a verdict.

One test per row, named for the row it pins.

    CSM field state       policy consulted         verdict
    ----------------------------------------------------------------
    PRESENT               —                        PASS / FAIL
    ABSENT_DEFAULT        on_absent_default        per policy
    ABSENT_UNSUPPORTED    on_absent_unsupported    per policy
    UNKNOWN               on_capability_unknown    UNKNOWN, always
    key absent            —                        UNKNOWN · no_match
    rule not applicable   —                        no finding at all

The ABSENT_DEFAULT row can only be reached with a synthetic pack: no vendor
documentation has been sourced, so no shipped pack produces that state. The test
says so where it is asserted, rather than leaving a reader to assume the corpus
covers it.
"""

from __future__ import annotations

from typing import Any

import pytest

from api.comply.engine import evaluate_device
from api.models.csm import CanonicalSecurityModel, CsmSource, DeviceIdentity
from api.models.enums import (
    AbsenceAction,
    ConditionOp,
    ConfidenceMethod,
    FieldState,
    PackStatus,
    Severity,
    SourceType,
    UnknownReason,
    Verdict,
)
from api.models.evidence import Evidence
from api.models.field import Field
from api.models.rule import (
    AbsencePolicy,
    AppliesTo,
    CheckSpec,
    ComplianceRule,
    Condition,
    Rulepack,
)

FIELD = "telnet_enabled"
AUDIT = "audit-1"


def evidence(line: int = 17) -> Evidence:
    return Evidence(
        file_id="f1",
        file_path="rtr.cfg",
        line_start=line,
        line_end=line,
        raw_line="transport input telnet ssh",
        source_type=SourceType.CLI,
    )


def rule(**kw: Any) -> ComplianceRule:
    base: dict[str, Any] = {
        "rule_id": "NRK-TEST-001",
        "title": "Telnet disabled",
        "severity": Severity.CRITICAL,
        "rationale": "Telnet carries credentials in plaintext.",
        "check": CheckSpec(field=FIELD, condition=Condition(op=ConditionOp.IS_FALSE)),
    }
    base.update(kw)
    return ComplianceRule(**base)


def pack(*rules: ComplianceRule) -> Rulepack:
    return Rulepack(
        rulepack_id="test", version="1.0.0", status=PackStatus.ACTIVE, rules=tuple(rules)
    )


def csm_with(field: Field[Any] | None, *, vendor: str = "cisco", os_family: str = "ios"):
    return CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1", vendor=vendor, os_family=os_family),
        source=CsmSource(file_ids=("f1",), pack_versions={"cisco": "1.1.0"}),
        fields={FIELD: field} if field is not None else {},
    )


def only(csm, rp):
    findings = evaluate_device(csm, rp, audit_id=AUDIT)
    assert len(findings) == 1
    return findings[0]


# ---------------------------------------------------------------------------
# Row 1 — PRESENT
# ---------------------------------------------------------------------------


def present(value: Any) -> Field[Any]:
    return Field[Any](
        value=value,
        state=FieldState.PRESENT,
        confidence=1.0,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
        evidence=(evidence(),),
    )


def test_row_present_satisfying_the_condition_passes() -> None:
    finding = only(csm_with(present(False)), pack(rule()))

    assert finding.status is Verdict.PASS
    assert finding.evidence, "a PASS must carry the line it rests on (Rule 2)"
    assert finding.unknown_reason is None


def test_row_present_violating_the_condition_fails() -> None:
    finding = only(csm_with(present(True)), pack(rule()))

    assert finding.status is Verdict.FAIL
    assert [e.line_start for e in finding.evidence] == [17]
    assert finding.observed.value is True


# ---------------------------------------------------------------------------
# Row 2 — ABSENT_DEFAULT (synthetic only; no sourced defaults ship)
# ---------------------------------------------------------------------------


def absent_default(value: Any) -> Field[Any]:
    return Field[Any](
        value=value,
        state=FieldState.ABSENT_DEFAULT,
        confidence=0.95,
        confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        default_ref="testvendor/testos — TestOS Guide (fictional), §4.2",
    )


def test_row_absent_default_evaluates_against_the_default() -> None:
    """Reachable only with a synthetic field: no shipped pack sources a default."""
    finding = only(csm_with(absent_default(False)), pack(rule()))

    assert finding.status is Verdict.PASS
    assert finding.evidence == (), "there is no configuration line — that is the premise"
    assert finding.absence_reason, "so the citation must carry the justification instead"


def test_row_absent_default_can_be_overridden_to_fail() -> None:
    r = rule(absence_policy=AbsencePolicy(on_absent_default=AbsenceAction.FAIL))
    finding = only(csm_with(absent_default(False)), pack(r))

    assert finding.status is Verdict.FAIL
    assert finding.absence_reason


# ---------------------------------------------------------------------------
# Row 3 — ABSENT_UNSUPPORTED
# ---------------------------------------------------------------------------


def absent_unsupported() -> Field[Any]:
    return Field[Any](
        value=None,
        state=FieldState.ABSENT_UNSUPPORTED,
        confidence=0.95,
        confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        default_ref="testvendor/testos — TestOS Guide (fictional), §1.1",
    )


def test_row_absent_unsupported_is_not_applicable_by_default() -> None:
    finding = only(csm_with(absent_unsupported()), pack(rule()))

    assert finding.status is Verdict.NOT_APPLICABLE
    assert finding.unknown_reason is None


# ---------------------------------------------------------------------------
# Row 4 — UNKNOWN, always
# ---------------------------------------------------------------------------


def unknown(reason: UnknownReason) -> Field[Any]:
    return Field[Any].unknown(reason, confidence_method=ConfidenceMethod.DETERMINISTIC)


def test_row_capability_unknown_abstains() -> None:
    """The row carrying almost all real traffic: no defaults ship."""
    finding = only(csm_with(unknown(UnknownReason.CAPABILITY_UNKNOWN)), pack(rule()))

    assert finding.status is Verdict.UNKNOWN
    assert finding.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
    assert finding.remediation is None, "we do not know there is anything to fix"


@pytest.mark.parametrize(
    "reason",
    [
        UnknownReason.CAPABILITY_UNKNOWN,
        UnknownReason.NO_MATCH,
        UnknownReason.CONFLICTING_EVIDENCE,
        UnknownReason.LOW_CONFIDENCE,
    ],
)
def test_no_abstention_reason_can_produce_a_verdict(reason: UnknownReason) -> None:
    finding = only(csm_with(unknown(reason)), pack(rule()))

    assert finding.status is Verdict.UNKNOWN
    assert finding.unknown_reason is reason


def test_an_abstention_keeps_the_citations_it_had() -> None:
    """A conflicting-evidence field carries the lines that show the conflict."""
    conflicted = Field[Any](
        value=None,
        state=FieldState.UNKNOWN,
        confidence=0.0,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
        unknown_reason=UnknownReason.CONFLICTING_EVIDENCE,
        evidence=(evidence(10), evidence(22)),
    )
    finding = only(csm_with(conflicted), pack(rule()))

    assert finding.status is Verdict.UNKNOWN
    assert [e.line_start for e in finding.evidence] == [10, 22]


# ---------------------------------------------------------------------------
# Row 5 — the pack never declared the field
# ---------------------------------------------------------------------------


def test_row_field_absent_from_the_model_abstains_with_no_match() -> None:
    """Different from 'the directive is absent' — the packs cannot read it at all."""
    finding = only(csm_with(None), pack(rule()))

    assert finding.status is Verdict.UNKNOWN
    assert finding.unknown_reason is UnknownReason.NO_MATCH
    assert finding.needs_training, "a parse gap belongs in the P10 training queue"


def test_capability_unknown_does_not_route_to_training() -> None:
    """OBS-1 — no amount of administrator training teaches a vendor's default.

    It needs sourced documentation, which is a different backlog.
    """
    finding = only(csm_with(unknown(UnknownReason.CAPABILITY_UNKNOWN)), pack(rule()))

    assert not finding.needs_training


# ---------------------------------------------------------------------------
# Row 6 — not applicable to this platform
# ---------------------------------------------------------------------------


def test_row_inapplicable_rule_produces_no_finding() -> None:
    """'Never relevant here' is not the same as 'could not determine'."""
    r = rule(applies_to=AppliesTo(vendor=("juniper",), os_family=("junos",)))
    findings = evaluate_device(csm_with(present(False)), pack(r), audit_id=AUDIT)

    assert findings == ()


def test_a_wildcard_rule_applies_everywhere() -> None:
    findings = evaluate_device(
        csm_with(present(False), vendor="arista", os_family="eos"), pack(rule()), audit_id=AUDIT
    )

    assert len(findings) == 1


# ---------------------------------------------------------------------------
# Type mismatch (D18) reaches the finding as its own reason
# ---------------------------------------------------------------------------


def test_a_rule_that_cannot_be_applied_abstains_distinctly() -> None:
    r = rule(check=CheckSpec(field=FIELD, condition=Condition(op=ConditionOp.LTE, value=600)))
    finding = only(csm_with(present(True)), pack(r))

    assert finding.status is Verdict.UNKNOWN
    assert finding.unknown_reason is UnknownReason.RULE_TYPE_MISMATCH
    assert finding.status is not Verdict.FAIL, "a broken rule is not a failing device"


def test_rule_type_mismatch_is_not_a_training_item() -> None:
    """The packs read the field fine. The rule is what is wrong."""
    r = rule(check=CheckSpec(field=FIELD, condition=Condition(op=ConditionOp.LTE, value=600)))
    finding = only(csm_with(present(True)), pack(r))

    assert not finding.needs_training


# ---------------------------------------------------------------------------
# Rule 2 at the engine, not only in the contract
# ---------------------------------------------------------------------------


def test_no_verdict_without_evidence_or_a_citation() -> None:
    """A PRESENT field cannot lack evidence, so this is belt and braces.

    Asserted at the engine anyway: the contract catching it would be a crash,
    and the engine abstaining is a result.
    """
    stateless = Field[Any](
        value=False,
        state=FieldState.ABSENT_DEFAULT,
        confidence=0.95,
        confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        default_ref="x",
    )
    finding = only(csm_with(stateless), pack(rule()))

    assert finding.status is Verdict.PASS
    assert finding.absence_reason == "x"


# ---------------------------------------------------------------------------
# Determinism and provenance
# ---------------------------------------------------------------------------


def test_evaluation_is_deterministic() -> None:
    csm = csm_with(present(True))
    rp = pack(rule(), rule(rule_id="NRK-TEST-002"))

    first = evaluate_device(csm, rp, audit_id=AUDIT)
    second = evaluate_device(csm, rp, audit_id=AUDIT)

    assert [f.rule_id for f in first] == [f.rule_id for f in second]
    assert [f.status for f in first] == [f.status for f in second]
    assert [f.finding_id for f in first] == [f.finding_id for f in second]


def test_every_finding_records_what_produced_it() -> None:
    finding = only(csm_with(present(False)), pack(rule()))

    assert finding.provenance.engine_version
    assert finding.provenance.rulepack_version == "1.0.0"
    assert finding.provenance.pack_versions == {"cisco": "1.1.0"}


def test_severity_is_carried_from_the_rule_not_computed() -> None:
    finding = only(csm_with(present(True)), pack(rule(severity=Severity.LOW)))

    assert finding.base_severity is Severity.LOW
    assert finding.exposure_score is None, "exposure is P7/P12"
    assert finding.priority_rank is None
