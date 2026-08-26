"""Finding, RemediationSnippet, TrainingExample and AuditRecord contracts.

Covers Rule 2 (justification), Rule 4 (vetted remediation only), R7 (confidence
populations survive into reporting) and the audit chain's per-record invariant.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from api.models import (
    GENESIS_HASH,
    Actor,
    ActorType,
    AuditAction,
    AuditRecord,
    ConfidenceMethod,
    Evidence,
    ExampleSource,
    FieldState,
    Finding,
    FindingProvenance,
    Framework,
    FrameworkRef,
    ImpactAssessment,
    LockoutRisk,
    ObservedValue,
    RemediationRef,
    RemediationSnippet,
    Severity,
    SourceType,
    Subject,
    Suggestion,
    TrainingExample,
    TrainingOutcome,
    UnknownReason,
    Verdict,
    canonical_json,
    hash_payload,
)

EV = Evidence(
    file_id="f1",
    file_path="rtr.cfg",
    line_start=412,
    line_end=412,
    raw_line="ip ssh version 1",
    source_type=SourceType.CLI,
)

OBSERVED = ObservedValue(
    value=1,
    state=FieldState.PRESENT,
    confidence=1.0,
    confidence_method=ConfidenceMethod.DETERMINISTIC,
)

PROV = FindingProvenance(engine_version="0.1.0")


def finding(**kw: object) -> Finding:
    base: dict[str, object] = {
        "finding_id": "fnd-1",
        "audit_id": "aud-1",
        "device_id": "d1",
        "rule_id": "NRK-SSH-001",
        "status": Verdict.FAIL,
        "base_severity": Severity.HIGH,
        "observed": OBSERVED,
        "expected": "ssh_version == 2",
        "evidence": (EV,),
        "provenance": PROV,
    }
    base.update(kw)
    return Finding(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Finding — Rule 2 and Rule 3 carried through to the report
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [Verdict.PASS, Verdict.FAIL])
def test_verdict_requires_evidence_or_absence_citation(status: Verdict) -> None:
    with pytest.raises(ValidationError, match="requires evidence or an absence citation"):
        finding(status=status, evidence=())


def test_absence_citation_satisfies_justification() -> None:
    """A verdict may rest on a documented default instead of a source line."""
    f = finding(
        status=Verdict.PASS,
        evidence=(),
        absence_reason="IOS 17.x defaults SSH to version 2",
        observed=ObservedValue(
            value=2,
            state=FieldState.ABSENT_DEFAULT,
            confidence=1.0,
            confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        ),
    )
    assert f.status is Verdict.PASS


def test_unknown_requires_a_reason() -> None:
    with pytest.raises(ValidationError, match="must record why it abstained"):
        finding(status=Verdict.UNKNOWN, evidence=())


def test_unknown_finding_carries_no_remediation() -> None:
    """We do not know there is anything to fix."""
    with pytest.raises(ValidationError, match="must not carry remediation"):
        finding(
            status=Verdict.UNKNOWN,
            evidence=(),
            unknown_reason=UnknownReason.CAPABILITY_UNKNOWN,
            remediation=RemediationRef(snippet_id="s1", vendor="cisco", os_family="ios"),
        )


def test_decided_finding_carries_no_unknown_reason() -> None:
    with pytest.raises(ValidationError, match="must not carry an"):
        finding(unknown_reason=UnknownReason.NO_MATCH)


def test_unknown_from_parse_gap_routes_to_training() -> None:
    f = finding(status=Verdict.UNKNOWN, evidence=(), unknown_reason=UnknownReason.NO_MATCH)
    assert f.needs_training
    assert not f.is_actionable


def test_unknown_from_capability_gap_does_not_route_to_training() -> None:
    """Nothing to teach: the platform documentation is what is missing."""
    f = finding(
        status=Verdict.UNKNOWN,
        evidence=(),
        unknown_reason=UnknownReason.CAPABILITY_UNKNOWN,
    )
    assert not f.needs_training


def test_observed_value_preserves_confidence_population() -> None:
    """R7 survives into the report: parser confidence is not a probability."""
    assert not OBSERVED.confidence_is_probability
    calibrated = ObservedValue(
        value=1,
        state=FieldState.PRESENT,
        confidence=0.9,
        confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY,
    )
    assert calibrated.confidence_is_probability


def test_finding_has_no_field_for_model_output() -> None:
    """Rule 1, structurally: a model has nowhere to write a verdict here."""
    forbidden = {
        "explanation",
        "model_output",
        "suggestion",
        "llm_verdict",
        "ai_summary",
        "predicted_status",
    }
    assert forbidden.isdisjoint(set(Finding.model_fields))


def test_finding_reports_framework_ids() -> None:
    f = finding(frameworks=(FrameworkRef(framework=Framework.CIS, control_id="1.5.2"),))
    assert f.citations() == ["rtr.cfg:412"]
    assert f.frameworks[0].control_id == "1.5.2"


# ---------------------------------------------------------------------------
# RemediationSnippet — Rule 4
# ---------------------------------------------------------------------------


def snippet(**kw: object) -> RemediationSnippet:
    base: dict[str, object] = {
        "snippet_id": "SNP-CISCO-IOS-SSH-001",
        "rule_id": "NRK-SSH-001",
        "vendor": "cisco",
        "os_family": "ios",
        "commands": ("configure terminal", "ip ssh version 2", "end"),
        "vetted_by": "team-atlantis",
    }
    base.update(kw)
    return RemediationSnippet(**base)  # type: ignore[arg-type]


def test_snippet_requires_a_vetter() -> None:
    """Rule 4 — an unvetted snippet is not a snippet."""
    with pytest.raises(ValidationError):
        snippet(vetted_by="")


def test_snippet_requires_at_least_one_command() -> None:
    with pytest.raises(ValidationError):
        snippet(commands=())


def test_blank_command_is_rejected() -> None:
    with pytest.raises(ValidationError, match="blank command"):
        snippet(commands=("configure terminal", "   "))


def test_service_affecting_change_must_have_rollback() -> None:
    """The operator must be able to get back."""
    with pytest.raises(ValidationError, match="no rollback"):
        snippet(impact=ImpactAssessment(service_affecting=True))


def test_service_affecting_with_rollback_is_valid() -> None:
    s = snippet(
        impact=ImpactAssessment(service_affecting=True),
        rollback=("configure terminal", "no ip ssh version 2", "end"),
    )
    assert s.rollback


def test_high_lockout_risk_must_explain_itself() -> None:
    with pytest.raises(ValidationError, match="must explain itself"):
        ImpactAssessment(lockout_risk=LockoutRisk.HIGH)


def test_snippet_cannot_depend_on_itself() -> None:
    with pytest.raises(ValidationError, match="depends on itself"):
        snippet(depends_on=("SNP-CISCO-IOS-SSH-001",))


def test_snippet_lookup_key_is_the_only_resolution_path() -> None:
    """Remediation is resolved by key, never generated."""
    assert snippet().key == ("cisco", "ios", "NRK-SSH-001")


# ---------------------------------------------------------------------------
# TrainingExample — where trust originates
# ---------------------------------------------------------------------------


def suggestion(rank: int, field: str, **kw: object) -> Suggestion:
    base: dict[str, object] = {"rank": rank, "field": field, "raw_score": 0.8}
    base.update(kw)
    return Suggestion(**base)  # type: ignore[arg-type]


def example(**kw: object) -> TrainingExample:
    base: dict[str, object] = {
        "example_id": "tex-1",
        "vendor": "acme",
        "os_family": "acme-os",
        "raw_line_scrubbed": "set ssh proto-version 2",
        "field": "ssh_version",
        "suggestions_shown": (
            suggestion(1, "ssh_version"),
            suggestion(2, "telnet_enabled"),
            suggestion(3, "aaa_enabled"),
        ),
        "outcome": TrainingOutcome.ACCEPTED_RANK_1,
        "confirmed_by": "admin@ntro",
        "source": ExampleSource.ADMIN,
    }
    base.update(kw)
    return TrainingExample(**base)  # type: ignore[arg-type]


def test_uncalibrated_suggestion_may_not_carry_calibrated_confidence() -> None:
    """R7 — a raw score cannot become a probability by being stored in that slot."""
    with pytest.raises(ValidationError, match="cannot become a probability"):
        suggestion(1, "ssh_version", calibrated_confidence=0.9)


def test_calibrated_suggestion_must_carry_its_confidence() -> None:
    with pytest.raises(ValidationError, match="claims calibrated confidence"):
        suggestion(1, "ssh_version", confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY)


def test_suggestion_must_be_model_derived() -> None:
    with pytest.raises(ValidationError, match="must be model-derived"):
        suggestion(1, "ssh_version", confidence_method=ConfidenceMethod.DETERMINISTIC)


def test_accepted_rank_must_exist_among_suggestions() -> None:
    with pytest.raises(ValidationError, match="no suggestion at that rank"):
        example(outcome=TrainingOutcome.ACCEPTED_RANK_3, suggestions_shown=(suggestion(1, "x"),))


def test_accepted_rank_must_agree_with_recorded_field() -> None:
    """If the administrator changed it, the outcome is CORRECTED, not ACCEPTED."""
    with pytest.raises(ValidationError, match="the outcome is CORRECTED"):
        example(field="telnet_enabled")


def test_correction_is_recorded_faithfully() -> None:
    e = example(field="telnet_enabled", outcome=TrainingOutcome.CORRECTED)
    assert e.outcome is TrainingOutcome.CORRECTED
    assert e.improved_coverage


def test_rejected_example_names_no_field() -> None:
    with pytest.raises(ValidationError, match="rejected as not security relevant"):
        example(outcome=TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT)


def test_rejected_example_without_field_is_valid() -> None:
    e = example(field=None, outcome=TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT)
    assert not e.improved_coverage


def test_top3_hit_metric() -> None:
    """Feeds the top-3 mapping accuracy measured at P9."""
    assert example().top3_hit
    assert not example(field="logging_enabled", outcome=TrainingOutcome.CORRECTED).top3_hit


def test_duplicate_suggestion_ranks_are_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate suggestion ranks"):
        example(suggestions_shown=(suggestion(1, "a"), suggestion(1, "b")))


# ---------------------------------------------------------------------------
# AuditRecord — hash chain
# ---------------------------------------------------------------------------


def record(seq: int = 0, prev: str = GENESIS_HASH, **kw: object) -> AuditRecord:
    base: dict[str, object] = {
        "seq": seq,
        "timestamp": datetime(2026, 8, 26, 12, 0, tzinfo=UTC),
        "actor": Actor(type=ActorType.HUMAN, id="admin@ntro", role="administrator"),
        "action": AuditAction.PACK_ACTIVATED,
        "subject": Subject(kind="vendor_pack", id="acme/acme-os@1.2.0"),
        "payload": {"from": "1.1.0", "to": "1.2.0"},
        "prev_hash": prev,
    }
    base.update(kw)
    return AuditRecord(**base)  # type: ignore[arg-type]


def test_hashes_are_derived_and_self_consistent() -> None:
    r = record()
    assert r.payload_hash == hash_payload({"from": "1.1.0", "to": "1.2.0"})
    assert r.verify_self()
    assert r.is_genesis


def test_payload_hash_must_match_payload() -> None:
    with pytest.raises(ValidationError, match="does not match payload"):
        record(payload_hash="0" * 64)


def test_entry_hash_must_match_record_contents() -> None:
    with pytest.raises(ValidationError, match="this is what tampering looks like"):
        record(entry_hash="0" * 64)


def test_records_link_into_a_chain() -> None:
    first = record(seq=0)
    second = record(seq=1, prev=first.entry_hash)
    assert second.links_to(first)
    assert not second.is_genesis


def test_broken_link_is_detected() -> None:
    first = record(seq=0)
    wrong = record(seq=1, prev="b" * 64)
    assert not wrong.links_to(first)


def test_payload_key_order_does_not_change_the_hash() -> None:
    """Canonical JSON — the chain must not fail to verify for cosmetic reasons."""
    a = hash_payload({"b": 2, "a": 1})
    b = hash_payload({"a": 1, "b": 2})
    assert a == b


def test_canonical_json_is_stable_and_compact() -> None:
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


def test_model_actor_may_only_suggest() -> None:
    """Rule 1, in the audit trail: models suggest, humans decide."""
    model_actor = Actor(type=ActorType.MODEL, id="all-MiniLM-L6-v2")

    ok = record(actor=model_actor, action=AuditAction.AI_SUGGESTED)
    assert ok.actor.type is ActorType.MODEL

    for forbidden in (
        AuditAction.ADMIN_CONFIRMED,
        AuditAction.PACK_ACTIVATED,
        AuditAction.AUDIT_RUN,
    ):
        with pytest.raises(ValidationError, match="models suggest, humans decide"):
            record(actor=model_actor, action=forbidden)
