"""Exposure assessment, and the ranking P12 refuses to produce (P12).

Exposure needs interfaces and access lists. This corpus has neither, so on real
data every assessment here is undetermined and `priority_rank` stays `None`.
These tests use **constructed canonical models** to exercise the determined path
— the shape P7 and P8 both took — and constructed models are named as such rather
than presented as evidence about anything.

The assertions that matter most are the negative ones: that a severity value
alone can never produce a score, and that an undetermined assessment cannot carry
a number a caller could sort by.
"""

from __future__ import annotations

import pytest

from api.models.csm import (
    CanonicalSecurityModel,
    CsmSource,
    DeviceIdentity,
    Interface,
)
from api.models.enums import (
    AclType,
    ConditionOp,
    ConfidenceMethod,
    FieldState,
    Severity,
    UnknownReason,
    Verdict,
)
from api.models.finding import Finding, FindingProvenance, ObservedValue
from api.models.rule import CheckSpec, ComplianceRule, Condition, Rulepack
from api.prioritise.errors import ExposureError
from api.prioritise.exposure import (
    SEVERITY_WEIGHT,
    ExposureAssessment,
    ExposureDeterminacy,
    assess,
    is_exposure_relevant,
    management_exposure,
)
from api.prioritise.service import ORDERING_UNAVAILABLE, prioritise


def csm(*, interfaces: tuple[Interface, ...] = (), acls: tuple = ()) -> CanonicalSecurityModel:
    return CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d" * 64, vendor="acme", os_family="os"),
        source=CsmSource(file_ids=("f" * 64,)),
        fields={},
        acls=acls,
        interfaces=interfaces,
    )


def finding(rule_id: str = "R-1", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        finding_id=f"fnd-{rule_id}",
        audit_id="aud-1",
        device_id="d" * 64,
        rule_id=rule_id,
        status=Verdict.UNKNOWN,
        base_severity=severity,
        observed=ObservedValue(
            value=None,
            state=FieldState.UNKNOWN,
            confidence=0.0,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        ),
        expected="something",
        unknown_reason=UnknownReason.NO_MATCH,
        provenance=FindingProvenance(engine_version="test"),
    )


def rulepack(field: str = "ssh_version", rule_id: str = "R-1") -> Rulepack:
    return Rulepack(
        rulepack_id="rp",
        version="1.0.0",
        rules=(
            ComplianceRule(
                rule_id=rule_id,
                title="t",
                severity=Severity.HIGH,
                rationale="r",
                check=CheckSpec(field=field, condition=Condition(op=ConditionOp.NON_EMPTY)),
            ),
        ),
    )


# ---------------------------------------------------------------------------
# The abstentions — every one of these is what the real corpus produces
# ---------------------------------------------------------------------------


def test_no_interfaces_means_exposure_is_undetermined() -> None:
    """The state of every device in this repository."""
    result = assess(csm(), field_name="ssh_version", severity=Severity.HIGH)

    assert result.determinacy is ExposureDeterminacy.NO_INTERFACE_DATA
    assert result.score is None
    assert "no interfaces" in result.reason


def test_interfaces_without_acls_are_still_undetermined() -> None:
    """Knowing where a control lives is not knowing who can reach it."""
    interfaces = (Interface(name="Mgmt0", is_management=True, ip_addresses=("192.0.2.1",)),)
    result = assess(csm(interfaces=interfaces), field_name="ssh_version", severity=Severity.HIGH)

    assert result.determinacy is ExposureDeterminacy.NO_ACL_DATA
    assert result.score is None
    assert "no access list" in result.reason


def test_undocumented_management_status_is_its_own_answer() -> None:
    """DEF-2 arriving in the layer it was fixed for.

    An interface whose management status is undocumented is not a non-management
    interface. Reported distinctly from "no interfaces" because the remedies
    differ: one needs interface parsing, the other needs vendor documentation.
    """
    interfaces = (Interface(name="Eth1", is_management=None),)
    result = assess(csm(interfaces=interfaces), field_name="ssh_version", severity=Severity.HIGH)

    assert result.determinacy is ExposureDeterminacy.INDETERMINATE_INTERFACES
    assert result.score is None


def test_a_control_whose_risk_does_not_vary_with_reachability_says_so() -> None:
    """A determinate answer, not an abstention.

    An unlogged device is equally unlogged whoever can reach it. Letting exposure
    drift into fields it has nothing to say about would make the score meaningless
    where it did apply.
    """
    result = assess(csm(), field_name="logging_hosts", severity=Severity.HIGH)

    assert result.determinacy is ExposureDeterminacy.NOT_EXPOSURE_RELEVANT
    assert result.score is None
    assert not is_exposure_relevant("logging_hosts")
    assert is_exposure_relevant("telnet_enabled")


# ---------------------------------------------------------------------------
# The invariant
# ---------------------------------------------------------------------------


def test_an_undetermined_assessment_cannot_carry_a_score() -> None:
    with pytest.raises(ExposureError, match="no number"):
        ExposureAssessment(determinacy=ExposureDeterminacy.NO_ACL_DATA, score=0.5, reason="x")


def test_a_determined_assessment_cannot_omit_its_score() -> None:
    with pytest.raises(ExposureError, match="carries no score"):
        ExposureAssessment(determinacy=ExposureDeterminacy.DETERMINED)


def test_severity_alone_produces_nothing() -> None:
    """DEVELOPER_GUIDE.md §7, asserted arithmetically.

    Reachability is zero without interfaces, and every weight multiplies it, so
    a CRITICAL finding on a device with no interface data scores exactly the same
    as an INFO one: nothing at all.
    """
    for severity in Severity:
        assert SEVERITY_WEIGHT[severity] * management_exposure(()) == 0.0
        assert assess(csm(), field_name="ssh_version", severity=severity).score is None


# ---------------------------------------------------------------------------
# The determined path, on constructed models
# ---------------------------------------------------------------------------


def test_a_reachable_management_interface_behind_an_acl_scores() -> None:
    """Constructed, and labelled as such. No corpus device looks like this."""
    from api.models.acl import ACL

    interfaces = (Interface(name="Mgmt0", is_management=True, ip_addresses=("192.0.2.1",)),)
    acls = (ACL(acl_id="mgmt-in", name="mgmt-in", acl_type=AclType.EXTENDED, entries=()),)
    result = assess(
        csm(interfaces=interfaces, acls=acls),
        field_name="telnet_enabled",
        severity=Severity.CRITICAL,
    )

    assert result.determinacy is ExposureDeterminacy.DETERMINED
    assert result.score == 1.0
    assert result.factors


def test_a_disabled_management_interface_lowers_reachability() -> None:
    reachable = (Interface(name="Mgmt0", is_management=True, ip_addresses=("192.0.2.1",)),)
    dark = (
        Interface(name="Mgmt0", is_management=True, ip_addresses=("192.0.2.1",)),
        Interface(name="Mgmt1", is_management=True, ip_addresses=(), enabled=False),
    )
    assert management_exposure(reachable) == 1.0
    assert management_exposure(dark) == 0.5
    assert management_exposure(()) == 0.0


# ---------------------------------------------------------------------------
# The ranking that is not produced
# ---------------------------------------------------------------------------


def test_no_ranking_is_produced_when_no_exposure_is_determined() -> None:
    """The result on every device in this repository."""
    result = prioritise(csm(), (finding(),), rulepack())

    assert result.ranked is False
    assert result.determined == 0
    assert result.undetermined == 1
    assert all(f.finding.priority_rank is None for f in result.findings)
    assert all(f.finding.exposure_score is None for f in result.findings)


def test_the_refusal_names_the_rule_it_is_obeying() -> None:
    """An operator asking "why is there no order?" gets the reason, not a blank."""
    result = prioritise(csm(), (finding(),), rulepack())

    assert result.reason == ORDERING_UNAVAILABLE
    assert "severity alone must not determine remediation order" in result.reason.lower()
    assert "No exposure ranking was produced" in result.describe()


def test_the_blockers_point_at_the_missing_input() -> None:
    """So a reader is sent to the sourcing backlog rather than to a bug report."""
    findings = (finding("R-1"), finding("R-2"))
    pack = Rulepack(
        rulepack_id="rp",
        version="1.0.0",
        rules=(
            rulepack("ssh_version", "R-1").rules[0],
            rulepack("logging_hosts", "R-2").rules[0],
        ),
    )
    result = prioritise(csm(), findings, pack)

    assert result.blockers() == {"no_interface_data": 1, "not_exposure_relevant": 1}


def test_a_ranking_is_produced_when_exposure_is_determined() -> None:
    """Constructed model. Proves the machinery is real, measures nothing."""
    from api.models.acl import ACL

    interfaces = (Interface(name="Mgmt0", is_management=True, ip_addresses=("192.0.2.1",)),)
    acls = (ACL(acl_id="a", name="a", acl_type=AclType.EXTENDED, entries=()),)
    model = csm(interfaces=interfaces, acls=acls)

    findings = (finding("R-1", Severity.LOW), finding("R-2", Severity.CRITICAL))
    pack = Rulepack(
        rulepack_id="rp",
        version="1.0.0",
        rules=(
            rulepack("ssh_version", "R-1").rules[0],
            rulepack("telnet_enabled", "R-2").rules[0],
        ),
    )
    result = prioritise(model, findings, pack)

    assert result.ranked is True
    assert result.determined == 2
    ranks = {f.finding.rule_id: f.finding.priority_rank for f in result.findings}
    assert ranks["R-2"] == 1, "the more exposed finding ranks first"
    assert ranks["R-1"] == 2
