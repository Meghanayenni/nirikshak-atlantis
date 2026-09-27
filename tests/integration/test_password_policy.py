"""The password minimum, and what its absence does and does not establish.

ADR 0063. One development file sets `security passwords min-length`; the rest do
not. The rule's threshold is 15, from NIST SP 800-63B-4 and the DISA STIG, so
the one file that sets a policy sets one that is too short.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.comply.engine import evaluate_device
from api.comply.rulepacks import load_rulepack
from api.ingest.packs import load_active_packs
from api.models.enums import FieldState, UnknownReason, Verdict
from api.normalise.service import build_csm
from api.parse.service import parse_configuration

DEV = Path("corpus/cisco/dev")


@pytest.fixture(scope="module")
def ios():
    return next(
        p for p in load_active_packs(use_cache=False) if (p.vendor, p.os_family) == ("cisco", "ios")
    )


@pytest.fixture(scope="module")
def rulepack():
    return load_rulepack()


def audit(name: str, pack, rulepack):
    path = DEV / name
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(
        path.read_text(encoding="utf-8"), pack, file_id=file_id, file_path=str(path)
    )
    csm = build_csm(parsed, pack, device_id=file_id)
    findings = {f.rule_id: f for f in evaluate_device(csm, rulepack, audit_id="a")}
    return csm, findings


def test_branch_rtr_07_sets_twelve_which_is_below_fifteen(ios, rulepack) -> None:
    csm, findings = audit("branch-rtr-07.cfg", ios, rulepack)

    field = csm.fields["min_password_length"]
    assert field.value == 12
    assert [e.line_start for e in field.evidence] == [39]

    finding = findings["NRK-PASSWD-001"]
    assert finding.status is Verdict.FAIL
    assert finding.evidence[0].raw_line.strip() == "security passwords min-length 12"


@pytest.mark.parametrize("name", ["edge-rtr-01.cfg", "edge-rtr-09.cfg", "rtr-core-01.cfg"])
def test_an_absent_policy_abstains_and_is_never_failed(name: str, ios, rulepack) -> None:
    """The decision this module exists to pin (ADR 0063).

    The command reference gives the default both as "not enabled" and as six
    characters, and an AAA password policy this pack does not read can set a
    minimum too. Absence of this one line therefore does not establish that no
    minimum is enforced, and a FAIL here would be a guess.
    """
    csm, findings = audit(name, ios, rulepack)

    assert csm.fields["min_password_length"].state is FieldState.UNKNOWN
    finding = findings["NRK-PASSWD-001"]
    assert finding.status is Verdict.UNKNOWN
    assert finding.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
    assert finding.evidence == ()


def test_no_default_is_declared_for_the_password_minimum(ios) -> None:
    assert ios.default_for("min_password_length") is None
    assert ios.capability_for("min_password_length") is None


def test_the_threshold_is_the_sourced_fifteen(rulepack) -> None:
    rule = next(r for r in rulepack.rules if r.rule_id == "NRK-PASSWD-001")
    assert rule.check.condition.op.value == "gte"
    assert rule.check.condition.value == 15
    assert any("800-63B-4" in ref for ref in rule.references)
    assert any("CISC-ND-000550" in ref for ref in rule.references)
