"""The SSH algorithm lists, read from the development lines they were authored from.

ADR 0062. Three development files carry `ip ssh server algorithm` lines, and
they disagree in the three ways that matter: weak on both lists, strong on
both, and one list set while the other is left at the platform default.
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


def test_edge_rtr_01_offers_weak_ciphers_and_macs_and_fails_both(ios, rulepack) -> None:
    csm, findings = audit("edge-rtr-01.cfg", ios, rulepack)

    assert csm.fields["ssh_ciphers"].value == ["3des-cbc", "aes128-cbc"]
    assert [e.line_start for e in csm.fields["ssh_ciphers"].evidence] == [44]
    assert csm.fields["ssh_macs"].value == ["hmac-md5", "hmac-sha1"]
    assert [e.line_start for e in csm.fields["ssh_macs"].evidence] == [45]

    assert findings["NRK-CIPHER-001"].status is Verdict.FAIL
    assert findings["NRK-CIPHER-002"].status is Verdict.FAIL
    assert findings["NRK-CIPHER-001"].evidence[0].raw_line.strip() == (
        "ip ssh server algorithm encryption 3des-cbc aes128-cbc"
    )


def test_branch_rtr_07_offers_only_ctr_and_sha2_and_passes_both(ios, rulepack) -> None:
    csm, findings = audit("branch-rtr-07.cfg", ios, rulepack)

    assert csm.fields["ssh_ciphers"].value == ["aes256-ctr", "aes192-ctr", "aes128-ctr"]
    assert csm.fields["ssh_macs"].value == ["hmac-sha2-256"]
    assert findings["NRK-CIPHER-001"].status is Verdict.PASS
    assert findings["NRK-CIPHER-002"].status is Verdict.PASS
    assert [e.line_start for e in findings["NRK-CIPHER-001"].evidence] == [54]
    assert [e.line_start for e in findings["NRK-CIPHER-002"].evidence] == [55]


def test_a_list_left_at_its_default_abstains_while_the_other_is_judged(ios, rulepack) -> None:
    """dist-sw-03 sets ciphers and no MACs. One verdict, one abstention.

    The reason two fields exist: a single combined list would have judged this
    device's MAC offer without having read it.
    """
    csm, findings = audit("dist-sw-03.cfg", ios, rulepack)

    assert findings["NRK-CIPHER-001"].status is Verdict.FAIL
    assert csm.fields["ssh_macs"].state is FieldState.UNKNOWN
    assert findings["NRK-CIPHER-002"].status is Verdict.UNKNOWN
    assert findings["NRK-CIPHER-002"].unknown_reason is UnknownReason.CAPABILITY_UNKNOWN


def test_the_pack_reads_offers_and_the_rule_names_the_weak_ones(ios, rulepack) -> None:
    """Weakness is a rule's judgement, never a pack's (Rule 1, Rule 5)."""
    for pattern in ios.patterns_for("ssh_ciphers") + ios.patterns_for("ssh_macs"):
        for weak in ("cbc", "md5", "sha1"):
            assert weak not in pattern.match.pattern

    by_id = {r.rule_id: r for r in rulepack.rules}
    assert "3des-cbc" in by_id["NRK-CIPHER-001"].check.condition.value
    assert "hmac-sha1" in by_id["NRK-CIPHER-002"].check.condition.value
    assert "weak_ciphers" not in {p.field for p in ios.patterns}
