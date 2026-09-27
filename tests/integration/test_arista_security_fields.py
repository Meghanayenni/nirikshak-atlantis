"""Arista EOS security fields, read from the development file they came from.

ADR 0064. EOS configures remote access in `management` blocks rather than on
`line vty`, so the same canonical fields are read from different places — and
the place each one is *not* read from matters as much.
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

DEV = Path("corpus/arista/dev")


@pytest.fixture(scope="module")
def eos():
    return next(
        p
        for p in load_active_packs(use_cache=False)
        if (p.vendor, p.os_family) == ("arista", "eos")
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


@pytest.fixture(scope="module")
def spine(eos, rulepack):
    return audit("dc1-spine-01.cfg", eos, rulepack)


def test_telnet_re_enabled_under_management_telnet_fails(spine) -> None:
    csm, findings = spine
    field = csm.fields["telnet_enabled"]

    assert field.value is True
    # Line 42 only. The two `no shutdown` lines under `management api
    # http-commands` (46, 48) and the one under `management ssh` (38) are
    # other services and must not be read as telnet.
    assert [e.line_start for e in field.evidence] == [42]
    assert findings["NRK-TELNET-001"].status is Verdict.FAIL


def test_ssh_and_telnet_timeouts_disagree_so_the_field_abstains_citing_both(spine) -> None:
    """15 minutes for ssh, 0 (never) for telnet. Reading ssh alone would pass a
    device whose telnet sessions never expire."""
    csm, findings = spine
    field = csm.fields["idle_timeout_seconds"]

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CONFLICTING_EVIDENCE
    assert [e.line_start for e in field.evidence] == [37, 41]
    assert findings["NRK-TIMEOUT-001"].status is Verdict.UNKNOWN


def test_the_console_timeout_is_not_a_management_timeout(spine) -> None:
    csm, _ = spine
    assert 34 not in {e.line_start for e in csm.fields["idle_timeout_seconds"].evidence}


def test_the_ssh_timeout_is_read_in_minutes(eos) -> None:
    """EOS writes minutes; the canonical field is seconds (ADR 0064)."""
    text = "management ssh\n   idle-timeout 10\n"
    parsed = parse_configuration(text, eos, file_id="f" * 64, file_path="t.cfg")
    csm = build_csm(parsed, eos, device_id="f" * 64)
    assert csm.fields["idle_timeout_seconds"].value == 600


def test_the_banner_passes_and_its_body_is_not_configuration(spine) -> None:
    csm, findings = spine

    assert csm.fields["banner_present"].value is True
    assert [e.line_start for e in csm.fields["banner_present"].evidence] == [62]
    assert findings["NRK-BANNER-001"].status is Verdict.PASS

    residue = {line.raw_line_scrubbed.strip() for line in csm.residue}
    assert "Authorised use only." not in residue
    assert "EOF" not in residue


def test_an_absent_telnet_block_abstains_because_the_default_is_withheld(eos, rulepack) -> None:
    """The EOS default is sourced and deliberately not declared (ADR 0064).

    When it is, this test is the one that must change: sw-leaf-01 would then
    PASS as inferred.
    """
    assert eos.default_for("telnet_enabled") is None
    assert eos.capability_for("telnet_enabled") is None

    csm, findings = audit("sw-leaf-01.cfg", eos, rulepack)
    assert csm.fields["telnet_enabled"].state is FieldState.UNKNOWN
    assert findings["NRK-TELNET-001"].status is Verdict.UNKNOWN
    assert findings["NRK-TELNET-001"].unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
