"""JunOS security fields, in both surfaces JunOS ships (ADR 0065).

core-rtr-01.conf is brace-nested; edge-rtr-02 and the two SRX files are flat
`set` form. A field is read from whichever surface a development file carries,
and a surface with no development line abstains rather than being guessed.
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

DEV = Path("corpus/juniper/dev")


@pytest.fixture(scope="module")
def junos():
    return next(
        p
        for p in load_active_packs(use_cache=False)
        if (p.vendor, p.os_family) == ("juniper", "junos")
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
def core(junos, rulepack):
    return audit("core-rtr-01.conf", junos, rulepack)


@pytest.fixture(scope="module")
def edge(junos, rulepack):
    return audit("edge-rtr-02.conf", junos, rulepack)


# ---------------------------------------------------------------------------
# Brace form — core-rtr-01
# ---------------------------------------------------------------------------


def test_brace_telnet_under_system_services_fails(core) -> None:
    csm, findings = core
    field = csm.fields["telnet_enabled"]

    assert field.value is True
    # Line 67 only. `destination-port telnet` in a firewall term (line 164)
    # names the protocol a filter matches; it does not enable the service.
    assert [e.line_start for e in field.evidence] == [67]
    assert findings["NRK-TELNET-001"].status is Verdict.FAIL


def test_brace_login_message_is_a_banner(core) -> None:
    csm, findings = core
    assert [e.line_start for e in csm.fields["banner_present"].evidence] == [44]
    assert findings["NRK-BANNER-001"].status is Verdict.PASS


def test_brace_syslog_host_is_read_and_the_local_file_is_not(core) -> None:
    csm, findings = core
    assert csm.fields["logging_hosts"].value == ["198.51.100.40"]
    assert [e.line_start for e in csm.fields["logging_hosts"].evidence] == [78]
    assert findings["NRK-LOGGING-001"].status is Verdict.PASS


def test_brace_ssh_version_has_no_development_line_and_abstains(core) -> None:
    csm, findings = core
    assert csm.fields["ssh_version"].state is FieldState.UNKNOWN
    assert findings["NRK-SSH-001"].status is Verdict.UNKNOWN


# ---------------------------------------------------------------------------
# Flat form — edge-rtr-02 and the SRX files
# ---------------------------------------------------------------------------


def test_one_flat_syslog_host_on_three_lines_is_one_host(edge) -> None:
    """ADR 0065: `distinct` — the host once, every line cited."""
    csm, _ = edge
    field = csm.fields["logging_hosts"]
    assert field.value == ["198.51.100.40"]
    assert [e.line_start for e in field.evidence] == [43, 44, 45]


def test_flat_login_message_is_a_banner(edge) -> None:
    csm, findings = edge
    assert [e.line_start for e in csm.fields["banner_present"].evidence] == [39]
    assert findings["NRK-BANNER-001"].status is Verdict.PASS


def test_flat_telnet_abstains_and_the_commented_line_is_not_read(edge, junos) -> None:
    """No flat telnet pattern exists, and no default is declared.

    edge-rtr-02 line 14 is a comment that quotes `set system services telnet`.
    It must not become a fact, and without a flat pattern the absence cannot be
    read as "off" either — so the check abstains (ADR 0065).
    """
    csm, findings = edge
    assert csm.fields["telnet_enabled"].state is FieldState.UNKNOWN
    assert csm.fields["telnet_enabled"].evidence == ()
    assert findings["NRK-TELNET-001"].status is Verdict.UNKNOWN
    assert findings["NRK-TELNET-001"].unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
    assert junos.default_for("telnet_enabled") is None
    assert junos.capability_for("telnet_enabled") is None


@pytest.mark.parametrize(("name", "line"), [("srx-branch-04.conf", 3), ("srx-edge-01.conf", 4)])
def test_flat_ssh_protocol_version_is_read(name: str, line: int, junos, rulepack) -> None:
    csm, findings = audit(name, junos, rulepack)
    assert csm.fields["ssh_version"].value == 2
    assert [e.line_start for e in csm.fields["ssh_version"].evidence] == [line]
    assert findings["NRK-SSH-001"].status is Verdict.PASS
