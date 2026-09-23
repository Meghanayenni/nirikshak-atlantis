"""Cisco NX-OS — a fourth platform, and the first bound access list.

`corpus/cisco/dev/dc1-leaf-01.cfg` scored 0.25 against `cisco/ios`, below the
0.60 detection floor, and could not be audited at all. That was correct
abstention and a platform nobody could reach.

The hard part is detection, not parsing. NX-OS and IOS share most of their
vocabulary, so a pack that merely *scored* on this file would trip the
`min_margin` ambiguity rule and leave it unauditable a second way. The
signatures are constructs classic IOS does not write at all.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.analyse.service import analyse_device
from api.comply.engine import evaluate_device, new_audit_id
from api.comply.rulepacks import load_rulepack
from api.config import settings
from api.ingest.packs import find_pack, load_active_packs
from api.ingest.vendor_detect import detect_vendor
from api.models.enums import AclDialect, UnknownReason, Verdict
from api.models.ingestion import DetectionOutcome
from api.normalise.service import build_csm
from api.parse.service import parse_configuration
from api.parse.structures import _DIALECTS, _LIST_READERS

LEAF = Path("corpus/cisco/dev/dc1-leaf-01.cfg")


@pytest.fixture(scope="module")
def packs():
    return load_active_packs(use_cache=False)


@pytest.fixture(scope="module")
def nxos(packs):
    return find_pack("cisco", "nxos", packs)


@pytest.fixture(scope="module")
def csm(nxos):
    parsed = parse_configuration(
        LEAF.read_text(encoding="utf-8"), nxos, file_id=LEAF.name, file_path=str(LEAF)
    )
    return build_csm(parsed, nxos, device_id=LEAF.name)


# ---------------------------------------------------------------------------
# Detection, which is the whole difficulty
# ---------------------------------------------------------------------------


def detect(path: Path, packs):
    return detect_vendor(
        packs,
        path.read_text(encoding="utf-8").splitlines(),
        filename=path.name,
        min_score=settings.detection_min_score,
        min_margin=settings.detection_min_margin,
    )


def test_the_nxos_device_is_identified_rather_than_abstained_on(packs) -> None:
    result = detect(LEAF, packs)

    assert result.outcome is DetectionOutcome.DETECTED
    assert (result.vendor, result.os_family) == ("cisco", "nxos")


def test_nxos_wins_by_a_margin_rather_than_by_a_hair(packs) -> None:
    """Two Cisco platforms is where the ambiguity rule earns its keep.

    `cisco/ios` still scores on this file — the two share most of their
    vocabulary. What must hold is that the gap is decisive, because a narrow
    win would be reported as AMBIGUOUS and the device would go unaudited for a
    second reason.
    """
    result = detect(LEAF, packs)
    runner_up = next(c for c in result.candidates if c.os_family != "nxos")

    assert result.margin >= settings.detection_min_margin
    assert result.score - runner_up.score > 0.5


@pytest.mark.parametrize(
    "path",
    [
        Path("corpus/cisco/dev/rtr-core-01.cfg"),
        Path("corpus/cisco/dev/edge-rtr-01.cfg"),
        Path("corpus/arista/dev/sw-leaf-01.cfg"),
    ],
)
def test_the_nxos_signatures_claim_no_other_platform(packs, path: Path) -> None:
    """The other direction, which is the one that would do damage quietly.

    A signature matching IOS as well would not fail on the NX-OS file — it would
    start pulling IOS devices towards the wrong pack, where every pattern misses
    and every field reads UNKNOWN.
    """
    result = detect(path, packs)
    nxos_score = next(
        (c.score for c in result.candidates if (c.vendor, c.os_family) == ("cisco", "nxos")), 0.0
    )
    assert nxos_score == 0.0, f"an NX-OS signature matched {path.name}"


# ---------------------------------------------------------------------------
# What it reads
# ---------------------------------------------------------------------------


def test_seven_canonical_fields_resolve(csm) -> None:
    resolved = {name: f.value for name, f in csm.fields.items() if f.value is not None}

    assert resolved == {
        "aaa_enabled": True,
        "banner_present": True,
        "http_server_enabled": False,
        "idle_timeout_seconds": 600,
        "logging_hosts": ["198.51.100.40"],
        "ntp_servers": ["192.0.2.10", "192.0.2.11"],
        "telnet_enabled": False,
    }


def test_telnet_is_read_from_the_feature_gate(csm) -> None:
    """NX-OS gates the service; IOS gates the transport on a line.

    `no feature telnet` names no value to capture, so the pattern asserts the
    literal the line's presence means — which is the mechanism D69 exposed in
    the training form, used here by a shipped pack for the first time.
    """
    telnet = csm.get("telnet_enabled")

    assert telnet.value is False
    assert telnet.evidence[0].raw_line.strip() == "no feature telnet"


def test_the_idle_timeout_is_scoped_to_the_vty_line(csm) -> None:
    """`line console` carries an identical `exec-timeout 10` and is not read."""
    timeout = csm.get("idle_timeout_seconds")

    assert timeout.value == 600
    assert [e.line_start for e in timeout.evidence] == [69]


def test_ssh_version_abstains_rather_than_being_inferred_from_feature_ssh(csm) -> None:
    """The one field deliberately not read, and the reason it is not.

    NX-OS has no `ip ssh version` command. Mapping `feature ssh` to version 2
    would be a claim about what the platform supports, with no document behind
    it — `SOURCING_BACKLOG` gap 2. So the field is UNKNOWN and NRK-SSH-001
    abstains on a device that is otherwise well hardened, which is the honest
    outcome rather than a convenient one.
    """
    assert csm.get("ssh_version") is None

    findings = evaluate_device(csm, load_rulepack(), audit_id=new_audit_id())
    ssh = next(f for f in findings if f.rule_id == "NRK-SSH-001")

    assert ssh.status is Verdict.UNKNOWN
    assert ssh.unknown_reason is UnknownReason.NO_MATCH


def test_the_device_otherwise_passes(csm) -> None:
    """The corpus's declared "good device" fixture, now actually auditable."""
    findings = evaluate_device(csm, load_rulepack(), audit_id=new_audit_id())
    verdicts = {f.rule_id: f.status for f in findings}

    assert sum(v is Verdict.PASS for v in verdicts.values()) == 6
    assert not any(v is Verdict.FAIL for v in verdicts.values())


# ---------------------------------------------------------------------------
# Structure — the first access list in the corpus that knows where it is applied
# ---------------------------------------------------------------------------


def test_the_access_list_is_read_with_cidr_addresses(csm) -> None:
    assert len(csm.acls) == 1
    assert csm.acl_failures == ()

    acl = csm.acls[0]
    assert acl.name == "MGMT-IN"
    assert [e.seq for e in acl.entries] == [1, 2, 3]
    assert acl.entries[0].src.resolved_cidrs == ("198.51.100.0/24",)
    assert (acl.entries[0].dst_port.low, acl.entries[0].dst_port.high) == (22, 22)


def test_the_list_resolves_its_binding(csm) -> None:
    """The first `applied_to` the corpus has ever produced.

    Every Cisco and JunOS list so far has been declared and never bound: no
    development file applied one to an interface, so `applied_to` was always
    empty and the exposure ranking had a list it could not place. This one is
    applied to `mgmt0` inbound, and the binding is read off the interface rather
    than guessed from the name.
    """
    applied = csm.acls[0].applied_to

    assert len(applied) == 1
    assert applied[0].interface == "mgmt0"
    assert applied[0].direction.value == "in"


def test_the_clean_list_produces_no_observations(csm) -> None:
    """Two specific permits above a catch-all deny is a correct list.

    The result that shows the analyser is reading rather than pattern-matching
    for alarm — the closing `deny ip any any` is what a list is supposed to end
    with.
    """
    assert analyse_device(csm).observations == ()


def test_the_management_interface_is_read_but_not_classified(csm) -> None:
    """`mgmt0` is conventionally management, and nothing here documents that.

    Reading the convention out of the name would be the inference DEF-2 forbids,
    so `is_management` stays None and the exposure ranking keeps abstaining
    (ADR 0034). The interface, its address and its bound list are all read.
    """
    mgmt = next(i for i in csm.interfaces if i.name == "mgmt0")

    assert mgmt.ip_addresses == ("198.51.100.11/24",)
    assert [a.acl_id for a in mgmt.applied_acls] == ["MGMT-IN"]
    assert mgmt.is_management is None


# ---------------------------------------------------------------------------
# The table that had to agree with itself
# ---------------------------------------------------------------------------


def test_every_dialect_has_a_reader() -> None:
    """A dialect in `_DIALECTS` and not in `_LIST_READERS` reads nothing.

    Silently: `extract_acls` returns two empty tuples, which is exactly what a
    device with no access lists returns. `nxos_cidr` shipped in one table and
    not the other during this work, and the NX-OS list simply did not appear —
    no error, no dropped-list diagnostic, nothing.
    """
    missing = set(_DIALECTS) - set(_LIST_READERS)
    assert missing == set(), f"dialects with an entry parser and no reader: {missing}"


def test_every_dialect_a_shipped_pack_names_can_be_read(packs) -> None:
    declared = {p.acl_extraction.dialect for p in packs if p.acl_extraction is not None}
    assert declared <= set(_LIST_READERS)
    assert AclDialect.NXOS_CIDR in declared
