"""End-to-end normalisation of the Cisco development corpus (P5).

Parse → normalise, against the two files the pack was authored from. The eight
P4 fields must arrive in the canonical model with the same values, the same
states and the same citations they had in the `ParseResult`: P5 resolves
absences, it does not re-decide facts.

The three fields absent from `sw-access-02` are what exercise the absence table
against a *real* pack — and because the shipped Cisco pack declares no
capabilities and no defaults (no vendor documentation has been sourced), they
must all resolve to UNKNOWN / capability_unknown. That is the honest result, and
asserting it here is what stops a fabricated default appearing later without
anyone noticing.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.ingest.packs import load_active_packs
from api.models.enums import ConfidenceMethod, FieldState, UnknownReason
from api.normalise.service import build_csm
from api.parse.service import parse_configuration

DEV = Path("corpus/cisco/dev")


@pytest.fixture(scope="module")
def cisco():
    pack = next(p for p in load_active_packs(use_cache=False) if p.vendor == "cisco")
    assert pack.pack_version == "1.1.0"
    return pack


def normalise(name: str, pack):
    path = DEV / name
    text = path.read_text(encoding="utf-8")
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(text, pack, file_id=file_id, file_path=f"corpus/cisco/dev/{name}")
    return parsed, build_csm(parsed, pack, device_id=file_id)


@pytest.fixture(scope="module")
def rtr(cisco):
    return normalise("rtr-core-01.cfg", cisco)


@pytest.fixture(scope="module")
def sw(cisco):
    return normalise("sw-access-02.cfg", cisco)


# ---------------------------------------------------------------------------
# One file, one CSM (decision D14)
# ---------------------------------------------------------------------------


def test_one_file_produces_one_csm(rtr) -> None:
    _, csm = rtr

    assert csm.csm_version == "1.0"
    assert len(csm.source.file_ids) == 1


def test_the_csm_records_the_pack_version_that_actually_applied(rtr) -> None:
    """Not whichever pack is active when a report is generated later."""
    parsed, csm = rtr

    assert csm.source.pack_versions == {"cisco": "1.1.0"}
    assert csm.source.pack_versions["cisco"] == parsed.pack_version


def test_device_identity_is_the_canonical_type(rtr) -> None:
    from api.models.csm import DeviceIdentity

    _, csm = rtr

    assert isinstance(csm.device, DeviceIdentity)
    assert csm.device.vendor == "cisco"
    assert csm.device.os_family == "ios"
    assert csm.device.device_id


def test_operator_metadata_is_not_invented(rtr) -> None:
    """`role`, `site` and `peer_group` have no source in a configuration file."""
    _, csm = rtr

    assert csm.device.role is None
    assert csm.device.site is None
    assert csm.device.peer_group is None


# ---------------------------------------------------------------------------
# Determined fields cross the boundary unchanged
# ---------------------------------------------------------------------------

RTR_EXPECTED = {
    "ssh_version": (2, 12),
    "telnet_enabled": (False, 38),
    "http_server_enabled": (False, 13),
    "https_server_enabled": (True, 14),
    "idle_timeout_seconds": (600, 39),
    "banner_present": (True, 22),
}


@pytest.mark.parametrize("name,expected", list(RTR_EXPECTED.items()))
def test_rtr_core_fields_survive_normalisation(rtr, name, expected) -> None:
    value, line = expected
    _, csm = rtr
    field = csm.fields[name]

    assert field.state is FieldState.PRESENT
    assert field.value == value
    assert field.confidence == 1.0
    assert field.confidence_method is ConfidenceMethod.DETERMINISTIC
    assert [e.line_start for e in field.evidence] == [line]


def test_multi_valued_fields_survive(rtr) -> None:
    _, csm = rtr

    assert csm.fields["ntp_servers"].value == ["192.0.2.20", "192.0.2.21"]
    assert [e.line_start for e in csm.fields["ntp_servers"].evidence] == [19, 20]
    assert csm.fields["logging_hosts"].value == ["192.0.2.10"]


def test_a_determined_field_is_the_same_object_it_was_in_the_parse(rtr) -> None:
    """Rule 2 at the trust boundary: no opportunity to drop a citation.

    `Field` is frozen, so passing it through by reference makes "unchanged"
    literal rather than a property that has to be re-checked.
    """
    parsed, csm = rtr

    for name, field in parsed.fields.items():
        if field.is_determinable:
            assert csm.fields[name] is field


def test_all_eight_fields_are_present_on_rtr_core(rtr) -> None:
    _, csm = rtr

    assert len(csm.fields) == 8
    assert len(csm.determinable_fields()) == 8
    assert csm.coverage() == 1.0


# ---------------------------------------------------------------------------
# Absence, against the real pack
# ---------------------------------------------------------------------------

SW_ABSENT = ["ssh_version", "https_server_enabled", "banner_present"]


@pytest.mark.parametrize("name", SW_ABSENT)
def test_absent_fields_abstain_because_capability_is_undocumented(sw, name) -> None:
    """The shipped Cisco pack documents no capabilities, so every absence abstains.

    Not ABSENT_UNSUPPORTED and not ABSENT_DEFAULT: nothing has been sourced that
    would justify either. This is the state P5 ships in, deliberately.
    """
    _, csm = sw
    field = csm.fields[name]

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
    assert field.value is None
    assert not field.is_determinable


def test_the_reason_changed_from_no_match_to_capability_unknown(sw) -> None:
    """P5's contribution to an absent field, visible as a change of reason.

    P4 could only say "no line matched". P5 asks the further question — can this
    platform even express the control — and reports that it does not know.
    """
    parsed, csm = sw

    assert parsed.fields["ssh_version"].unknown_reason is UnknownReason.NO_MATCH
    assert csm.fields["ssh_version"].unknown_reason is UnknownReason.CAPABILITY_UNKNOWN


def test_sw_access_determined_fields_are_unchanged(sw) -> None:
    _, csm = sw

    assert csm.fields["telnet_enabled"].value is True
    assert [e.line_start for e in csm.fields["telnet_enabled"].evidence] == [17]
    assert csm.fields["idle_timeout_seconds"].value == 1800
    assert len(csm.determinable_fields()) == 5
    assert len(csm.abstained_fields()) == 3


# ---------------------------------------------------------------------------
# Residue
# ---------------------------------------------------------------------------


def test_residue_reaches_the_csm_with_positions_intact(rtr) -> None:
    parsed, csm = rtr

    assert csm.residue_count == len(parsed.residue)
    assert [line.line_number for line in csm.residue] == [
        node.line_number for node in parsed.residue
    ]


def test_residue_carries_no_comments_or_banner_prose(rtr) -> None:
    """Inherited from P4: those never became nodes, so they cannot arrive here."""
    _, csm = rtr
    texts = [line.raw_line_scrubbed for line in csm.residue]

    assert not any(t.startswith("!") for t in texts)
    assert not any("Authorised access only" in t for t in texts)


def test_acls_and_interfaces_are_empty_and_that_is_deliberate(rtr) -> None:
    """The corpus contains no ACL in any split — see CORPUS_PREREQUISITES.md."""
    _, csm = rtr

    assert csm.acls == ()
    assert csm.interfaces == ()


# ---------------------------------------------------------------------------
# A detection-only pack still normalises
# ---------------------------------------------------------------------------


def test_a_detection_only_pack_yields_a_valid_empty_csm() -> None:
    """Arista is recognised but not yet parseable. That is an honest state.

    Device identity is established, no field is claimed, and the whole file
    becomes residue for the training queue — not an exception.
    """
    pack = next(p for p in load_active_packs(use_cache=False) if p.vendor == "arista")
    assert pack.is_detection_only

    path = Path("corpus/arista/dev/sw-leaf-01.cfg")
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(
        path.read_text(encoding="utf-8"), pack, file_id=file_id, file_path=str(path)
    )
    csm = build_csm(parsed, pack, device_id=file_id)

    assert csm.fields == {}
    assert csm.coverage() == 0.0
    assert csm.residue_count > 0
    assert csm.device.vendor == "arista"
