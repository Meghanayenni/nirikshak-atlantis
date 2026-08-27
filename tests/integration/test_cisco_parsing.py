"""End-to-end parsing of the Cisco development corpus.

Exact values and exact line numbers, asserted against the two files the pack was
authored from. The two disagree on five of the eight fields, which is what makes
them worth testing against: a pattern with its sense backwards fails here rather
than passing on uniform data.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.ingest.packs import load_active_packs
from api.models import ConfidenceMethod, FieldState, UnknownReason
from api.parse.service import parse_configuration

DEV = Path("corpus/cisco/dev")


@pytest.fixture(scope="module")
def cisco():
    pack = next(p for p in load_active_packs(use_cache=False) if p.vendor == "cisco")
    assert pack.pack_version == "1.1.0", "the active Cisco pack should be the parsing pack"
    return pack


def parse(name: str, cisco):
    path = DEV / name
    text = path.read_text(encoding="utf-8")
    return (
        parse_configuration(
            text,
            cisco,
            file_id=hashlib.sha256(path.read_bytes()).hexdigest(),
            file_path=f"corpus/cisco/dev/{name}",
        ),
        text,
    )


@pytest.fixture(scope="module")
def rtr(cisco):
    return parse("rtr-core-01.cfg", cisco)


@pytest.fixture(scope="module")
def sw(cisco):
    return parse("sw-access-02.cfg", cisco)


# ---------------------------------------------------------------------------
# The pack is now a parsing pack
# ---------------------------------------------------------------------------


def test_cisco_pack_is_no_longer_detection_only(cisco) -> None:
    assert not cisco.is_detection_only
    # 9, not 12: three patterns were removed at review because no line in the
    # development corpus could verify them. See ADR 0011.
    assert len(cisco.patterns) == 9
    assert cisco.parent_version == "1.0.0"


def test_all_patterns_self_check(cisco) -> None:
    assert cisco.validate_patterns() == {}


def test_eight_declared_fields(cisco) -> None:
    from api.parse.fields import declared_fields

    assert declared_fields(cisco) == [
        "ssh_version",
        "telnet_enabled",
        "http_server_enabled",
        "https_server_enabled",
        "idle_timeout_seconds",
        "logging_hosts",
        "ntp_servers",
        "banner_present",
    ]


# ---------------------------------------------------------------------------
# rtr-core-01 — exact values, exact lines
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field_name", "value", "lines"),
    [
        ("ssh_version", 2, [12]),
        ("telnet_enabled", False, [38]),
        ("http_server_enabled", False, [13]),
        ("https_server_enabled", True, [14]),
        ("idle_timeout_seconds", 600, [39]),
        ("logging_hosts", ["192.0.2.10"], [16]),
        ("ntp_servers", ["192.0.2.20", "192.0.2.21"], [19, 20]),
        ("banner_present", True, [22]),
    ],
)
def test_rtr_core_fields(rtr, field_name: str, value: object, lines: list[int]) -> None:
    result, _ = rtr
    field = result.fields[field_name]

    assert field.state is FieldState.PRESENT, f"{field_name} should be present"
    assert field.value == value
    assert [e.line_start for e in field.evidence] == lines


def test_rtr_core_determines_every_field(rtr) -> None:
    result, _ = rtr
    assert len(result.determinable) == 8
    assert result.abstained == {}


# ---------------------------------------------------------------------------
# sw-access-02 — the contrast, including three honest abstentions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field_name", "value", "lines"),
    [
        ("telnet_enabled", True, [17]),
        ("http_server_enabled", False, [7]),
        ("idle_timeout_seconds", 1800, [18]),
        ("logging_hosts", ["192.0.2.10"], [9]),
        ("ntp_servers", ["192.0.2.20"], [10]),
    ],
)
def test_sw_access_fields(sw, field_name: str, value: object, lines: list[int]) -> None:
    result, _ = sw
    field = result.fields[field_name]

    assert field.state is FieldState.PRESENT
    assert field.value == value
    assert [e.line_start for e in field.evidence] == lines


@pytest.mark.parametrize("field_name", ["ssh_version", "https_server_enabled", "banner_present"])
def test_sw_access_abstains_where_the_directive_is_absent(sw, field_name: str) -> None:
    result, _ = sw
    field = result.fields[field_name]

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.NO_MATCH
    assert field.value is None
    assert field.evidence == ()


def test_telnet_differs_across_the_two_devices(rtr, sw) -> None:
    """The sharpest pair in the corpus, and the reason both files are here."""
    assert rtr[0].fields["telnet_enabled"].value is False
    assert sw[0].fields["telnet_enabled"].value is True


# ---------------------------------------------------------------------------
# Scoping, evidence, structure
# ---------------------------------------------------------------------------


def test_console_timeout_is_not_the_management_timeout(rtr) -> None:
    """rtr-core-01 line 36 is `exec-timeout 0 0` under `line con 0`."""
    result, text = rtr
    lines = text.split("\n")

    assert lines[35].strip() == "exec-timeout 0 0", "fixture drifted"
    assert result.fields["idle_timeout_seconds"].value == 600
    assert [e.line_start for e in result.fields["idle_timeout_seconds"].evidence] == [39]


def test_banner_body_is_not_parsed(rtr) -> None:
    result, _ = rtr
    body = "Authorised access only. Activity is monitored."

    assert all(body not in n.text for n in result.tree.nodes.values())
    assert all(body not in n.text for n in result.residue)
    assert any(u.raw_line == body for u in result.tree.unplaced)


def test_comments_are_not_nodes_or_residue(rtr) -> None:
    result, _ = rtr
    assert all(not n.text.startswith("!") for n in result.tree.nodes.values())
    assert all(not n.text.startswith("!") for n in result.residue)


@pytest.mark.parametrize("name", ["rtr-core-01.cfg", "sw-access-02.cfg"])
def test_tree_is_lossless(cisco, name: str) -> None:
    result, text = parse(name, cisco)
    assert result.tree.verify_lossless(text)


@pytest.mark.parametrize("name", ["rtr-core-01.cfg", "sw-access-02.cfg"])
def test_every_evidence_line_quotes_the_real_source(cisco, name: str) -> None:
    result, text = parse(name, cisco)
    lines = text.replace("\r\n", "\n").split("\n")

    for field_name, field in result.fields.items():
        for evidence in field.evidence:
            assert lines[evidence.line_start - 1] == evidence.raw_line, (
                f"{field_name} cites line {evidence.line_start} but the text differs"
            )


@pytest.mark.parametrize("name", ["rtr-core-01.cfg", "sw-access-02.cfg"])
def test_every_present_field_carries_evidence(cisco, name: str) -> None:
    result, _ = parse(name, cisco)
    for field_name, field in result.fields.items():
        if field.state is FieldState.PRESENT:
            assert field.evidence, f"{field_name} is PRESENT without evidence"


@pytest.mark.parametrize("name", ["rtr-core-01.cfg", "sw-access-02.cfg"])
def test_all_confidence_is_deterministic(cisco, name: str) -> None:
    """D6 — no similarity confidence anywhere in P4."""
    result, _ = parse(name, cisco)
    for field_name, field in result.fields.items():
        assert field.confidence_method is ConfidenceMethod.DETERMINISTIC, field_name
        assert not field.confidence_is_probability
        if field.state is FieldState.PRESENT:
            assert field.confidence == 1.0


@pytest.mark.parametrize("name", ["rtr-core-01.cfg", "sw-access-02.cfg"])
def test_parsing_is_deterministic(cisco, name: str) -> None:
    first, _ = parse(name, cisco)
    second, _ = parse(name, cisco)

    assert first.tree.reconstruct() == second.tree.reconstruct()
    assert {k: v.value for k, v in first.fields.items()} == {
        k: v.value for k, v in second.fields.items()
    }


def test_provenance_records_the_pack_version(rtr) -> None:
    result, _ = rtr
    provenance = result.fields["ssh_version"].provenance

    assert provenance is not None
    assert provenance.pack_id == "cisco/ios"
    assert provenance.pack_version == "1.1.0"
    assert provenance.pattern_id == "p-ssh-version-001"


def test_residue_holds_only_unmatched_commands(rtr) -> None:
    result, _ = rtr
    residue_text = [n.text for n in result.residue]

    assert "version 17.9" in residue_text, "unmatched commands become residue"
    assert "ip ssh version 2" not in residue_text, "matched commands do not"
    assert result.residue_count > 0


def test_result_summary(rtr, sw) -> None:
    assert rtr[0].coverage() == 1.0
    assert sw[0].coverage() == pytest.approx(5 / 8)
    assert "8/8" in rtr[0].summary()
