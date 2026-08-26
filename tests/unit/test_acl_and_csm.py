"""ACL interval normalisation and the Canonical Security Model."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.models import (
    ACL,
    AclAction,
    ACLEntry,
    AclType,
    AddrKind,
    AddrSpec,
    CanonicalSecurityModel,
    ConfidenceMethod,
    DeviceIdentity,
    Evidence,
    Field,
    FieldState,
    Interface,
    PortOp,
    PortSpec,
    ProtocolSpec,
    SourceType,
    UnknownLine,
    UnknownReason,
)

EV = Evidence(
    file_id="f1",
    file_path="rtr.cfg",
    line_start=1,
    line_end=1,
    raw_line="permit tcp any any eq 22",
    source_type=SourceType.CLI,
)


# ---------------------------------------------------------------------------
# PortSpec — normalised to an inclusive interval for P7 analysis
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "low", "high"),
    [
        ({"op": PortOp.ANY}, 0, 65535),
        ({"op": PortOp.EQ, "low": 22}, 22, 22),
        ({"op": PortOp.RANGE, "low": 1000, "high": 2000}, 1000, 2000),
        ({"op": PortOp.LT, "high": 1024}, 0, 1023),
        ({"op": PortOp.GT, "low": 1023}, 1024, 65535),
    ],
)
def test_port_operators_normalise_to_intervals(spec: dict, low: int, high: int) -> None:
    p = PortSpec(**spec)
    assert (p.low, p.high) == (low, high)


def test_inverted_port_range_is_rejected() -> None:
    with pytest.raises(ValidationError, match="inverted"):
        PortSpec(op=PortOp.RANGE, low=2000, high=1000)


def test_port_overlap_detection() -> None:
    a = PortSpec(op=PortOp.RANGE, low=100, high=200)
    assert a.overlaps(PortSpec(op=PortOp.RANGE, low=150, high=300))
    assert not a.overlaps(PortSpec(op=PortOp.RANGE, low=201, high=300))


def test_any_port_is_recognised() -> None:
    assert PortSpec(op=PortOp.ANY).is_any


# ---------------------------------------------------------------------------
# AddrSpec
# ---------------------------------------------------------------------------


def test_cidr_must_resolve_for_interval_analysis() -> None:
    with pytest.raises(ValidationError, match="must resolve to at least one CIDR"):
        AddrSpec(kind=AddrKind.CIDR, value="10.0.0.0/8")


def test_invalid_cidr_is_rejected() -> None:
    with pytest.raises(ValidationError, match="invalid CIDR"):
        AddrSpec(kind=AddrKind.CIDR, value="bad", resolved_cidrs=("999.0.0.0/8",))


def test_valid_cidr_is_accepted() -> None:
    a = AddrSpec(kind=AddrKind.CIDR, value="10.0.0.0/8", resolved_cidrs=("10.0.0.0/8",))
    assert not a.is_any


def test_any_address_needs_no_resolution() -> None:
    assert AddrSpec(kind=AddrKind.ANY).is_any


def test_object_address_must_be_named() -> None:
    with pytest.raises(ValidationError, match="must name the object"):
        AddrSpec(kind=AddrKind.OBJECT)


# ---------------------------------------------------------------------------
# ACLEntry / ACL
# ---------------------------------------------------------------------------


def entry(seq: int = 10, **kw: object) -> ACLEntry:
    base: dict[str, object] = {
        "seq": seq,
        "action": AclAction.PERMIT,
        "protocol": ProtocolSpec(name="tcp", number=6),
        "src": AddrSpec(kind=AddrKind.ANY),
        "dst": AddrSpec(kind=AddrKind.ANY),
        "dst_port": PortSpec(op=PortOp.EQ, low=22),
        "evidence": (EV,),
    }
    base.update(kw)
    return ACLEntry(**base)  # type: ignore[arg-type]


def test_acl_entry_requires_evidence() -> None:
    """An ACL entry is a security claim like any other (Rule 2)."""
    with pytest.raises(ValidationError):
        entry(evidence=())


def test_permit_any_any_is_detected() -> None:
    permissive = entry(
        protocol=ProtocolSpec(name="ip"),
        dst_port=PortSpec(op=PortOp.ANY),
    )
    assert permissive.is_permit_any_any
    assert not entry().is_permit_any_any


def test_acl_entries_must_be_in_sequence_order() -> None:
    """Order is semantically significant for shadowing analysis."""
    with pytest.raises(ValidationError, match="out of sequence order"):
        ACL(
            acl_id="a1",
            name="MGMT-IN",
            acl_type=AclType.EXTENDED,
            entries=(entry(seq=20), entry(seq=10)),
        )


def test_acl_rejects_duplicate_sequence_numbers() -> None:
    with pytest.raises(ValidationError, match="duplicate entry sequence"):
        ACL(
            acl_id="a1",
            name="MGMT-IN",
            acl_type=AclType.EXTENDED,
            entries=(entry(seq=10), entry(seq=10)),
        )


def test_wellformed_acl() -> None:
    acl = ACL(
        acl_id="a1",
        name="MGMT-IN",
        acl_type=AclType.EXTENDED,
        entries=(entry(seq=10), entry(seq=20)),
    )
    assert len(acl.entries) == 2
    assert not acl.is_applied


# ---------------------------------------------------------------------------
# Canonical Security Model
# ---------------------------------------------------------------------------


def present_field(value: int = 2) -> Field[int]:
    return Field[int](
        value=value,
        state=FieldState.PRESENT,
        confidence=1.0,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
        evidence=(EV,),
    )


def test_csm_holds_fields_and_reports_coverage() -> None:
    csm = CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1", hostname="rtr-core-01", vendor="cisco"),
        fields={
            "ssh_version": present_field(),
            "telnet_enabled": Field[bool].unknown(UnknownReason.NO_MATCH),
        },
    )
    assert csm.state_of("ssh_version") is FieldState.PRESENT
    assert csm.state_of("telnet_enabled") is FieldState.UNKNOWN
    assert set(csm.determinable_fields()) == {"ssh_version"}
    assert set(csm.abstained_fields()) == {"telnet_enabled"}
    assert csm.coverage() == 0.5


def test_absent_field_is_treated_as_unknown_not_as_false() -> None:
    """A field the parser never produced is not determinable — it is not 'no'."""
    csm = CanonicalSecurityModel(device=DeviceIdentity(device_id="d1"))
    assert csm.state_of("telnet_enabled") is FieldState.UNKNOWN
    assert csm.get("telnet_enabled") is None
    assert csm.coverage() == 0.0


def test_csm_accepts_unregistered_field_names() -> None:
    """Rule 5 — adding a canonical field must not require a code change."""
    csm = CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1"),
        fields={"some_future_control": present_field()},
    )
    assert csm.state_of("some_future_control") is FieldState.PRESENT


def test_residue_is_first_class() -> None:
    csm = CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1"),
        residue=(
            UnknownLine(
                line_number=90,
                raw_line_scrubbed="set ssh proto-version 2",
                normalised_line="set ssh proto-version <NUM>",
                file_id="f1",
            ),
        ),
    )
    assert csm.residue_count == 1


def test_management_interfaces_are_selectable() -> None:
    csm = CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1"),
        interfaces=(
            Interface(name="Gi0/0", is_management=True),
            Interface(name="Gi0/1", is_management=False),
        ),
    )
    assert [i.name for i in csm.management_interfaces()] == ["Gi0/0"]


def test_csm_rejects_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        CanonicalSecurityModel(
            device=DeviceIdentity(device_id="d1"),
            raw_config="hostname r1",  # vendor syntax must not leak in
        )
