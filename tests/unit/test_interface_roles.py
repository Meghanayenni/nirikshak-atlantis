"""Declaring which interfaces are management-plane, and refusing to guess it.

P12's exposure ranking abstains on every corpus device with
`indeterminate_interfaces`: three interfaces are read and nothing establishes
which is the management plane. `InterfaceRole` is the construct that could say
so — a **claim about the platform**, carrying the same typed provenance as a
platform default, admissible only when sourced.

**No pack ships one.** Nothing in this repository documents which interface
names a vendor designates as management-plane, and `Loopback0`'s description of
`MGMT-LOOPBACK` is operator free text, not documentation (DEF-2, D76). So the
construct ships empty, P12 keeps abstaining, and this module proves the path is
wired rather than dead by exercising it against a constructed pack.

That split is deliberate and is the same shape as D73: the mechanism is proven
in both directions, and no shipped pack claims anything it cannot cite.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.ingest.packs import load_active_packs
from api.models.csm import CanonicalSecurityModel, DeviceIdentity, Interface
from api.models.enums import PlatformSourceType, ProvenanceStatus
from api.models.pack import InterfaceRole, PlatformProvenance, VendorPack
from api.normalise.service import _classify_interfaces

SOURCED = PlatformProvenance(
    platform="acme/os",
    source_type=PlatformSourceType.VENDOR_DOCUMENTATION,
    source_id="ACME OS Configuration Guide, release 9",
    locator="§4.2, table 4-1",
    status=ProvenanceStatus.SOURCED,
)

ASSERTED = PlatformProvenance(
    platform="acme/os",
    source_type=PlatformSourceType.PROJECT_ASSERTED,
    status=ProvenanceStatus.PROJECT_ASSERTED,
)


def pack_with(*roles: InterfaceRole) -> VendorPack:
    return VendorPack(
        vendor="acme", os_family="os", pack_version="1.0.0", interface_roles=roles
    )


def interfaces(*names: str) -> tuple[Interface, ...]:
    return tuple(Interface(name=name) for name in names)


# ---------------------------------------------------------------------------
# The shipped state
# ---------------------------------------------------------------------------


def test_no_shipped_pack_declares_an_interface_role() -> None:
    """**This test is expected to be deleted** by the first sourced role.

    It fails loudly at that point so whoever adds one has to look at the
    provenance rules above rather than adding a classification quietly — the
    same gate `test_no_platform_defaults_are_shipped_yet` puts in front of a
    platform default, and for the same reason: an interface role decides what
    an operator is told to fix first.
    """
    declared = {p.pack_id: len(p.interface_roles) for p in load_active_packs(use_cache=False)}

    assert all(count == 0 for count in declared.values()), (
        f"platform knowledge appeared without a sourcing review: {declared}"
    )


def test_the_corpus_still_has_no_management_plane() -> None:
    """The honest consequence, stated as a measurement rather than a plan.

    Every interface NIRIKSHAK reads is `is_management=None`, so P12 abstains
    with `indeterminate_interfaces`. That is SOURCING_BACKLOG gap 2 in a new
    place, not a defect in this construct.
    """
    for pack in load_active_packs(use_cache=False):
        assert pack.admissible_interface_roles == ()


# ---------------------------------------------------------------------------
# What a sourced role does
# ---------------------------------------------------------------------------


def test_a_sourced_role_classifies_and_cites() -> None:
    role = InterfaceRole(
        name_pattern=r"^Management\d+$", is_management=True, provenance=SOURCED
    )
    out = _classify_interfaces(interfaces("Management0"), pack_with(role))

    assert out[0].is_management is True
    assert "ACME OS Configuration Guide" in out[0].management_ref


def test_a_name_matching_no_role_stays_undocumented() -> None:
    """The whole point, and the failure mode DEF-2 is named after.

    Declaring that `Management0` is the management plane says **nothing** about
    `GigabitEthernet0/0`. Returning `False` here would let one declaration
    silently classify every interface on the device, and the exposure ranking
    would then de-prioritise findings on an interface nobody ever looked at.
    """
    role = InterfaceRole(
        name_pattern=r"^Management\d+$", is_management=True, provenance=SOURCED
    )
    out = _classify_interfaces(interfaces("GigabitEthernet0/0"), pack_with(role))

    assert out[0].is_management is None, "silence is not a classification"
    assert out[0].management_ref is None


def test_saying_not_management_takes_its_own_declaration() -> None:
    """`is_management is False` is a determinable state the ranking acts on.

    So it is exactly as capable of producing a wrong answer as a `True`, and it
    needs its own citation rather than arriving as the absence of one.
    """
    role = InterfaceRole(
        name_pattern=r"^GigabitEthernet", is_management=False, provenance=SOURCED
    )
    out = _classify_interfaces(interfaces("GigabitEthernet0/0"), pack_with(role))

    assert out[0].is_management is False
    assert out[0].management_ref


def test_a_project_asserted_role_classifies_nothing() -> None:
    """It may be written down and reviewed. It may not reach the ranking."""
    role = InterfaceRole(
        name_pattern=r"^Management\d+$", is_management=True, provenance=ASSERTED
    )
    pack = pack_with(role)

    assert pack.interface_roles, "the declaration is kept"
    assert pack.admissible_interface_roles == (), "and is not admissible"
    assert _classify_interfaces(interfaces("Management0"), pack)[0].is_management is None


def test_a_pack_with_no_roles_returns_its_interfaces_untouched() -> None:
    before = interfaces("Gi0/0", "Gi0/1")
    assert _classify_interfaces(before, pack_with()) == before


# ---------------------------------------------------------------------------
# The contract's refusals
# ---------------------------------------------------------------------------


def test_an_unanchored_pattern_is_refused() -> None:
    """`Management0` unanchored also matches `not-Management0`.

    That is how a role declaration quietly becomes the heuristic it exists to
    replace.
    """
    with pytest.raises(ValidationError, match="not anchored"):
        InterfaceRole(
            name_pattern=r"Management\d+$", is_management=True, provenance=SOURCED
        )


def test_an_example_that_does_not_match_its_own_pattern_is_refused() -> None:
    """An example is the evidence a person read the declaration."""
    with pytest.raises(ValidationError, match="does not match its own pattern"):
        InterfaceRole(
            name_pattern=r"^Management\d+$",
            is_management=True,
            provenance=SOURCED,
            examples=("Loopback0",),
        )


def test_two_roles_matching_the_same_names_are_refused() -> None:
    """Otherwise the classification depends on declaration order."""
    role = InterfaceRole(
        name_pattern=r"^Management\d+$", is_management=True, provenance=SOURCED
    )
    other = InterfaceRole(
        name_pattern=r"^Management\d+$", is_management=False, provenance=SOURCED
    )
    with pytest.raises(ValidationError, match="duplicate interface role patterns"):
        pack_with(role, other)


def test_a_classification_without_a_citation_cannot_be_constructed() -> None:
    """Rule 2 over an assertion that rests on a document, not on a line."""
    with pytest.raises(ValidationError, match="with no citation"):
        Interface(name="Management0", is_management=True)


# ---------------------------------------------------------------------------
# End to end — the ranking does produce a score once the plane is located
# ---------------------------------------------------------------------------


def test_exposure_stops_abstaining_once_a_role_locates_the_plane() -> None:
    """Proof the deferred capability raises rather than silently degrading.

    Nothing on the corpus exercises this, so it is exercised on constructed
    input. Without that, "P12 abstains" and "P12 is broken" would look the same
    from outside.
    """
    from api.models.acl import ACL, AclApplication, ACLEntry, AddrSpec, ProtocolSpec
    from api.models.enums import (
        AclAction,
        AclType,
        AddrKind,
        Direction,
        Severity,
        SourceType,
    )
    from api.models.evidence import Evidence
    from api.prioritise.exposure import ExposureDeterminacy, assess

    role = InterfaceRole(
        name_pattern=r"^Management\d+$", is_management=True, provenance=SOURCED
    )
    classified = _classify_interfaces(
        (Interface(name="Management0", ip_addresses=("192.0.2.1",)),), pack_with(role)
    )

    evidence = Evidence(
        file_id="f" * 64,
        file_path="constructed.cfg",
        line_start=1,
        line_end=1,
        raw_line="permit ip any any",
        source_type=SourceType.CLI,
    )
    acl = ACL(
        acl_id="A",
        name="A",
        acl_type=AclType.EXTENDED,
        applied_to=(AclApplication(interface="Management0", direction=Direction.IN),),
        entries=(
            ACLEntry(
                seq=1,
                action=AclAction.PERMIT,
                protocol=ProtocolSpec(name="ip"),
                src=AddrSpec(kind=AddrKind.ANY, value="any"),
                dst=AddrSpec(kind=AddrKind.ANY, value="any"),
                evidence=(evidence,),
            ),
        ),
    )
    csm = CanonicalSecurityModel(
        device=DeviceIdentity(device_id="d1"), interfaces=classified, acls=(acl,)
    )

    before = assess(
        CanonicalSecurityModel(
            device=DeviceIdentity(device_id="d1"),
            interfaces=(Interface(name="Management0", ip_addresses=("192.0.2.1",)),),
            acls=(acl,),
        ),
        field_name="ssh_version",
        severity=Severity.HIGH,
    )
    after = assess(csm, field_name="ssh_version", severity=Severity.HIGH)

    assert before.determinacy is ExposureDeterminacy.INDETERMINATE_INTERFACES
    assert after.determinacy is ExposureDeterminacy.DETERMINED
    assert after.score is not None and after.score > 0
