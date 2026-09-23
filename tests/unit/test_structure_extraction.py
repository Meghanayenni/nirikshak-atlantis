"""Reading access lists and interfaces out of a tree (P16).

Everything downstream of this has existed since P7 and produced nothing, because
`build_csm` returned `acls=()` and `interfaces=()` unconditionally. These tests
cover the step that was missing, and in particular the property that makes its
output safe to analyse: **an access list is emitted whole or not at all.**
"""

from __future__ import annotations

from api.models.enums import AclDialect, AclType, AddrKind, Direction, PortOp, SyntaxMode
from api.models.pack import AclExtraction, InterfaceExtraction, VendorPack
from api.parse.block_parser import build_tree
from api.parse.structures import extract_acls, extract_interfaces

FILE_ID = "f" * 64

ACL_SPEC = AclExtraction(
    dialect=AclDialect.IOS_WILDCARD,
    acl_type=AclType.EXTENDED,
    named_block=r"^ip access-list extended (\S+)$",
    applied=r"^ip access-group (\S+) (in|out)$",
    remark=r"^remark (.*)$",
)

IFACE_SPEC = InterfaceExtraction(
    block=r"^interface (\S+)$",
    description=r"^description (.+)$",
    ip_address=r"^ip address (\S+) (\S+)$",
    shutdown=r"^shutdown$",
    no_shutdown=r"^no shutdown$",
)


def pack(**kw) -> VendorPack:
    base = {
        "vendor": "cisco",
        "os_family": "ios",
        "pack_version": "9.9.9",
        "acl_extraction": ACL_SPEC,
        "interface_extraction": IFACE_SPEC,
        "comment_prefixes": ("!",),
    }
    base.update(kw)
    return VendorPack(**base)


def tree(text: str):
    return build_tree(
        text, file_id=FILE_ID, file_path="d.cfg", mode=SyntaxMode.INDENT, comment_prefixes=("!",)
    )


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


def test_an_interface_carries_its_address_state_and_citations() -> None:
    t = tree(
        "interface GigabitEthernet0/0\n"
        " description WAN-UPLINK\n"
        " ip address 203.0.113.2 255.255.255.252\n"
        " no shutdown\n"
    )
    interfaces = extract_interfaces(t, pack())

    assert len(interfaces) == 1
    gi0 = interfaces[0]
    assert gi0.name == "GigabitEthernet0/0"
    assert gi0.description == "WAN-UPLINK"
    assert gi0.ip_addresses == ("203.0.113.2",)
    assert gi0.enabled is True
    assert len(gi0.evidence) == 4


def test_management_status_stays_undocumented_rather_than_guessed() -> None:
    """DEF-2 — an undocumented interface is not a non-management one.

    Nothing in the pack declares which interfaces are the management plane, and
    a description reading `MGMT-LOOPBACK` is operator free text, not a fact about
    the platform. Inferring from it would be exactly the invention this project
    refuses, so the field stays None and the exposure layer abstains.
    """
    t = tree("interface Loopback0\n description MGMT-LOOPBACK\n")
    interface = extract_interfaces(t, pack())[0]

    assert interface.is_management is None


def test_shutdown_is_read_as_disabled() -> None:
    t = tree("interface GigabitEthernet0/2\n shutdown\n")
    assert extract_interfaces(t, pack())[0].enabled is False


# ---------------------------------------------------------------------------
# Access lists
# ---------------------------------------------------------------------------


def test_a_wildcard_mask_becomes_a_cidr() -> None:
    t = tree(
        "ip access-list extended MGMT-IN\n"
        " permit tcp 198.51.100.0 0.0.0.255 any eq 22\n"
        " deny   ip any any log\n"
    )
    acl = extract_acls(t, pack())[0][0]

    assert acl.name == "MGMT-IN"
    assert len(acl.entries) == 2

    first = acl.entries[0]
    assert first.src.kind is AddrKind.CIDR
    assert first.src.resolved_cidrs == ("198.51.100.0/24",)
    assert first.dst.kind is AddrKind.ANY
    assert first.dst_port.op is PortOp.EQ
    assert first.dst_port.low == 22

    assert acl.entries[1].flags.log is True


def test_remarks_are_not_entries() -> None:
    """A remark is a comment. Counting one as an entry would shift every
    sequence number after it, and sequence order is what shadowing analysis
    reasons about."""
    t = tree(
        "ip access-list extended R\n"
        " remark permit established return traffic\n"
        " permit tcp any any established\n"
    )
    acl = extract_acls(t, pack())[0][0]

    assert len(acl.entries) == 1
    assert acl.entries[0].seq == 1
    assert acl.entries[0].flags.established is True


def test_the_overly_permissive_shape_is_recognised() -> None:
    t = tree("ip access-list extended R\n permit ip any any\n")
    assert extract_acls(t, pack())[0][0].entries[0].is_permit_any_any is True


def test_an_unreadable_entry_drops_the_whole_list() -> None:
    """The property that makes the output safe to analyse.

    Order is semantically significant: entry three shadows entry five because of
    what sits between them. A list missing one entry nobody could read would let
    the analyser call a reachable rule unreachable, confidently. A partially
    parsed ACL is worse than none, because it looks complete.
    """
    t = tree(
        "ip access-list extended R\n"
        " permit tcp any any eq 22\n"
        " permit tcp any any eq wildly-unknown-service\n"
        " deny   ip any any\n"
    )
    assert extract_acls(t, pack())[0] == ()


def test_a_non_contiguous_wildcard_drops_the_list_rather_than_inventing_a_range() -> None:
    """`0.0.0.254` matches a discontiguous set of addresses. There is no CIDR
    for that, and inventing the nearest one would feed a wrong interval into
    shadowing analysis."""
    t = tree("ip access-list extended R\n permit ip 10.0.0.0 0.0.0.254 any\n")
    assert extract_acls(t, pack())[0] == ()


def test_a_list_records_where_it_is_bound() -> None:
    t = tree(
        "interface GigabitEthernet0/0\n"
        " ip access-group MGMT-IN in\n"
        "ip access-list extended MGMT-IN\n"
        " permit ip any any\n"
    )
    p = pack()
    interfaces = extract_interfaces(t, p)
    acl = extract_acls(t, p, interfaces)[0][0]

    assert interfaces[0].applied_acls[0].acl_id == "MGMT-IN"
    assert interfaces[0].applied_acls[0].direction is Direction.IN
    assert acl.applied_to[0].interface == "GigabitEthernet0/0"
    assert acl.applied_to[0].direction is Direction.IN


def test_a_pack_declaring_no_extraction_yields_nothing() -> None:
    """Every platform without a declaration keeps the previous behaviour."""
    t = tree("interface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n")
    bare = pack(acl_extraction=None, interface_extraction=None)

    assert extract_interfaces(t, bare) == ()
    assert extract_acls(t, bare)[0] == ()


# ---------------------------------------------------------------------------
# A dropped list is announced, not silently absent
# ---------------------------------------------------------------------------


def test_a_dropped_list_names_itself_and_the_entry_that_defeated_it() -> None:
    """A dropped list and a device with no access lists are both `()`.

    They call for opposite responses — "nobody has taught the parser this
    syntax" against "this device filters nothing" — and the more alarming of the
    two is the one that looks like silence.
    """
    t = tree(
        "ip access-list extended EDGE-IN\n"
        " permit tcp any any eq 22\n"
        " permit ip 10.0.0.0 0.0.0.254 any\n"
        " deny   ip any any\n"
    )
    acls, failures = extract_acls(t, pack())

    assert acls == ()
    assert len(failures) == 1

    failure = failures[0]
    assert failure.acl_name == "EDGE-IN"
    assert failure.entry_line == 3
    assert "non-contiguous" in failure.reason
    assert "EDGE-IN was not analysed" in failure.describe()


def test_an_unknown_port_keyword_is_named_in_the_reason() -> None:
    """The reason points at one token, not at the whole list."""
    t = tree("ip access-list extended R\n permit tcp any any eq wildly-unknown\n")
    _, failures = extract_acls(t, pack())

    assert "wildly-unknown" in failures[0].reason
    assert "guessing its number" in failures[0].reason


def test_a_fully_readable_list_reports_no_failure() -> None:
    t = tree("ip access-list extended R\n permit ip any any\n")
    acls, failures = extract_acls(t, pack())

    assert len(acls) == 1
    assert failures == ()
