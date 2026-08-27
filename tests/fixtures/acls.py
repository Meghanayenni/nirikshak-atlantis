"""Builders for constructed ACL objects (decisions D20, D21).

**These are contract instances, not corpus files.** The corpus contains no access
lists in any split, and P7 adds none: ACL *extraction* stays out of the parser
until real configuration evidence exists, so nothing here claims vendor ACL
parsing coverage.

What they do give is the analyser's test surface. Interval containment is
arithmetic — whether entry 40's range sits inside entry 20's does not depend on
which vendor wrote either line — so building `ACLEntry` objects directly tests
the analysis exhaustively without inventing vendor syntax. Same standing as the
P6 operator matrix, which tested `lte` without needing a configuration that used
it.

The evidence attached to each entry is synthetic and labelled as such. P9 may
state that the analyser is correct on constructed cases; it may **not** state a
detection rate against real-world access lists, because none have been seen.
"""

from __future__ import annotations

from api.models.acl import ACL, ACLEntry, AclEntryFlags, AddrSpec, PortSpec, ProtocolSpec
from api.models.enums import AclAction, AclType, AddrKind, PortOp, SourceType
from api.models.evidence import Evidence

SYNTHETIC_FILE = "synthetic-acl-fixture.cfg"
"""Named so it can never be mistaken for a corpus path in a report or a test."""


def evidence(seq: int, text: str) -> Evidence:
    return Evidence(
        file_id="f" * 64,
        file_path=SYNTHETIC_FILE,
        line_start=seq,
        line_end=seq,
        raw_line=text,
        source_type=SourceType.CLI,
    )


def any_addr() -> AddrSpec:
    return AddrSpec(kind=AddrKind.ANY, value="any")


def cidr(value: str) -> AddrSpec:
    return AddrSpec(kind=AddrKind.CIDR, value=value, resolved_cidrs=(value,))


def host(value: str) -> AddrSpec:
    return AddrSpec(kind=AddrKind.HOST, value=value, resolved_cidrs=(f"{value}/32",))


def unresolved_object(name: str = "grp-internal") -> AddrSpec:
    """An object-group whose members are not known here.

    Legal by contract: `resolved_cidrs` is required only for HOST and CIDR. Its
    interval is unknown, **not empty** — which is the whole of decision D24.
    """
    return AddrSpec(kind=AddrKind.OBJECT, value=name)


def resolved_object(name: str, *cidrs: str) -> AddrSpec:
    """An object-group that *has* been resolved. Analysable like any other."""
    return AddrSpec(kind=AddrKind.OBJECT, value=name, resolved_cidrs=tuple(cidrs))


def port(op: PortOp = PortOp.ANY, low: int | None = None, high: int | None = None) -> PortSpec:
    kw: dict[str, object] = {"op": op}
    if low is not None:
        kw["low"] = low
    if high is not None:
        kw["high"] = high
    return PortSpec(**kw)  # type: ignore[arg-type]


def entry(
    seq: int,
    action: AclAction = AclAction.PERMIT,
    protocol: str = "ip",
    src: AddrSpec | None = None,
    dst: AddrSpec | None = None,
    src_port: PortSpec | None = None,
    dst_port: PortSpec | None = None,
    *,
    established: bool = False,
    disabled: bool = False,
    text: str | None = None,
) -> ACLEntry:
    return ACLEntry(
        seq=seq,
        action=action,
        protocol=ProtocolSpec(name=protocol),
        src=src or any_addr(),
        dst=dst or any_addr(),
        src_port=src_port or port(),
        dst_port=dst_port or port(),
        flags=AclEntryFlags(established=established, disabled=disabled),
        evidence=(evidence(seq, text or f"{seq} {action.value} {protocol} ..."),),
    )


def acl(*entries: ACLEntry, name: str = "TEST-ACL", acl_id: str = "acl-1") -> ACL:
    return ACL(
        acl_id=acl_id,
        name=name,
        acl_type=AclType.EXTENDED,
        entries=tuple(entries),
    )
