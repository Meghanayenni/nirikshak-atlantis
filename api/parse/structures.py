"""Access lists and interfaces, read out of a parsed configuration.

Everything downstream of this module has existed since P7 and produced nothing.
`ACL`, `ACLEntry`, `AddrSpec`, `PortSpec` and `Interface` are complete contracts,
the interval analyser is exhaustively tested against constructed objects, and the
exposure ranking at P12 abstains on every finding — all because
`build_csm` returned `acls=()` and `interfaces=()` unconditionally. Nothing ever
built one from a file. This module is that missing step.

## Why the entries are read in code and the structure is read from data

A pack declares *where* a list opens and *where* it is bound to an interface, as
anchored regexes (Rule 5). It does not declare the entry grammar, because an
access-control entry is a structured statement: `0.0.0.255` becomes `/24` by
arithmetic on a wildcard mask, not by matching. So the pack names a `dialect` and
the parser for that dialect lives here. Adding a platform that writes an existing
grammar stays a data change; a genuinely new grammar needs a parser, which is the
limit of "wherever the architecture permits".

## An ACL is emitted whole or not at all

**If any entry in a list cannot be parsed, the entire list is dropped** and its
lines stay in residue.

This looks harsh and is the only defensible behaviour. Order is semantically
significant for shadowing: entry three shadows entry five *because of what sits
between them*. A list missing one entry it could not read would let the analyser
conclude, confidently and wrongly, that a reachable rule is unreachable — or miss
a shadow that is really there. A partially parsed ACL is worse than no ACL,
because the output looks complete. Residue is the honest place for a line nobody
could read, and it is already the queue that asks a human.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from api.models.acl import (
    ACL,
    AclApplication,
    ACLEntry,
    AclEntryFlags,
    AddrSpec,
    PortSpec,
    ProtocolSpec,
)
from api.models.config_tree import ConfigNode, ConfigTree
from api.models.csm import Interface, InterfaceAcl
from api.models.enums import AclAction, AclDialect, AddrKind, Direction, PortOp, SourceType
from api.models.evidence import Evidence
from api.models.pack import VendorPack

__all__ = ["extract_interfaces", "extract_acls"]


def _evidence(node: ConfigNode, tree: ConfigTree, source_type: SourceType) -> Evidence:
    """A citation for one node. `line_sha256` is derived, never supplied."""
    return Evidence(
        file_id=node.file_id,
        file_path=tree.file_path,
        line_start=node.line_number,
        line_end=node.line_number,
        raw_line=node.raw_line,
        source_type=source_type,
        block_path=node.block_path,
    )


def _children(tree: ConfigTree, node: ConfigNode) -> list[ConfigNode]:
    return [tree.nodes[c] for c in node.children if c in tree.nodes]


# ---------------------------------------------------------------------------
# Address and port specifications
# ---------------------------------------------------------------------------


def _wildcard_to_cidr(address: str, wildcard: str) -> str | None:
    """`198.51.100.0 0.0.0.255` -> `198.51.100.0/24`, or None if it will not.

    A wildcard mask is an inverted netmask, and only a *contiguous* one has a
    prefix length. Non-contiguous masks are legal IOS and match a discontiguous
    set of addresses; there is no CIDR for that, so this returns None and the
    caller drops the whole list rather than inventing a range.
    """
    try:
        addr = ipaddress.IPv4Address(address)
        wild = ipaddress.IPv4Address(wildcard)
    except ValueError:
        return None

    netmask = int(wild) ^ 0xFFFFFFFF
    # A contiguous netmask is a run of ones followed by a run of zeros.
    if netmask and ((netmask ^ 0xFFFFFFFF) + 1) & (netmask ^ 0xFFFFFFFF):
        return None

    prefix = bin(netmask).count("1")
    try:
        return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
    except ValueError:
        return None


def _take_address(tokens: list[str]) -> AddrSpec | None:
    """Consume one address specification from the front of `tokens`."""
    if not tokens:
        return None

    head = tokens.pop(0)

    if head == "any":
        return AddrSpec(kind=AddrKind.ANY, value="any")

    if head == "host":
        if not tokens:
            return None
        value = tokens.pop(0)
        try:
            ipaddress.IPv4Address(value)
        except ValueError:
            return None
        return AddrSpec(kind=AddrKind.HOST, value=f"host {value}", resolved_cidrs=(f"{value}/32",))

    if head == "object-group":
        if not tokens:
            return None
        return AddrSpec(kind=AddrKind.OBJECT, value=tokens.pop(0))

    # `A.B.C.D W.W.W.W` — an address followed by a wildcard mask.
    if not tokens:
        return None
    wildcard = tokens.pop(0)
    cidr = _wildcard_to_cidr(head, wildcard)
    if cidr is None:
        return None
    return AddrSpec(kind=AddrKind.CIDR, value=f"{head} {wildcard}", resolved_cidrs=(cidr,))


_PORT_OPS = {"eq": PortOp.EQ, "lt": PortOp.LT, "gt": PortOp.GT, "neq": PortOp.NEQ}

_NAMED_PORTS = {
    "www": 80,
    "http": 80,
    "https": 443,
    "telnet": 23,
    "ssh": 22,
    "domain": 53,
    "ftp": 21,
    "smtp": 25,
    "snmp": 161,
    "syslog": 514,
    "ntp": 123,
    "bgp": 179,
    "tacacs": 49,
}
"""Port keywords IOS accepts in place of a number.

Deliberately small and only the ones the corpus uses. An unrecognised keyword
makes the entry unparseable and drops the list, which is correct: guessing a port
number would put a wrong interval into shadowing analysis.
"""


def _port_number(token: str) -> int | None:
    if token.isdigit():
        value = int(token)
        return value if 0 <= value <= 65535 else None
    return _NAMED_PORTS.get(token.lower())


def _take_port(tokens: list[str]) -> PortSpec | None | bool:
    """Consume a port specification if one is present.

    Returns the spec, `None` when the next token is not a port operator (not an
    error), or `False` when an operator is present but malformed.
    """
    if not tokens:
        return None

    head = tokens[0]

    if head == "range":
        if len(tokens) < 3:
            return False
        tokens.pop(0)
        low, high = _port_number(tokens.pop(0)), _port_number(tokens.pop(0))
        if low is None or high is None or low > high:
            return False
        return PortSpec(op=PortOp.RANGE, low=low, high=high)

    if head in _PORT_OPS:
        if len(tokens) < 2:
            return False
        op = _PORT_OPS[tokens.pop(0)]
        value = _port_number(tokens.pop(0))
        if value is None:
            return False
        return PortSpec(op=op, low=value, high=value)

    return None


# ---------------------------------------------------------------------------
# The IOS wildcard dialect
# ---------------------------------------------------------------------------


def _parse_ios_entry(
    node: ConfigNode, seq: int, tree: ConfigTree, source_type: SourceType
) -> ACLEntry | None:
    """One `permit`/`deny` line, or None if this parser cannot read it.

    None is not a soft failure. The caller drops the whole access list, because
    an entry it could not read changes what the entries around it shadow.
    """
    tokens = node.text.split()
    if not tokens:
        return None

    # A named IOS list may carry an explicit sequence number.
    if tokens[0].isdigit():
        tokens.pop(0)

    if not tokens or tokens[0] not in ("permit", "deny"):
        return None
    action = AclAction(tokens.pop(0))

    if not tokens:
        return None
    protocol = ProtocolSpec(name=tokens.pop(0).lower())

    src = _take_address(tokens)
    if src is None:
        return None

    src_port = _take_port(tokens)
    if src_port is False:
        return None

    dst = _take_address(tokens)
    if dst is None:
        return None

    dst_port = _take_port(tokens)
    if dst_port is False:
        return None

    flags = AclEntryFlags(
        established="established" in tokens,
        log="log" in tokens or "log-input" in tokens,
    )

    # Anything left that is not a flag we understand means the line says more
    # than this parser read, and a partially understood rule is not a rule.
    understood = {"established", "log", "log-input"}
    if any(token not in understood for token in tokens):
        return None

    return ACLEntry(
        seq=seq,
        action=action,
        protocol=protocol,
        src=src,
        src_port=src_port or PortSpec(op=PortOp.ANY),
        dst=dst,
        dst_port=dst_port or PortSpec(op=PortOp.ANY),
        flags=flags,
        evidence=(_evidence(node, tree, source_type),),
    )


_DIALECTS = {AclDialect.IOS_WILDCARD: _parse_ios_entry}


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def extract_interfaces(
    tree: ConfigTree, pack: VendorPack, source_type: SourceType = SourceType.CLI
) -> tuple[Interface, ...]:
    """Every interface the pack's declaration recognises."""
    spec = pack.interface_extraction
    if spec is None:
        return ()

    block = re.compile(spec.block)
    description = re.compile(spec.description) if spec.description else None
    ip_address = re.compile(spec.ip_address) if spec.ip_address else None
    shutdown = re.compile(spec.shutdown) if spec.shutdown else None
    no_shutdown = re.compile(spec.no_shutdown) if spec.no_shutdown else None
    applied = re.compile(pack.acl_extraction.applied) if pack.acl_extraction else None

    out: list[Interface] = []
    for node in tree.nodes.values():
        match = block.match(node.text)
        if match is None:
            continue

        desc: str | None = None
        addresses: list[str] = []
        enabled: bool | None = None
        acls: list[InterfaceAcl] = []
        evidence = [_evidence(node, tree, source_type)]

        for child in _children(tree, node):
            if description and (m := description.match(child.text)):
                # Cited like any other claim: the description is what the
                # interface says it is for, and Rule 2 does not exempt prose.
                desc = m.group(1).strip()
                evidence.append(_evidence(child, tree, source_type))
            elif ip_address and (m := ip_address.match(child.text)):
                addresses.append(m.group(1))
                evidence.append(_evidence(child, tree, source_type))
            elif shutdown and shutdown.match(child.text):
                enabled = False
                evidence.append(_evidence(child, tree, source_type))
            elif no_shutdown and no_shutdown.match(child.text):
                enabled = True
                evidence.append(_evidence(child, tree, source_type))
            elif applied and (m := applied.match(child.text)):
                acls.append(InterfaceAcl(acl_id=m.group(1), direction=Direction(m.group(2))))
                evidence.append(_evidence(child, tree, source_type))

        out.append(
            Interface(
                name=match.group(1),
                description=desc,
                enabled=enabled,
                ip_addresses=tuple(addresses),
                applied_acls=tuple(acls),
                evidence=tuple(evidence),
            )
        )
    return tuple(out)


def extract_acls(
    tree: ConfigTree,
    pack: VendorPack,
    interfaces: tuple[Interface, ...] = (),
    source_type: SourceType = SourceType.CLI,
) -> tuple[ACL, ...]:
    """Every access list the pack's declaration recognises, whole or not at all."""
    spec = pack.acl_extraction
    if spec is None:
        return ()

    parse_entry = _DIALECTS.get(spec.dialect)
    if parse_entry is None:  # pragma: no cover - a dialect with no parser
        return ()

    named = re.compile(spec.named_block)
    remark = re.compile(spec.remark) if spec.remark else None

    # Where each list is bound, read off the interfaces already extracted.
    bindings: dict[str, list[AclApplication]] = {}
    for interface in interfaces:
        for applied in interface.applied_acls:
            bindings.setdefault(applied.acl_id, []).append(
                AclApplication(interface=interface.name, direction=applied.direction)
            )

    out: list[ACL] = []
    for node in tree.nodes.values():
        match = named.match(node.text)
        if match is None:
            continue

        name = match.group(1)
        entries: list[ACLEntry] = []
        readable = True

        for child in _children(tree, node):
            if remark and remark.match(child.text):
                continue
            entry = parse_entry(child, len(entries) + 1, tree, source_type)
            if entry is None:
                # One unreadable entry invalidates the ordering, and ordering is
                # the whole of shadowing analysis.
                readable = False
                break
            entries.append(entry)

        if not readable:
            continue

        out.append(
            ACL(
                acl_id=name,
                name=name,
                acl_type=spec.acl_type,
                applied_to=tuple(bindings.get(name, ())),
                entries=tuple(entries),
                evidence=(_evidence(node, tree, source_type),),
            )
        )
    return tuple(out)


def matched_node_ids(tree: ConfigTree, pack: VendorPack) -> set[str]:
    """Nodes consumed by structure extraction, so they leave the residue queue.

    A line this module read is not unrecognised, and putting it in front of an
    administrator to classify would waste the one resource the training loop
    spends: their attention.
    """
    consumed: set[str] = set()

    spec_if = pack.interface_extraction
    spec_acl = pack.acl_extraction

    if spec_if is not None:
        block = re.compile(spec_if.block)
        sub = [
            re.compile(raw)
            for raw in (
                spec_if.description,
                spec_if.ip_address,
                spec_if.shutdown,
                spec_if.no_shutdown,
            )
            if raw
        ]
        if spec_acl is not None:
            sub.append(re.compile(spec_acl.applied))
        for node in tree.nodes.values():
            if block.match(node.text):
                consumed.add(node.node_id)
                for child in _children(tree, node):
                    if any(rx.match(child.text) for rx in sub):
                        consumed.add(child.node_id)

    if spec_acl is not None:
        named = re.compile(spec_acl.named_block)
        remark = re.compile(spec_acl.remark) if spec_acl.remark else None
        parse_entry = _DIALECTS.get(spec_acl.dialect)
        for node in tree.nodes.values():
            if not named.match(node.text):
                continue
            children = _children(tree, node)
            # Only claim the block when every entry was readable — an ACL that
            # was dropped must leave its lines in residue, where a human sees
            # them, rather than marking them handled.
            if parse_entry is not None and all(
                (remark and remark.match(c.text))
                or parse_entry(c, 1, tree, SourceType.CLI) is not None
                for c in children
            ):
                consumed.add(node.node_id)
                consumed.update(c.node_id for c in children)

    return consumed


def _unused(*_: Any) -> None:  # pragma: no cover - keeps the import surface honest
    return None
