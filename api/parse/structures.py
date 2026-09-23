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
from api.models.csm import AclExtractionFailure, Interface, InterfaceAcl
from api.models.enums import AclAction, AclDialect, AddrKind, Direction, PortOp, SourceType
from api.models.evidence import Evidence
from api.models.pack import AclExtraction, VendorPack

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


# ---------------------------------------------------------------------------
# The JunOS flat-`set` filter dialect
# ---------------------------------------------------------------------------
#
# A JunOS firewall filter in `set` form has no block header and no one-line
# entry. One term is several independent top-level lines:
#
#     set firewall family inet filter PROTECT-RE term allow-mgmt-ssh from protocol tcp
#     set firewall family inet filter PROTECT-RE term allow-mgmt-ssh then accept
#
# So this dialect cannot be an entry parser hung off the IOS extraction shape:
# there is nothing for `named_block` to open and no child list to walk. It reads
# the whole file, groups lines by (filter, term) in **first-appearance order**,
# and builds one `ACLEntry` per term. Order is what shadowing reasons about, and
# first appearance is the order the device evaluates them in.

_JUNOS_TERM_TAIL = re.compile(r"term (\S+) (from|then) (.+)$")
"""What follows the filter name on a term line.

The *prefix* — `set firewall family inet filter NAME ` — is the pack's
`named_block`, because `family inet` is a configuration detail an operator can
legitimately differ on (`inet6`, `ethernet-switching`) and Rule 5 says that
belongs in data. What follows is the filter grammar itself and belongs here, in
the same way wildcard-mask arithmetic belongs here for IOS.
"""
_JUNOS_PREFIX_LIST = re.compile(r"^set policy-options prefix-list (\S+) (\S+)$")

_JUNOS_ACCEPT = frozenset({"accept"})
_JUNOS_REJECT = frozenset({"discard", "reject"})
_JUNOS_LOG = frozenset({"log", "syslog"})

_JUNOS_FROM_KEYWORDS = frozenset(
    {
        "protocol",
        "source-address",
        "destination-address",
        "source-port",
        "destination-port",
        "source-prefix-list",
        "destination-prefix-list",
    }
)
"""The `from` keywords this dialect reads.

Deliberately closed and deliberately small — only what a development file
actually writes. A term using anything else defeats the parser and drops its
whole filter, which is the same all-or-nothing rule the IOS dialect follows
(D75) and for the same reason: a filter missing one match condition would let
the analyser call a reachable term unreachable.
"""


class _JunosTerm:
    """Accumulated `from` and `then` clauses for one named term."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.from_clauses: list[tuple[ConfigNode, str]] = []
        self.then_clauses: list[tuple[ConfigNode, str]] = []

    @property
    def nodes(self) -> list[ConfigNode]:
        return [node for node, _ in self.from_clauses + self.then_clauses]


def _junos_prefix_lists(tree: ConfigTree) -> dict[str, list[str]]:
    """`set policy-options prefix-list TRUSTED-MGMT 198.51.100.0/24` -> members.

    Resolved because the definition is **in the same file**, not because a
    plausible range was available. An unresolved address makes `address_covers`
    return `None`, and the analyser then reports UNDETERMINED rather than
    comparing — so leaving a prefix list unresolved while the configuration
    defines it would discard information the operator plainly gave.

    A prefix list the file references but never defines stays unresolved, which
    is the honest outcome and the one the IOS `object-group` case produces.
    """
    out: dict[str, list[str]] = {}
    for node in tree.nodes.values():
        match = _JUNOS_PREFIX_LIST.match(node.text)
        if match is None:
            continue
        try:
            ipaddress.ip_network(match.group(2), strict=False)
        except ValueError:
            continue
        out.setdefault(match.group(1), []).append(match.group(2))
    return out


def _junos_address(
    value: str, prefix_lists: dict[str, list[str]], is_list: bool
) -> AddrSpec | None:
    if is_list:
        members = prefix_lists.get(value, [])
        return AddrSpec(kind=AddrKind.OBJECT, value=value, resolved_cidrs=tuple(members))
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
    return AddrSpec(kind=AddrKind.CIDR, value=value, resolved_cidrs=(str(network),))


def _junos_port(value: str) -> PortSpec | None:
    number = _port_number(value)
    if number is None:
        return None
    return PortSpec(op=PortOp.EQ, low=number, high=number)


def _build_junos_entry(
    term: _JunosTerm,
    seq: int,
    tree: ConfigTree,
    prefix_lists: dict[str, list[str]],
    source_type: SourceType,
) -> ACLEntry | None:
    """One term, or None if any clause in it could not be read."""
    protocol = ProtocolSpec(name="any")
    src: AddrSpec = AddrSpec(kind=AddrKind.ANY, value="any")
    dst: AddrSpec = AddrSpec(kind=AddrKind.ANY, value="any")
    src_port = PortSpec(op=PortOp.ANY)
    dst_port = PortSpec(op=PortOp.ANY)

    for _, clause in term.from_clauses:
        tokens = clause.split()
        if len(tokens) != 2 or tokens[0] not in _JUNOS_FROM_KEYWORDS:
            # Includes the bracketed list form `destination-port [ ssh https ]`,
            # which denotes two intervals this contract cannot hold in one spec.
            return None
        keyword, value = tokens

        if keyword == "protocol":
            protocol = ProtocolSpec(name=value.lower())
        elif keyword in ("source-address", "source-prefix-list"):
            resolved = _junos_address(value, prefix_lists, keyword.endswith("prefix-list"))
            if resolved is None:
                return None
            src = resolved
        elif keyword in ("destination-address", "destination-prefix-list"):
            resolved = _junos_address(value, prefix_lists, keyword.endswith("prefix-list"))
            if resolved is None:
                return None
            dst = resolved
        elif keyword == "source-port":
            port = _junos_port(value)
            if port is None:
                return None
            src_port = port
        else:
            port = _junos_port(value)
            if port is None:
                return None
            dst_port = port

    action: AclAction | None = None
    log = False
    for _, clause in term.then_clauses:
        token = clause.strip()
        if token in _JUNOS_ACCEPT:
            action = AclAction.PERMIT
        elif token in _JUNOS_REJECT:
            action = AclAction.DENY
        elif token in _JUNOS_LOG:
            log = True
        else:
            # `next term`, `count`, `policer`, `routing-instance` and the rest.
            # `next term` in particular means the term does not decide the packet
            # at all, so modelling it as permit or deny would be a fabrication
            # about what the device does.
            return None

    if action is None:
        # A term that only logs decides nothing on its own.
        return None

    return ACLEntry(
        seq=seq,
        action=action,
        protocol=protocol,
        src=src,
        src_port=src_port,
        dst=dst,
        dst_port=dst_port,
        flags=AclEntryFlags(log=log),
        evidence=tuple(_evidence(node, tree, source_type) for node in term.nodes),
    )


def _why_junos_unreadable(term: _JunosTerm) -> tuple[ConfigNode, str]:
    """Name the clause that defeated the parser, and the token inside it."""
    for node, clause in term.from_clauses:
        tokens = clause.split()
        if not tokens:
            continue
        if tokens[0] not in _JUNOS_FROM_KEYWORDS:
            return node, f"matches on {tokens[0]!r}, which this dialect does not read"
        if len(tokens) != 2:
            return node, (
                f"writes {tokens[0]!r} as a list of {len(tokens) - 1} values, and one "
                "entry cannot hold two intervals for one field; splitting it would "
                "invent an ordering the configuration does not state"
            )
        if tokens[0].endswith("port") and _port_number(tokens[1]) is None:
            return node, (
                f"names the port {tokens[1]!r}, which this dialect does not recognise; "
                "guessing its number would put a wrong interval into shadowing analysis"
            )
        if tokens[0].endswith("address"):
            try:
                ipaddress.ip_network(tokens[1], strict=False)
            except ValueError:
                return node, f"names the address {tokens[1]!r}, which is not a network"

    known = _JUNOS_ACCEPT | _JUNOS_REJECT | _JUNOS_LOG
    for node, clause in term.then_clauses:
        if clause.strip() not in known:
            return node, (
                f"takes the action {clause.strip()!r}, which does not decide the packet "
                "as a permit or a deny; modelling it as either would state something "
                "about the device that is not true"
            )

    node = term.then_clauses[0][0] if term.then_clauses else term.from_clauses[0][0]
    return node, "never accepts, discards or rejects, so it decides nothing on its own"


def _extract_junos_set_lists(
    tree: ConfigTree, spec: AclExtraction, source_type: SourceType
) -> tuple[list[ACL], list[AclExtractionFailure]]:
    prefix_lists = _junos_prefix_lists(tree)

    named = re.compile(spec.named_block)

    # dict preserves insertion order, which is the order the device evaluates.
    filters: dict[str, dict[str, _JunosTerm]] = {}
    for node in tree.nodes.values():
        head = named.match(node.text)
        if head is None:
            continue
        tail = _JUNOS_TERM_TAIL.match(node.text[head.end() :])
        if tail is None:
            continue
        filter_name = head.group(1)
        term_name, kind, clause = tail.groups()
        terms = filters.setdefault(filter_name, {})
        term = terms.get(term_name)
        if term is None:
            term = terms[term_name] = _JunosTerm(term_name)
        (term.from_clauses if kind == "from" else term.then_clauses).append((node, clause))

    out: list[ACL] = []
    failures: list[AclExtractionFailure] = []
    for filter_name, terms in filters.items():
        entries: list[ACLEntry] = []
        defeated: _JunosTerm | None = None
        for term in terms.values():
            entry = _build_junos_entry(term, len(entries) + 1, tree, prefix_lists, source_type)
            if entry is None:
                defeated = term
                break
            entries.append(entry)

        if defeated is not None:
            node, reason = _why_junos_unreadable(defeated)
            failures.append(
                AclExtractionFailure(
                    acl_name=filter_name,
                    reason=f"term {defeated.name!r} {reason}",
                    entry_line=node.line_number,
                    entry_text=node.text,
                )
            )
            continue

        first = next(iter(terms.values())).nodes[0]
        out.append(
            ACL(
                acl_id=filter_name,
                name=filter_name,
                acl_type=spec.acl_type,
                entries=tuple(entries),
                evidence=(_evidence(first, tree, source_type),),
            )
        )
    return out, failures


def _junos_set_node_ids(tree: ConfigTree, spec: AclExtraction) -> set[str]:
    """Lines this dialect consumed, including the prefix lists it resolved.

    A filter that was dropped leaves every one of its lines in residue, where a
    human sees them — the same rule the IOS path follows.
    """
    lists, _ = _extract_junos_set_lists(tree, spec, SourceType.CLI)
    kept = {acl.name for acl in lists}
    named = re.compile(spec.named_block)

    consumed: set[str] = set()
    referenced: set[str] = set()
    for node in tree.nodes.values():
        head = named.match(node.text)
        if head is None or head.group(1) not in kept:
            continue
        tail = _JUNOS_TERM_TAIL.match(node.text[head.end() :])
        if tail is None:
            continue
        consumed.add(node.node_id)
        tokens = tail.group(3).split()
        if len(tokens) == 2 and tokens[0].endswith("prefix-list"):
            referenced.add(tokens[1])

    for node in tree.nodes.values():
        match = _JUNOS_PREFIX_LIST.match(node.text)
        if match is not None and match.group(1) in referenced:
            consumed.add(node.node_id)
    return consumed


_DIALECTS = {AclDialect.IOS_WILDCARD: _parse_ios_entry}


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def _extract_ios_lists(
    tree: ConfigTree, spec: AclExtraction, source_type: SourceType
) -> tuple[list[ACL], list[AclExtractionFailure]]:
    """A named block whose children are one-line entries.

    Unchanged from ADR 0027 apart from being reachable through the dialect
    table rather than being the only thing `extract_acls` could do.
    """
    parse_entry = _DIALECTS[spec.dialect]
    named = re.compile(spec.named_block)
    remark = re.compile(spec.remark) if spec.remark else None

    out: list[ACL] = []
    failures: list[AclExtractionFailure] = []
    for node in tree.nodes.values():
        match = named.match(node.text)
        if match is None:
            continue

        name = match.group(1)
        entries: list[ACLEntry] = []
        defeated: ConfigNode | None = None

        for child in _children(tree, node):
            if remark and remark.match(child.text):
                continue
            entry = parse_entry(child, len(entries) + 1, tree, source_type)
            if entry is None:
                # One unreadable entry invalidates the ordering, and ordering is
                # the whole of shadowing analysis.
                defeated = child
                break
            entries.append(entry)

        if defeated is not None:
            failures.append(
                AclExtractionFailure(
                    acl_name=name,
                    reason=_why_unreadable(defeated),
                    entry_line=defeated.line_number,
                    entry_text=defeated.text,
                )
            )
            continue

        out.append(
            ACL(
                acl_id=name,
                name=name,
                acl_type=spec.acl_type,
                entries=tuple(entries),
                evidence=(_evidence(node, tree, source_type),),
            )
        )
    return out, failures


_LIST_READERS = {
    AclDialect.IOS_WILDCARD: _extract_ios_lists,
    AclDialect.JUNOS_SET_FILTER: _extract_junos_set_lists,
}
"""One reader per dialect. A dialect is a *shape plus a grammar*, not a vendor."""



def _why_unreadable(node: ConfigNode) -> str:
    """Name the specific thing that defeated the parser, not that it failed.

    "could not be parsed" sends an operator to read the whole list. "uses a
    non-contiguous wildcard mask, which has no CIDR equivalent" sends them to
    one token, and tells whoever maintains the dialect what to add next.
    """
    tokens = node.text.split()
    if tokens and tokens[0].isdigit():
        tokens = tokens[1:]

    if not tokens or tokens[0] not in ("permit", "deny"):
        return "is not a permit or deny entry, and this parser reads no other form"

    for index, token in enumerate(tokens):
        if token in _PORT_OPS and index + 1 < len(tokens):
            if _port_number(tokens[index + 1]) is None:
                return (
                    f"names the port {tokens[index + 1]!r}, which this dialect does not "
                    "recognise; guessing its number would put a wrong interval into "
                    "shadowing analysis"
                )

    for index, token in enumerate(tokens):
        if _looks_like_ipv4(token) and index + 1 < len(tokens):
            candidate = tokens[index + 1]
            if _looks_like_ipv4(candidate) and _wildcard_to_cidr(token, candidate) is None:
                return (
                    f"uses the wildcard mask {candidate}, which is non-contiguous and "
                    "has no CIDR equivalent"
                )

    return "uses syntax this dialect does not read"


def _looks_like_ipv4(token: str) -> bool:
    try:
        ipaddress.IPv4Address(token)
    except ValueError:
        return False
    return True


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
    applied_raw = pack.acl_extraction.applied if pack.acl_extraction else None
    applied = re.compile(applied_raw) if applied_raw else None

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
) -> tuple[tuple[ACL, ...], tuple[AclExtractionFailure, ...]]:
    """Every access list the declaration recognises, and every one it dropped.

    The failures are returned rather than logged because a dropped list and a
    device with no access lists are the same empty tuple, and an operator needs
    to tell them apart.
    """
    spec = pack.acl_extraction
    if spec is None:
        return (), ()

    # The dialect owns the *shape* as well as the entry grammar. IOS writes one
    # block whose children are entries; JunOS `set` form writes no block at all
    # and spreads one term across several top-level lines. A seam that only
    # varied the entry parser could not read the second, so it varies here.
    reader = _LIST_READERS.get(spec.dialect)
    if reader is None:  # pragma: no cover - a dialect with no reader
        return (), ()

    out, failures = reader(tree, spec, source_type)

    # Where each list is bound, read off the interfaces already extracted.
    bindings: dict[str, list[AclApplication]] = {}
    for interface in interfaces:
        for applied in interface.applied_acls:
            bindings.setdefault(applied.acl_id, []).append(
                AclApplication(interface=interface.name, direction=applied.direction)
            )

    # Bindings are applied after the fact rather than inside each reader: where
    # a list is *used* is the same question on every platform, and a reader that
    # had to answer it would answer it once per dialect.
    return (
        tuple(
            acl.model_copy(update={"applied_to": tuple(bindings.get(acl.name, ()))})
            for acl in out
        ),
        tuple(failures),
    )


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
        if spec_acl is not None and spec_acl.applied:
            sub.append(re.compile(spec_acl.applied))
        for node in tree.nodes.values():
            if block.match(node.text):
                consumed.add(node.node_id)
                for child in _children(tree, node):
                    if any(rx.match(child.text) for rx in sub):
                        consumed.add(child.node_id)

    if spec_acl is not None and spec_acl.dialect is AclDialect.JUNOS_SET_FILTER:
        consumed |= _junos_set_node_ids(tree, spec_acl)

    if spec_acl is not None and spec_acl.dialect in _DIALECTS:
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
