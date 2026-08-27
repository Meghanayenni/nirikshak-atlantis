"""Interval containment over addresses, ports and protocols.

This is the computation the Concept Report promises: access lists evaluated as
interval logic rather than pattern matching. Nothing here knows which vendor
wrote the list, and nothing here reads configuration text.

**Containment is three-valued.** Every function returns `True`, `False` or
`None`, where `None` means *not determinable* — and that is decision D24, not a
convenience.

An `AddrSpec` naming an object-group carries no `resolved_cidrs`: the contract
requires them only for `HOST` and `CIDR`. Its interval is genuinely unknown, not
empty. Treating unknown as empty would make such an entry match nothing, so it
could neither shadow another entry nor be shadowed by one — it would drop
silently out of the analysis while the report looked complete. That is the Rule 3
failure shape, and it is easy to write by accident, which is why the three-valued
return is threaded all the way through rather than collapsed at the edges.

`None` propagates: any comparison involving an unknown operand is unknown.
"""

from __future__ import annotations

import ipaddress
from typing import TypeAlias

from api.models.acl import AddrSpec, PortSpec, ProtocolSpec
from api.models.enums import AddrKind

Network: TypeAlias = ipaddress.IPv4Network | ipaddress.IPv6Network

Tri: TypeAlias = bool | None
"""True, False, or "not determinable". Never coerce `None` to `False`."""

UNIVERSAL_PROTOCOLS = frozenset({"any", "ip"})
"""Protocol names that match every protocol.

`ip` is a superset of `tcp`, `udp` and `icmp`, so an earlier `deny ip` shadows a
later `permit tcp`. Comparing protocols by equality would miss the most common
real shadowing case entirely.
"""

ANY_NETWORKS: tuple[Network, ...] = (
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("::/0"),
)


# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------


def networks_of(spec: AddrSpec) -> tuple[Network, ...] | None:
    """The address set this spec denotes, or `None` when it is not knowable.

    `None` is returned for an object-group with no resolved members. It is *not*
    the same as an empty tuple, and no caller may treat it as one.
    """
    if spec.kind is AddrKind.ANY:
        return ANY_NETWORKS
    if not spec.resolved_cidrs:
        return None
    try:
        return tuple(ipaddress.ip_network(cidr, strict=False) for cidr in spec.resolved_cidrs)
    except ValueError:  # pragma: no cover - AddrSpec validates on construction
        return None


def is_unresolved(spec: AddrSpec) -> bool:
    """Whether this address cannot be placed on the number line at all."""
    return networks_of(spec) is None


def address_covers(outer: AddrSpec, inner: AddrSpec) -> Tri:
    """Does `outer` match every address `inner` matches?

    Deliberately conservative in one direction: `inner` is covered when each of
    its networks sits inside a *single* network of `outer`. A network split
    across two of `outer`'s ranges is reported as not covered even though the
    union would cover it.

    That under-reports rather than over-reports, and the trade is worth making.
    An analysis that misses a shadowed rule costs the operator one finding; an
    analysis that invents one costs their trust in every other finding.
    """
    outer_nets = networks_of(outer)
    inner_nets = networks_of(inner)
    if outer_nets is None or inner_nets is None:
        return None

    for candidate in inner_nets:
        if not any(_subnet_of(candidate, container) for container in outer_nets):
            return False
    return True


def _subnet_of(inner: Network, outer: Network) -> bool:
    """Containment within one address family.

    IPv4 and IPv6 networks are not comparable, and `subnet_of` raises rather than
    returning False. A mixed-family pair simply does not overlap, so it is not
    contained.
    """
    if inner.version != outer.version:
        return False
    return inner.subnet_of(outer)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------


def port_covers(outer: PortSpec, inner: PortSpec) -> bool:
    """Does `outer`'s port interval contain `inner`'s?

    Always determinable: `PortSpec` normalises every operator form to an
    inclusive `low..high` interval at construction, so there is no unknown case.
    """
    return outer.low <= inner.low and inner.high <= outer.high


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


def protocol_covers(outer: ProtocolSpec, inner: ProtocolSpec) -> bool:
    """Does `outer` match every protocol `inner` matches?

    `ip`/`any` covers everything. Otherwise containment is name equality, or
    number equality when both carry one — a pack emitting `6` and another
    emitting `tcp` should still compare equal where the numbers are known.
    """
    if outer.name.lower() in UNIVERSAL_PROTOCOLS:
        return True
    if inner.name.lower() in UNIVERSAL_PROTOCOLS:
        # A specific protocol cannot cover "any".
        return False
    if outer.name.lower() == inner.name.lower():
        return True
    if outer.number is not None and inner.number is not None:
        return outer.number == inner.number
    return False


# ---------------------------------------------------------------------------
# Combining
# ---------------------------------------------------------------------------


def all_true(*results: Tri) -> Tri:
    """Three-valued conjunction.

    A definite `False` wins — one dimension that does not overlap is enough to
    settle the question, whatever the others do. Otherwise any `None` makes the
    whole answer unknown. Order matters here, and getting it the other way round
    would turn "we do not know" into "no".
    """
    if any(result is False for result in results):
        return False
    if any(result is None for result in results):
        return None
    return True
