"""Semantic ACL analysis — shadowed, redundant and overly permissive entries.

Order is the semantics. An access list is evaluated top to bottom and the first
matching entry wins, so an entry is dead if everything it would match has already
been decided above it. `ACL._check_sequence` guarantees entries arrive in
sequence order, which is why that guarantee exists.

**Coverage is pairwise.** An entry is reported shadowed when a *single* earlier
entry covers it, not when the union of several earlier entries does. Union
coverage is strictly more complete and much harder to explain: "line 40 can never
fire because of line 20" is checkable by a human in seconds, while "because of
lines 12, 20 and 31 taken together" is not. It also under-reports rather than
over-reports, and that is the right direction — a missed finding costs one
finding, an invented one costs trust in all of them.

**Unknown is not false** (decision D24). Coverage returns `True`, `False` or
`None`, and `None` propagates into an UNDETERMINED observation carrying its
reason. Two consequences follow, and both are tested:

  * an entry naming an unresolved object-group is never silently skipped;
  * an unresolved entry above another entry never causes a *false* shadowing
    claim about it — but it does prevent that entry being declared clean, which
    is the honest answer rather than the convenient one.
"""

from __future__ import annotations

from api.analyse.intervals import (
    Tri,
    address_covers,
    all_true,
    is_unresolved,
    port_covers,
    protocol_covers,
)
from api.models.acl import ACL, ACLEntry
from api.models.analysis import AclAnalysis, AclObservation
from api.models.enums import AclObservationKind, Severity, UnresolvedReason

ANALYSER_VERSION = "0.1.0"


def analyse_acl(acl: ACL) -> AclAnalysis:
    """Every observation about one access list, in entry order."""
    active = [entry for entry in acl.entries if not entry.flags.disabled]
    observations: list[AclObservation] = []

    for index, entry in enumerate(active):
        observations.extend(_observe(acl, entry, active[:index]))

    return AclAnalysis(
        acl_id=acl.acl_id,
        acl_name=acl.name,
        entries_analysed=len(active),
        observations=tuple(observations),
    )


def _observe(acl: ACL, entry: ACLEntry, earlier: list[ACLEntry]) -> list[AclObservation]:
    """Conclusions about one entry, given everything above it."""
    out: list[AclObservation] = []

    if entry.is_permit_any_any:
        out.append(
            AclObservation(
                kind=AclObservationKind.OVERLY_PERMISSIVE,
                acl_id=acl.acl_id,
                entry_seq=entry.seq,
                severity=Severity.HIGH,
                detail=(
                    "This entry permits every protocol between every source and "
                    "every destination, so the list places no restriction from "
                    "this point onward."
                ),
                evidence=entry.evidence,
            )
        )

    unresolved = _unresolved_reason(entry)
    if unresolved is not None:
        out.append(
            AclObservation(
                kind=AclObservationKind.UNDETERMINED,
                acl_id=acl.acl_id,
                entry_seq=entry.seq,
                detail=(
                    "This entry names an address that could not be resolved to a "
                    "range here, so whether it is reachable was not determined. "
                    "It was not assumed to match nothing."
                ),
                evidence=entry.evidence,
                unresolved_reason=unresolved,
            )
        )
        return out

    covering: list[ACLEntry] = []
    same_action: list[ACLEntry] = []
    indeterminate = False

    for candidate in earlier:
        result = covers(candidate, entry)
        if result is None:
            indeterminate = True
            continue
        if not result:
            continue
        if candidate.action is entry.action:
            same_action.append(candidate)
        else:
            covering.append(candidate)

    if covering:
        out.append(_shadowed(acl, entry, covering))
    elif same_action:
        out.append(_redundant(acl, entry, same_action))
    elif indeterminate:
        # Nothing above definitely covers this entry, but something above could
        # not be compared — so "not shadowed" is not a conclusion we have earned.
        out.append(
            AclObservation(
                kind=AclObservationKind.UNDETERMINED,
                acl_id=acl.acl_id,
                entry_seq=entry.seq,
                detail=(
                    "An entry above this one names an address that could not be "
                    "resolved here, so whether this entry is reachable was not "
                    "determined either way."
                ),
                evidence=entry.evidence,
                unresolved_reason=UnresolvedReason.UNRESOLVED_EARLIER_ENTRY,
            )
        )

    return out


def _shadowed(acl: ACL, entry: ACLEntry, covering: list[ACLEntry]) -> AclObservation:
    return AclObservation(
        kind=AclObservationKind.SHADOWED,
        acl_id=acl.acl_id,
        entry_seq=entry.seq,
        severity=Severity.MEDIUM,
        detail=(
            "Every packet this entry would match is already decided the other way "
            "by an earlier entry, so it can never take effect. The list does not "
            "do what reading this line suggests."
        ),
        evidence=entry.evidence,
        caused_by=tuple(c.seq for c in covering),
        caused_by_evidence=tuple(e for c in covering for e in c.evidence),
    )


def _redundant(acl: ACL, entry: ACLEntry, same_action: list[ACLEntry]) -> AclObservation:
    return AclObservation(
        kind=AclObservationKind.REDUNDANT,
        acl_id=acl.acl_id,
        entry_seq=entry.seq,
        severity=Severity.LOW,
        detail=(
            "An earlier entry already decides every packet this one would match, "
            "the same way. Removing it would not change how the device behaves."
        ),
        evidence=entry.evidence,
        caused_by=tuple(c.seq for c in same_action),
        caused_by_evidence=tuple(e for c in same_action for e in c.evidence),
    )


def _unresolved_reason(entry: ACLEntry) -> UnresolvedReason | None:
    if is_unresolved(entry.src) or is_unresolved(entry.dst):
        return UnresolvedReason.UNRESOLVED_OBJECT
    return None


def covers(outer: ACLEntry, inner: ACLEntry) -> Tri:
    """Does `outer` match every packet `inner` matches?

    `None` when an operand cannot be resolved — never `False`, which would be a
    claim that the two do not overlap.
    """
    if outer.flags.established and not inner.flags.established:
        # `established` matches only packets belonging to an existing session, so
        # such an entry matches strictly less than one without it. It can narrow
        # a list; it cannot shadow. Ignoring the flag produces confident false
        # positives on exactly the lists most likely to be carefully written.
        return False

    return all_true(
        protocol_covers(outer.protocol, inner.protocol),
        address_covers(outer.src, inner.src),
        address_covers(outer.dst, inner.dst),
        port_covers(outer.src_port, inner.src_port),
        port_covers(outer.dst_port, inner.dst_port),
    )
