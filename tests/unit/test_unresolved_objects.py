"""Unresolved object-groups are UNKNOWN, never an empty interval (decision D24).

`AddrSpec(kind=OBJECT)` may legitimately carry no `resolved_cidrs` — the contract
requires them only for `HOST` and `CIDR`. Its address set is genuinely *unknown*.

The failure this guards against is subtle and easy to write. Treating an unknown
interval as an empty one makes the entry match nothing, so it can neither shadow
another entry nor be shadowed by one. It drops silently out of the analysis while
the report looks complete — an entry the operator can see in their configuration
simply has no line in the output, and nothing says why. That is the Rule 3
substitution, in the one place a reader would never think to check.

Three-valued containment is the fix, threaded all the way through rather than
collapsed at the edges: `True`, `False`, or `None` meaning not determinable.
"""

from __future__ import annotations

from api.analyse.acl_analysis import analyse_acl, covers
from api.analyse.intervals import address_covers, all_true, is_unresolved, networks_of
from api.models.enums import AclAction, AclObservationKind, UnresolvedReason
from tests.fixtures.acls import acl, any_addr, cidr, entry, resolved_object, unresolved_object

D = AclAction.DENY
P = AclAction.PERMIT


# ---------------------------------------------------------------------------
# The contract-level distinction
# ---------------------------------------------------------------------------


def test_an_unresolved_object_has_no_interval_and_is_not_empty() -> None:
    spec = unresolved_object()

    assert networks_of(spec) is None, "None means unknown"
    assert networks_of(spec) != (), "and must never be confused with an empty set"
    assert is_unresolved(spec)


def test_a_resolved_object_has_an_interval() -> None:
    spec = resolved_object("grp", "10.0.0.0/8")

    assert networks_of(spec) is not None
    assert not is_unresolved(spec)


def test_containment_against_an_unresolved_operand_is_unknown() -> None:
    assert address_covers(cidr("10.0.0.0/8"), unresolved_object()) is None
    assert address_covers(unresolved_object(), cidr("10.0.0.0/8")) is None
    assert address_covers(any_addr(), unresolved_object()) is None


def test_unknown_never_collapses_to_false() -> None:
    """The single most important assertion in this module."""
    result = address_covers(cidr("10.0.0.0/8"), unresolved_object())

    assert result is not False
    assert result is None


def test_three_valued_conjunction_prefers_a_definite_false() -> None:
    """One dimension that definitely does not overlap settles the question."""
    assert all_true(True, False, None) is False
    assert all_true(True, None, True) is None
    assert all_true(True, True, True) is True


# ---------------------------------------------------------------------------
# OBJECT with resolved CIDRs — analysed normally
# ---------------------------------------------------------------------------


def test_object_with_resolved_cidrs_can_shadow() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=resolved_object("grp", "10.0.0.0/8")),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )

    assert len(analysis.of_kind(AclObservationKind.SHADOWED)) == 1
    assert analysis.of_kind(AclObservationKind.UNDETERMINED) == ()


def test_object_with_resolved_cidrs_can_be_shadowed() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "tcp", src=resolved_object("grp", "10.1.0.0/16")),
        )
    )
    shadowed = analysis.of_kind(AclObservationKind.SHADOWED)

    assert len(shadowed) == 1
    assert shadowed[0].entry_seq == 20


# ---------------------------------------------------------------------------
# OBJECT without resolved CIDRs — undetermined, and visibly so
# ---------------------------------------------------------------------------


def test_an_unresolved_entry_is_reported_as_undetermined() -> None:
    analysis = analyse_acl(acl(entry(10, P, "tcp", src=unresolved_object())))
    undetermined = analysis.of_kind(AclObservationKind.UNDETERMINED)

    assert len(undetermined) == 1
    assert undetermined[0].entry_seq == 10
    assert undetermined[0].unresolved_reason is UnresolvedReason.UNRESOLVED_OBJECT


def test_an_unresolved_entry_is_never_silently_dropped() -> None:
    """The whole point: it appears in the output rather than vanishing."""
    analysis = analyse_acl(
        acl(
            entry(10, P, "tcp", src=cidr("10.0.0.0/8")),
            entry(20, P, "tcp", src=unresolved_object()),
        )
    )

    assert not analysis.is_clean
    assert 20 in [o.entry_seq for o in analysis.observations]


def test_an_undetermined_observation_states_its_reason() -> None:
    analysis = analyse_acl(acl(entry(10, P, "tcp", dst=unresolved_object())))
    observation = analysis.of_kind(AclObservationKind.UNDETERMINED)[0]

    assert observation.unresolved_reason is not None
    assert observation.evidence, "and still cites the line it is about"
    assert not observation.is_actionable, "resolving the group is a different task"


def test_an_unresolved_destination_counts_too() -> None:
    analysis = analyse_acl(acl(entry(10, P, "tcp", dst=unresolved_object("grp-dmz"))))

    assert len(analysis.of_kind(AclObservationKind.UNDETERMINED)) == 1


# ---------------------------------------------------------------------------
# No FALSE shadowing caused by an unresolved entry
# ---------------------------------------------------------------------------


def test_an_unresolved_earlier_entry_does_not_shadow_a_later_one() -> None:
    """The required guarantee, stated directly.

    An entry above whose range we cannot compute must not be reported as
    shadowing anything — that would be a confident claim built on an unknown.
    """
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=unresolved_object()),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )

    assert analysis.of_kind(AclObservationKind.SHADOWED) == (), (
        "an unresolved entry produced a false shadowing claim"
    )


def test_but_the_later_entry_is_not_declared_clean_either() -> None:
    """The honest counterpart. Not shadowed is not the same as fine.

    Something above could not be compared, so whether this entry is reachable
    was not established. Reporting nothing would imply it was.
    """
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=unresolved_object()),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )
    undetermined = analysis.of_kind(AclObservationKind.UNDETERMINED)

    assert 20 in [o.entry_seq for o in undetermined]
    assert any(
        o.unresolved_reason is UnresolvedReason.UNRESOLVED_EARLIER_ENTRY for o in undetermined
    )


def test_covers_returns_none_not_false_for_an_unresolved_pair() -> None:
    assert (
        covers(
            entry(10, D, "ip", src=unresolved_object()),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        )
        is None
    )


def test_a_definite_shadow_still_wins_over_an_unresolved_neighbour() -> None:
    """An unknown elsewhere must not suppress a finding we did establish."""
    analysis = analyse_acl(
        acl(
            entry(10, P, "tcp", src=unresolved_object()),
            entry(20, D, "ip", src=cidr("10.0.0.0/8")),
            entry(30, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )
    shadowed = analysis.of_kind(AclObservationKind.SHADOWED)

    assert [o.entry_seq for o in shadowed] == [30]
    assert shadowed[0].caused_by == (20,)


# ---------------------------------------------------------------------------
# Mixed resolvable / unresolvable
# ---------------------------------------------------------------------------


def test_a_mixed_list_reports_both_kinds_of_conclusion() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
            entry(30, P, "tcp", src=unresolved_object()),
            entry(40, P, "tcp", src=cidr("192.168.0.0/16")),
        )
    )
    seqs = {o.kind: [x.entry_seq for x in analysis.of_kind(o.kind)] for o in analysis.observations}

    assert seqs[AclObservationKind.SHADOWED] == [20]
    assert 30 in seqs[AclObservationKind.UNDETERMINED]
    assert 40 in seqs[AclObservationKind.UNDETERMINED], (
        "an entry after an unresolved one cannot be declared reachable"
    )


def test_entries_before_an_unresolved_one_are_unaffected() -> None:
    """Order matters: nothing below can change a conclusion above."""
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
            entry(30, P, "tcp", src=unresolved_object()),
        )
    )
    shadowed = analysis.of_kind(AclObservationKind.SHADOWED)

    assert [o.entry_seq for o in shadowed] == [20]


def test_the_undetermined_count_is_reported() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, P, "tcp", src=unresolved_object()),
            entry(20, P, "tcp", src=unresolved_object("grp-two")),
        )
    )

    assert analysis.undetermined_count == 2
