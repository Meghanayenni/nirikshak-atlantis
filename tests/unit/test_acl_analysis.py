"""Semantic ACL analysis — the observation matrix (P7).

One test per case, each named for the case. Built on constructed `ACL` objects:
interval containment is arithmetic, so it can be tested exhaustively without
inventing vendor syntax. No corpus file is involved and no claim is made about
ACL parsing.

The negative half matters as much as the positive. A shadowing detector that
flags everything is worse than none at all, because it teaches an operator to
ignore the whole report — so every detection case has a matching test that the
detector stays quiet when it should.
"""

from __future__ import annotations

from api.analyse.acl_analysis import analyse_acl, covers
from api.models.enums import AclAction, AclObservationKind, PortOp, Severity, UnresolvedReason
from tests.fixtures.acls import acl, any_addr, cidr, entry, host, port, resolved_object

D = AclAction.DENY
P = AclAction.PERMIT


def kinds(analysis) -> list[AclObservationKind]:
    return [o.kind for o in analysis.observations]


def of(analysis, kind: AclObservationKind):
    return analysis.of_kind(kind)


# ---------------------------------------------------------------------------
# Shadowed
# ---------------------------------------------------------------------------


def test_a_fully_covered_entry_with_the_opposite_action_is_shadowed() -> None:
    """`deny ip 10.0.0.0/8` above `permit tcp 10.1.0.0/16` — the permit is dead."""
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )
    shadowed = of(analysis, AclObservationKind.SHADOWED)

    assert len(shadowed) == 1
    assert shadowed[0].entry_seq == 20
    assert shadowed[0].caused_by == (10,)


def test_a_shadowing_observation_cites_both_entries() -> None:
    """ "Line 20 can never fire" is not actionable; naming line 10 makes it so."""
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=cidr("10.0.0.0/8"), text="10 deny ip 10.0.0.0/8 any"),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16"), text="20 permit tcp 10.1.0.0/16 any"),
        )
    )
    observation = of(analysis, AclObservationKind.SHADOWED)[0]

    assert observation.evidence, "the shadowed entry must cite itself"
    assert observation.caused_by_evidence, "and the entry responsible"
    assert len(observation.citations()) == 2


def test_a_narrower_earlier_entry_does_not_shadow_a_wider_later_one() -> None:
    """Coverage runs one way. The negative control for the case above."""
    analysis = analyse_acl(
        acl(
            entry(10, D, "tcp", src=cidr("10.1.0.0/16")),
            entry(20, P, "ip", src=cidr("10.0.0.0/8")),
        )
    )

    assert of(analysis, AclObservationKind.SHADOWED) == ()


def test_a_disjoint_pair_produces_nothing() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "ip", src=cidr("192.168.0.0/16")),
        )
    )

    assert analysis.is_clean


def test_a_partial_overlap_is_not_reported_as_shadowed() -> None:
    """The over-reporting guard.

    `10.0.0.0/8` and `10.1.0.0/16` overlap only partly once ports differ. A
    detector that called this shadowed would be flagging a rule that does fire.
    """
    analysis = analyse_acl(
        acl(
            entry(10, D, "tcp", src=cidr("10.0.0.0/8"), dst_port=port(PortOp.EQ, 22)),
            entry(20, P, "tcp", src=cidr("10.0.0.0/8"), dst_port=port(PortOp.ANY)),
        )
    )

    assert of(analysis, AclObservationKind.SHADOWED) == ()


# ---------------------------------------------------------------------------
# Redundant
# ---------------------------------------------------------------------------


def test_a_fully_covered_entry_with_the_same_action_is_redundant() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, P, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )
    redundant = of(analysis, AclObservationKind.REDUNDANT)

    assert len(redundant) == 1
    assert redundant[0].entry_seq == 20
    assert redundant[0].caused_by == (10,)


def test_redundant_and_shadowed_are_distinguished_by_action() -> None:
    """Same geometry, opposite conclusion — the difference is the action.

    Sources are bounded so the first entry is not itself a permit-any-any, which
    would add an overly-permissive observation and blur what this test isolates.
    """
    src = cidr("10.0.0.0/8")
    inner = cidr("10.1.0.0/16")

    same = analyse_acl(acl(entry(10, P, "ip", src=src), entry(20, P, "tcp", src=inner)))
    opposite = analyse_acl(acl(entry(10, D, "ip", src=src), entry(20, P, "tcp", src=inner)))

    assert kinds(same) == [AclObservationKind.REDUNDANT]
    assert kinds(opposite) == [AclObservationKind.SHADOWED]


def test_shadowing_takes_precedence_over_redundancy() -> None:
    """When both apply, the entry is dead — which is the more urgent statement."""
    analysis = analyse_acl(
        acl(
            entry(10, P, "ip", src=cidr("10.0.0.0/8")),
            entry(20, D, "ip", src=cidr("10.0.0.0/8")),
            entry(30, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )
    last = [o for o in analysis.observations if o.entry_seq == 30]

    assert [o.kind for o in last] == [AclObservationKind.SHADOWED]


# ---------------------------------------------------------------------------
# Overly permissive
# ---------------------------------------------------------------------------


def test_permit_ip_any_any_is_flagged() -> None:
    analysis = analyse_acl(acl(entry(10, P, "ip", src=any_addr(), dst=any_addr())))
    flagged = of(analysis, AclObservationKind.OVERLY_PERMISSIVE)

    assert len(flagged) == 1
    assert flagged[0].severity is Severity.HIGH


def test_a_narrow_permit_is_not_flagged() -> None:
    analysis = analyse_acl(
        acl(entry(10, P, "tcp", src=cidr("10.0.0.0/8"), dst_port=port(PortOp.EQ, 443)))
    )

    assert of(analysis, AclObservationKind.OVERLY_PERMISSIVE) == ()


def test_deny_any_any_is_not_overly_permissive() -> None:
    """A catch-all deny is the correct end of a list, not a finding."""
    analysis = analyse_acl(acl(entry(10, D, "ip")))

    assert of(analysis, AclObservationKind.OVERLY_PERMISSIVE) == ()


# ---------------------------------------------------------------------------
# Clean list — the negative control
# ---------------------------------------------------------------------------


def test_a_clean_acl_produces_no_observations() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, P, "tcp", src=cidr("10.0.0.0/8"), dst_port=port(PortOp.EQ, 22)),
            entry(20, P, "tcp", src=cidr("192.168.0.0/16"), dst_port=port(PortOp.EQ, 443)),
            entry(30, D, "ip"),
        )
    )

    assert analysis.is_clean
    assert analysis.entries_analysed == 3


def test_an_empty_acl_is_clean_and_says_how_much_it_analysed() -> None:
    analysis = analyse_acl(acl())

    assert analysis.is_clean
    assert analysis.entries_analysed == 0


# ---------------------------------------------------------------------------
# Protocol subsumption
# ---------------------------------------------------------------------------


def test_ip_covers_tcp() -> None:
    assert covers(entry(10, D, "ip"), entry(20, P, "tcp")) is True


def test_tcp_does_not_cover_ip() -> None:
    assert covers(entry(10, D, "tcp"), entry(20, P, "ip")) is False


def test_tcp_does_not_cover_udp() -> None:
    assert covers(entry(10, D, "tcp"), entry(20, P, "udp")) is False


def test_any_covers_everything() -> None:
    assert covers(entry(10, D, "any"), entry(20, P, "icmp")) is True


# ---------------------------------------------------------------------------
# established / disabled
# ---------------------------------------------------------------------------


def test_an_established_entry_does_not_shadow_a_plain_one() -> None:
    """`established` matches strictly less, so it can narrow but never shadow.

    Ignoring the flag produces confident false positives on exactly the lists
    most likely to have been written carefully.
    """
    analysis = analyse_acl(
        acl(
            entry(10, D, "tcp", established=True),
            entry(20, P, "tcp", src=cidr("10.0.0.0/8")),
        )
    )

    assert of(analysis, AclObservationKind.SHADOWED) == ()


def test_an_established_entry_can_still_be_shadowed() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip"),
            entry(20, P, "tcp", established=True),
        )
    )

    assert len(of(analysis, AclObservationKind.SHADOWED)) == 1


def test_a_disabled_entry_is_excluded_from_analysis() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", disabled=True),
            entry(20, P, "tcp", src=cidr("10.0.0.0/8")),
        )
    )

    assert analysis.is_clean, "a disabled entry must not shadow anything"
    assert analysis.entries_analysed == 1, "and must not be counted as analysed"


# ---------------------------------------------------------------------------
# Ports and hosts
# ---------------------------------------------------------------------------


def test_a_wider_port_range_covers_a_narrower_one() -> None:
    assert (
        covers(
            entry(10, D, "tcp", dst_port=port(PortOp.RANGE, 1, 1024)),
            entry(20, P, "tcp", dst_port=port(PortOp.EQ, 22)),
        )
        is True
    )


def test_a_narrower_port_range_does_not_cover_a_wider_one() -> None:
    assert (
        covers(
            entry(10, D, "tcp", dst_port=port(PortOp.EQ, 22)),
            entry(20, P, "tcp", dst_port=port(PortOp.RANGE, 1, 1024)),
        )
        is False
    )


def test_a_cidr_covers_a_host_inside_it() -> None:
    assert (
        covers(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "ip", src=host("10.1.2.3")),
        )
        is True
    )


def test_a_cidr_does_not_cover_a_host_outside_it() -> None:
    assert (
        covers(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "ip", src=host("192.168.1.1")),
        )
        is False
    )


def test_ipv4_and_ipv6_do_not_cover_each_other() -> None:
    """Different address families do not overlap, and comparing them must not raise."""
    assert (
        covers(
            entry(10, D, "ip", src=cidr("0.0.0.0/0")),
            entry(20, P, "ip", src=cidr("2001:db8::/32")),
        )
        is False
    )


# ---------------------------------------------------------------------------
# Ordering and determinism
# ---------------------------------------------------------------------------


def test_observations_follow_entry_order() -> None:
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=cidr("10.0.0.0/8")),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
            entry(30, P, "tcp", src=cidr("10.2.0.0/16")),
        )
    )

    assert [o.entry_seq for o in analysis.observations] == [20, 30]


def test_analysis_is_deterministic() -> None:
    source = acl(
        entry(10, D, "ip", src=cidr("10.0.0.0/8")),
        entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        entry(30, P, "ip", src=any_addr(), dst=any_addr()),
    )

    first = analyse_acl(source)
    second = analyse_acl(source)

    assert [(o.kind, o.entry_seq, o.caused_by) for o in first.observations] == [
        (o.kind, o.entry_seq, o.caused_by) for o in second.observations
    ]


def test_a_resolved_object_group_is_analysed_normally() -> None:
    """Resolution is what matters, not the address kind."""
    analysis = analyse_acl(
        acl(
            entry(10, D, "ip", src=resolved_object("grp", "10.0.0.0/8")),
            entry(20, P, "tcp", src=cidr("10.1.0.0/16")),
        )
    )

    assert len(of(analysis, AclObservationKind.SHADOWED)) == 1
    assert of(analysis, AclObservationKind.UNDETERMINED) == ()


def test_no_observation_carries_an_unresolved_reason_unless_undetermined() -> None:
    analysis = analyse_acl(acl(entry(10, D, "ip"), entry(20, P, "tcp")))

    for observation in analysis.observations:
        if observation.kind is not AclObservationKind.UNDETERMINED:
            assert observation.unresolved_reason is None
        else:
            assert observation.unresolved_reason in set(UnresolvedReason)
