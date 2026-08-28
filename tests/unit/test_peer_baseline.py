"""Peer-baseline outlier detection (P12).

The corpus cannot exercise the interesting path: every cohort holds fewer than
`MIN_COHORT_SIZE` devices, so on real data this module returns refusals and
nothing else. These tests therefore work against **constructed observations** —
the same approach P7 took for ACL analysis and P8 for remediation, and named as
such rather than presented as a measurement.

What is being tested is the arithmetic and, more importantly, the three ways it
can lie: counting an abstention as an absence, calling a coin-flip an outlier,
and picking a "majority" out of a cohort that is genuinely split.
"""

from __future__ import annotations

import pytest

from api.models.enums import FieldState
from api.prioritise.baseline import (
    MIN_COHORT_SIZE,
    BaselineOutcome,
    DeviceObservation,
    baselines_for,
    build_baseline,
    find_outliers,
)

COHORT = "acme/os"


def device(name: str, **states: FieldState) -> DeviceObservation:
    return DeviceObservation(
        device_id=f"id-{name}", cohort=COHORT, hostname=name, states=dict(states)
    )


def fleet(*present_absent: tuple[str, FieldState]) -> list[DeviceObservation]:
    return [device(name, logging_hosts=state) for name, state in present_absent]


# ---------------------------------------------------------------------------
# The cohort floor
# ---------------------------------------------------------------------------


def test_a_cohort_below_the_floor_makes_no_claim() -> None:
    """Among three devices, "one differs from two" is a coin landing."""
    observations = fleet(
        ("a", FieldState.PRESENT), ("b", FieldState.PRESENT), ("c", FieldState.UNKNOWN)
    )
    baseline = build_baseline(observations, cohort=COHORT, field="logging_hosts")

    assert baseline.outcome is BaselineOutcome.COHORT_TOO_SMALL
    assert baseline.majority_state is None
    assert find_outliers(observations) == ()
    assert "are required before a deviation means anything" in baseline.explain()


def test_the_floor_is_stated_plainly_and_is_above_this_corpus() -> None:
    """Set plainly rather than derived, exactly as the calibration floor is.

    The largest cohort the corpus can form is four Cisco devices, so the refusal
    on real data is unambiguous rather than marginal.
    """
    assert MIN_COHORT_SIZE == 5


# ---------------------------------------------------------------------------
# The failure this module exists to prevent
# ---------------------------------------------------------------------------


def test_an_abstention_is_not_an_absence() -> None:
    """The peer-baseline form of DEF-2, and the reason for the whole module.

    Five devices: four read as PRESENT, one abstained. The abstaining device is
    NOT an outlier — we could not read it, which is a fact about our parser and
    not about the device.
    """
    observations = fleet(
        ("a", FieldState.PRESENT),
        ("b", FieldState.PRESENT),
        ("c", FieldState.PRESENT),
        ("d", FieldState.PRESENT),
        ("e", FieldState.UNKNOWN),
    )
    baseline = build_baseline(observations, cohort=COHORT, field="logging_hosts")

    assert baseline.outcome is BaselineOutcome.COMPARED
    assert baseline.determinable == 4
    assert baseline.indeterminate == 1
    assert baseline.majority_count == 4
    assert find_outliers(observations) == (), "an abstention must not be reported as drift"


def test_the_indeterminate_count_is_reported_not_discarded() -> None:
    """How much of the fleet the baseline could not see is part of the claim.

    A baseline over four readable devices where six abstained is a different
    statement from one over ten, and showing only the four would describe a fleet
    that was never read.
    """
    observations = fleet(
        *[(f"d{i}", FieldState.PRESENT) for i in range(4)],
        *[(f"u{i}", FieldState.UNKNOWN) for i in range(6)],
    )
    baseline = build_baseline(observations, cohort=COHORT, field="logging_hosts")

    assert baseline.cohort_size == 10
    assert baseline.determinable == 4
    assert baseline.indeterminate == 6
    assert "6 abstained" in baseline.explain()


def test_a_cohort_of_only_abstentions_compares_nothing() -> None:
    """The state of Arista and Juniper on this corpus: no pattern, no observation."""
    observations = fleet(*[(f"d{i}", FieldState.UNKNOWN) for i in range(6)])
    baseline = build_baseline(observations, cohort=COHORT, field="logging_hosts")

    assert baseline.outcome is BaselineOutcome.NO_DETERMINABLE_STATES
    assert "there is nothing to compare" in baseline.explain()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_the_concept_report_example() -> None:
    """ "Forty-seven switches with a logging host configured and three without."

    Scaled down but identical in shape: the three are outliers, the forty-seven
    are the baseline, and the explanation carries the arithmetic.
    """
    observations = fleet(
        *[(f"ok{i}", FieldState.PRESENT) for i in range(47)],
        *[(f"drift{i}", FieldState.ABSENT_DEFAULT) for i in range(3)],
    )
    outliers = find_outliers(observations)

    assert len(outliers) == 3
    assert {o.label for o in outliers} == {"drift0", "drift1", "drift2"}

    first = outliers[0]
    assert first.device_state is FieldState.ABSENT_DEFAULT
    assert first.baseline.majority_state is FieldState.PRESENT
    assert first.baseline.majority_count == 47
    assert "47 of 50" in first.explain()


def test_a_split_cohort_has_no_baseline() -> None:
    """Two conventions is a fact about the fleet, not a fault in a device.

    Reporting the smaller half as outliers would be an arbitrary choice of which
    half is correct — a judgement nobody made.
    """
    observations = fleet(
        ("a", FieldState.PRESENT),
        ("b", FieldState.PRESENT),
        ("c", FieldState.PRESENT),
        ("d", FieldState.ABSENT_DEFAULT),
        ("e", FieldState.ABSENT_DEFAULT),
        ("f", FieldState.ABSENT_DEFAULT),
    )
    baseline = build_baseline(observations, cohort=COHORT, field="logging_hosts")

    assert baseline.outcome is BaselineOutcome.NO_MAJORITY
    assert find_outliers(observations) == ()
    assert "no baseline to deviate from" in baseline.explain()


def test_devices_are_only_compared_within_their_own_cohort() -> None:
    """A Cisco router is not drift because a Juniper firewall differs."""
    cisco = [
        DeviceObservation(f"c{i}", "cisco/ios", f"c{i}", {"telnet_enabled": FieldState.PRESENT})
        for i in range(5)
    ]
    juniper = [
        DeviceObservation(
            f"j{i}", "juniper/junos", f"j{i}", {"telnet_enabled": FieldState.ABSENT_DEFAULT}
        )
        for i in range(5)
    ]
    assert find_outliers(cisco + juniper) == ()


def test_outlier_ordering_is_deterministic() -> None:
    """A queue that reshuffled between runs would make drift impossible to track."""
    observations = fleet(
        *[(f"ok{i}", FieldState.PRESENT) for i in range(8)],
        ("zeta", FieldState.ABSENT_DEFAULT),
        ("alpha", FieldState.ABSENT_DEFAULT),
    )
    first = [o.label for o in find_outliers(observations)]
    second = [o.label for o in find_outliers(list(reversed(observations)))]

    assert first == second == ["alpha", "zeta"]


def test_an_outlier_is_an_observation_not_a_verdict() -> None:
    """D22's separation, applied to drift.

    An `Outlier` names a state and a cohort. It carries no verdict, no severity
    and no remediation, because whether deviating from one's peers breaches a
    control is a different question decided by a different engine.
    """
    observations = fleet(
        *[(f"ok{i}", FieldState.PRESENT) for i in range(6)],
        ("odd", FieldState.ABSENT_DEFAULT),
    )
    outlier = find_outliers(observations)[0]

    assert not hasattr(outlier, "status")
    assert not hasattr(outlier, "severity")
    assert not hasattr(outlier, "remediation")


def test_baselines_include_the_refusals() -> None:
    """A response listing only comparable baselines reads as a uniform fleet."""
    observations = fleet(("a", FieldState.PRESENT), ("b", FieldState.PRESENT))
    baselines = baselines_for(observations)

    assert len(baselines) == 1
    assert baselines[0].outcome is BaselineOutcome.COHORT_TOO_SMALL


def test_a_device_label_falls_back_to_an_identifier_never_a_guess() -> None:
    anonymous = DeviceObservation("abcdef0123456789", COHORT, None, {})
    assert anonymous.label == "abcdef012345"

    named = DeviceObservation("abcdef0123456789", COHORT, "sw-leaf-01", {})
    assert named.label == "sw-leaf-01"


@pytest.mark.parametrize(
    "state", [FieldState.PRESENT, FieldState.ABSENT_DEFAULT, FieldState.ABSENT_UNSUPPORTED]
)
def test_every_determinable_state_can_form_a_majority(state: FieldState) -> None:
    """ABSENT_DEFAULT and ABSENT_UNSUPPORTED are observations, not absences of one."""
    observations = fleet(*[(f"d{i}", state) for i in range(6)])
    baseline = build_baseline(observations, cohort=COHORT, field="logging_hosts")

    assert baseline.outcome is BaselineOutcome.COMPARED
    assert baseline.majority_state is state
