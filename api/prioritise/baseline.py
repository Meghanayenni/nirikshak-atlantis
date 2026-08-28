"""Peer-baseline outlier detection.

The Concept Report:

> Across a fleet, the system reports devices that deviate from their own peer
> group — forty-seven switches with a logging host configured and three without.
> This is statistical and fully explainable, requires no model, and surfaces
> drift that no static checklist can express.

Every clause is a constraint. *Statistical* means counting, not scoring.
*Fully explainable* means every outlier carries the arithmetic that produced it,
so an operator can check the claim rather than trust it. *Requires no model*
means there is no import of `api.learn` here and no similarity anywhere near it —
this is a comparison of states, and a state either matched the cohort or it did
not.

**The failure this module is built to avoid is counting UNKNOWN as absent.**
"Forty-seven switches have a logging host and three do not" is only true if those
three were *read* and found not to have one. A device whose `logging_hosts` field
abstained is not a device without logging; it is a device we could not read, and
folding it into the minority would manufacture drift out of our own parsing gaps.
That is the same substitution DEF-2 was fixed for at P5, arriving here by a
different route — so states are partitioned three ways and only the determinable
ones are compared.

**A cohort below `MIN_COHORT_SIZE` produces no outliers at all.** Among three
devices, "one differs from two" is not drift; it is a coin landing. The floor is
set plainly above what this corpus can supply, exactly as
`api/learn/calibration.py` sets its sample floor, so the refusal is unambiguous
rather than marginal.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

from api.models.csm import CanonicalSecurityModel
from api.models.enums import FieldState

MIN_COHORT_SIZE = 5
"""Below this, a cohort produces no outlier claims.

Not a statistical derivation and not presented as one. With four devices, a
single deviation is 25% of the fleet and calling it an outlier says more about
the sample than the device. Set above what this corpus can supply so the refusal
is visible rather than borderline — the same reasoning, and the same honesty,
as the calibration floor at P10.
"""

MIN_MAJORITY_RATIO = 0.75
"""How much of a cohort must agree before a deviation is worth reporting.

A cohort split 50/50 has no baseline to deviate from — it has two conventions,
which is a fact about the fleet rather than a fault in a device. Reported as
`NO_MAJORITY` rather than as an outlier in whichever group happens to be smaller.
"""


class BaselineOutcome(StrEnum):
    """Why a cohort/field pair produced the answer it did."""

    COMPARED = "compared"
    """A baseline existed and every device was measured against it."""

    COHORT_TOO_SMALL = "cohort_too_small"
    """Fewer than MIN_COHORT_SIZE devices. No claim is made either way."""

    NO_DETERMINABLE_STATES = "no_determinable_states"
    """Every device abstained on this field, so there is nothing to compare.

    The common case on this corpus for every vendor except Cisco: a pack with no
    parsing pattern produces UNKNOWN everywhere, and a cohort of unknowns has no
    majority — it has no observations.
    """

    NO_MAJORITY = "no_majority"
    """The cohort is genuinely split. Two conventions, not one baseline."""


@dataclass(frozen=True)
class DeviceObservation:
    """One device's state for the fields a cohort is compared on.

    Deliberately not a `CanonicalSecurityModel`: the baseline compares *states*,
    and passing whole models around would let a future change reach a value, an
    evidence line or a verdict from inside a counting routine.
    """

    device_id: str
    cohort: str
    hostname: str | None
    states: dict[str, FieldState]

    @classmethod
    def from_csm(cls, csm: CanonicalSecurityModel, *, cohort: str) -> DeviceObservation:
        return cls(
            device_id=csm.device.device_id,
            cohort=cohort,
            hostname=csm.device.hostname,
            states={name: field.state for name, field in csm.fields.items()},
        )

    @property
    def label(self) -> str:
        """What an operator is shown. Falls back to the identifier, never to a guess."""
        return self.hostname or self.device_id[:12]


@dataclass(frozen=True)
class FieldBaseline:
    """What a cohort does about one canonical field, and how firmly.

    `indeterminate` is carried rather than discarded because it is the number
    that tells an operator how much of the fleet this baseline could not see. A
    baseline over four devices where six abstained is a different claim from one
    over ten, and a report that showed only the four would be describing a fleet
    it never read.
    """

    cohort: str
    field: str
    outcome: BaselineOutcome

    cohort_size: int = 0
    determinable: int = 0
    indeterminate: int = 0
    counts: dict[str, int] | None = None

    majority_state: FieldState | None = None
    majority_count: int = 0

    @property
    def majority_ratio(self) -> float:
        if not self.determinable:
            return 0.0
        return self.majority_count / self.determinable

    def explain(self) -> str:
        """The arithmetic, in a sentence. "Fully explainable" is a requirement."""
        if self.outcome is BaselineOutcome.COHORT_TOO_SMALL:
            return (
                f"cohort {self.cohort!r} holds {self.cohort_size} device(s); "
                f"{MIN_COHORT_SIZE} are required before a deviation means anything"
            )
        if self.outcome is BaselineOutcome.NO_DETERMINABLE_STATES:
            return (
                f"every one of {self.cohort_size} device(s) in {self.cohort!r} "
                f"abstained on {self.field!r}; there is nothing to compare"
            )
        if self.outcome is BaselineOutcome.NO_MAJORITY:
            return (
                f"{self.cohort!r} is split on {self.field!r} "
                f"({self.counts}); a split cohort has no baseline to deviate from"
            )
        return (
            f"{self.majority_count} of {self.determinable} readable device(s) in "
            f"{self.cohort!r} are {self.majority_state} for {self.field!r}"
            + (f", {self.indeterminate} abstained" if self.indeterminate else "")
        )


@dataclass(frozen=True)
class Outlier:
    """One device deviating from its cohort on one field.

    An observation about the fleet, never a verdict. Whether deviating is a
    breach is a question for the rule engine over the canonical model, and this
    layer has no route to one — the same separation decision D22 drew for ACL
    observations at P7.
    """

    device_id: str
    label: str
    cohort: str
    field: str
    device_state: FieldState
    baseline: FieldBaseline

    def explain(self) -> str:
        return (
            f"{self.label} is {self.device_state} for {self.field!r} while "
            f"{self.baseline.majority_count} of {self.baseline.determinable} "
            f"readable device(s) in {self.cohort!r} are "
            f"{self.baseline.majority_state}"
        )


def cohort_of(csm: CanonicalSecurityModel) -> str:
    """Which peer group a device is compared against.

    `peer_group` is operator metadata and nothing populates it today, so the
    cohort falls back to the platform. That is the honest default: comparing a
    Cisco router against a Juniper firewall would produce drift that is a
    difference in vendor rather than in configuration.
    """
    if csm.device.peer_group:
        return csm.device.peer_group
    vendor = csm.device.vendor or "unknown-vendor"
    os_family = csm.device.os_family or "unknown-os"
    return f"{vendor}/{os_family}"


DETERMINABLE_STATES: frozenset[FieldState] = frozenset(
    {FieldState.PRESENT, FieldState.ABSENT_DEFAULT, FieldState.ABSENT_UNSUPPORTED}
)
"""States that count as an observation.

`UNKNOWN` is excluded, and that exclusion is the point of this module. A field we
could not read is not a field that is missing, and counting it as one would
invent drift out of our own parsing gaps.
"""


def build_baseline(
    observations: list[DeviceObservation], *, cohort: str, field: str
) -> FieldBaseline:
    """What one cohort does about one field."""
    members = [o for o in observations if o.cohort == cohort]
    size = len(members)

    states = [o.states.get(field, FieldState.UNKNOWN) for o in members]
    determinable = [s for s in states if s in DETERMINABLE_STATES]
    indeterminate = len(states) - len(determinable)

    if size < MIN_COHORT_SIZE:
        return FieldBaseline(
            cohort=cohort,
            field=field,
            outcome=BaselineOutcome.COHORT_TOO_SMALL,
            cohort_size=size,
            determinable=len(determinable),
            indeterminate=indeterminate,
        )

    if not determinable:
        return FieldBaseline(
            cohort=cohort,
            field=field,
            outcome=BaselineOutcome.NO_DETERMINABLE_STATES,
            cohort_size=size,
            determinable=0,
            indeterminate=indeterminate,
        )

    counts = Counter(str(s) for s in determinable)
    top_state, top_count = counts.most_common(1)[0]

    baseline = FieldBaseline(
        cohort=cohort,
        field=field,
        outcome=BaselineOutcome.COMPARED,
        cohort_size=size,
        determinable=len(determinable),
        indeterminate=indeterminate,
        counts=dict(counts),
        majority_state=FieldState(top_state),
        majority_count=top_count,
    )

    if baseline.majority_ratio < MIN_MAJORITY_RATIO:
        return FieldBaseline(
            cohort=cohort,
            field=field,
            outcome=BaselineOutcome.NO_MAJORITY,
            cohort_size=size,
            determinable=len(determinable),
            indeterminate=indeterminate,
            counts=dict(counts),
        )

    return baseline


def find_outliers(observations: list[DeviceObservation]) -> tuple[Outlier, ...]:
    """Every device deviating from its own cohort's majority.

    Deterministic ordering — cohort, then field, then device label — so the same
    fleet produces the same list on every run and on every machine. A list that
    reordered between runs would make drift impossible to track.
    """
    outliers: list[Outlier] = []

    for cohort in sorted({o.cohort for o in observations}):
        members = [o for o in observations if o.cohort == cohort]
        fields = sorted({name for o in members for name in o.states})

        for field in fields:
            baseline = build_baseline(observations, cohort=cohort, field=field)
            if baseline.outcome is not BaselineOutcome.COMPARED:
                continue

            for member in sorted(members, key=lambda o: (o.label, o.device_id)):
                state = member.states.get(field, FieldState.UNKNOWN)
                if state not in DETERMINABLE_STATES:
                    continue  # an abstention is not a deviation
                if state == baseline.majority_state:
                    continue
                outliers.append(
                    Outlier(
                        device_id=member.device_id,
                        label=member.label,
                        cohort=cohort,
                        field=field,
                        device_state=state,
                        baseline=baseline,
                    )
                )

    return tuple(outliers)


def baselines_for(observations: list[DeviceObservation]) -> tuple[FieldBaseline, ...]:
    """Every cohort/field baseline, including the ones that produced no claim.

    The refusals are the useful half on this corpus: a report that listed only
    COMPARED baselines would show an empty page and look like a clean fleet.
    """
    out: list[FieldBaseline] = []
    for cohort in sorted({o.cohort for o in observations}):
        members = [o for o in observations if o.cohort == cohort]
        for field in sorted({name for o in members for name in o.states}):
            out.append(build_baseline(observations, cohort=cohort, field=field))
    return tuple(out)
