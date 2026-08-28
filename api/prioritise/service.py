"""Turning a flat findings list into an ordered remediation queue — or refusing to.

This is the "Prioritise" stage of the pipeline the Concept Report names:

    Ingest -> Parse -> Normalise -> Comply -> Prioritise -> Remediate -> Report

and it is the stage that has been a stub since P6, with `exposure_score` and
`priority_rank` sitting on `Finding` as `None` through five phases.

**P12 does not fill them in on this corpus, and that is the finding.** Exposure
needs interfaces and access lists; the corpus has neither, on any device, in any
split. So `prioritise()` assesses every finding, finds every assessment
undetermined, and returns a result that says so — carrying the *reason* per
finding rather than a rank nobody could justify.

The temptation this module exists to refuse is a one-line severity sort. It would
produce an ordered list an operator could act on, it would look exactly like the
feature, and DEVELOPER_GUIDE.md §7 forbids it in as many words: *"Severity alone must not
determine remediation order."* A severity sort presented as exposure-aware
prioritisation would not be a partial implementation — it would be a claim that
reachability had been considered when nothing had been read that could establish
it.

So the ranking is *conditional*, and the condition is checked rather than
assumed: findings are ranked only when their exposure was determined, and the
result reports how many were not.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.models.csm import CanonicalSecurityModel
from api.models.finding import Finding
from api.models.rule import Rulepack
from api.prioritise.baseline import (
    DeviceObservation,
    FieldBaseline,
    Outlier,
    baselines_for,
    cohort_of,
    find_outliers,
)
from api.prioritise.exposure import ExposureAssessment, assess


@dataclass(frozen=True)
class PrioritisedFinding:
    """One finding and what could be established about its exposure."""

    finding: Finding
    exposure: ExposureAssessment

    @property
    def is_ranked(self) -> bool:
        return self.finding.priority_rank is not None


@dataclass(frozen=True)
class Prioritisation:
    """The ordered queue, or an honest statement that there is not one.

    `ranked` is the field a caller must consult before presenting an order. A
    consumer that iterated `findings` and rendered positions would produce a
    ranking out of whatever order the list happened to arrive in, which is the
    failure this type exists to make awkward.
    """

    findings: tuple[PrioritisedFinding, ...]
    ranked: bool
    reason: str
    determined: int = 0
    undetermined: int = 0

    @property
    def total(self) -> int:
        return len(self.findings)

    def blockers(self) -> dict[str, int]:
        """Which missing input stopped how many findings. Points at the backlog."""
        counts: dict[str, int] = {}
        for item in self.findings:
            if item.exposure.is_determined:
                continue
            key = str(item.exposure.determinacy)
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    def describe(self) -> str:
        if self.ranked:
            return (
                f"{self.determined} of {self.total} finding(s) ranked by exposure; "
                f"{self.undetermined} could not be assessed."
            )
        return f"No exposure ranking was produced. {self.reason}"


ORDERING_UNAVAILABLE = (
    "Exposure could not be determined for any finding, so no exposure-aware "
    "ordering exists. Findings are returned in the order the engine produced "
    "them, which is rule order and carries no priority meaning. Ranking by "
    "severity alone is deliberately not offered: severity alone must not "
    "determine remediation order (DEVELOPER_GUIDE.md §7)."
)
"""The sentence a caller shows instead of a rank.

Written here rather than in the router so every consumer says the same thing, and
so the reason travels with the refusal rather than being re-derived by whoever
renders it.
"""


def field_for_rule(rulepack: Rulepack) -> dict[str, str]:
    """Which canonical field each rule examines.

    A `Finding` records the rule that produced it, not the field that rule read —
    so exposure, which is a property of the *control*, has to be resolved through
    the rulepack. Taking the contract from `api.models.rule` rather than importing
    `api.comply` keeps the forbidden edge intact: this layer must not be able to
    see verdict logic.
    """
    return {rule.rule_id: rule.check.field for rule in rulepack.rules}


def prioritise(
    csm: CanonicalSecurityModel,
    findings: tuple[Finding, ...],
    rulepack: Rulepack,
) -> Prioritisation:
    """Assess exposure for each finding and rank the ones that could be assessed.

    Every finding is assessed and returned rather than only the failing ones, so
    a caller sees the whole picture instead of a filtered one and can tell an
    unranked queue from a short one.
    """
    fields = field_for_rule(rulepack)

    assessed = [
        PrioritisedFinding(
            finding=finding,
            exposure=assess(
                csm,
                field_name=fields.get(finding.rule_id, ""),
                severity=finding.base_severity,
            ),
        )
        for finding in findings
    ]

    determined = [a for a in assessed if a.exposure.is_determined]
    undetermined = len(assessed) - len(determined)

    if not determined:
        return Prioritisation(
            findings=tuple(assessed),
            ranked=False,
            reason=ORDERING_UNAVAILABLE,
            determined=0,
            undetermined=undetermined,
        )

    # Highest exposure first; ties broken deterministically so a queue does not
    # reshuffle between runs while an operator is working through it.
    order = sorted(
        determined,
        key=lambda a: (-(a.exposure.score or 0.0), a.finding.rule_id),
    )
    ranked_ids = {id(a): position for position, a in enumerate(order, start=1)}

    final = tuple(
        PrioritisedFinding(
            finding=(
                a.finding.model_copy(
                    update={
                        "priority_rank": ranked_ids[id(a)],
                        "exposure_score": a.exposure.score,
                    }
                )
                if id(a) in ranked_ids
                else a.finding
            ),
            exposure=a.exposure,
        )
        for a in assessed
    )

    return Prioritisation(
        findings=final,
        ranked=True,
        reason="ranked by assessed exposure",
        determined=len(determined),
        undetermined=undetermined,
    )


# ---------------------------------------------------------------------------
# Fleet
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FleetBaseline:
    """Every cohort's baselines, and the devices that deviate from them."""

    observations: tuple[DeviceObservation, ...]
    baselines: tuple[FieldBaseline, ...]
    outliers: tuple[Outlier, ...]

    @property
    def device_count(self) -> int:
        return len(self.observations)

    @property
    def cohorts(self) -> tuple[str, ...]:
        return tuple(sorted({o.cohort for o in self.observations}))

    def describe(self) -> str:
        compared = sum(1 for b in self.baselines if b.majority_state is not None)
        if not compared:
            return (
                f"{self.device_count} device(s) across {len(self.cohorts)} cohort(s); "
                "no baseline could be established. Every cohort is either below the "
                "minimum size or abstained on every field."
            )
        return (
            f"{self.device_count} device(s) across {len(self.cohorts)} cohort(s); "
            f"{compared} baseline(s) established, {len(self.outliers)} deviation(s)."
        )


def fleet_baseline(models: list[CanonicalSecurityModel]) -> FleetBaseline:
    """Compare every device against its own peer group.

    Takes canonical models rather than reading a database, so the analysis is
    testable without one and cannot acquire a route to storage. The router
    assembles the models.
    """
    observations = [DeviceObservation.from_csm(csm, cohort=cohort_of(csm)) for csm in models]
    return FleetBaseline(
        observations=tuple(observations),
        baselines=baselines_for(observations),
        outliers=find_outliers(observations),
    )
