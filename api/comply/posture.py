"""Per-framework compliance posture, and the gate in front of it (ADR 0068).

Deviation analysis "against the chosen framework" (PS 26155) needs a measure per
framework, and a measure is only honest over a file that was fully read. So this
module decides two things, both from stored state and nothing the interface
holds:

**The gate.** A device is scored only when every entry in the Needs-review queue
for the file of its latest run has an administrator's decision, and that run is
newer than every such decision. Anything less is a reason, never a number. A
file the corpus manifest reserves for measurement is never scored here at all.

**The roll-up.** The unit is the framework *control*. A control rolls up from
every rule mapped to it on this device:

    violated            any mapped rule FAILED
    satisfied           every mapped rule PASSED, and at least one mapping to
                        the control is FULL
    no violation found  every mapped rule PASSED, and every mapping is PARTIAL
    undetermined        otherwise — an UNKNOWN, a NOT_APPLICABLE, or no verdict

The two directions are not symmetric. A failed check is a violation of the
control whatever share of it the rule tests, so violated needs one FAIL. A
passed check shows the control is met only when the rule tests all of it; most
mappings test part of a control, and for those a pass means "our check found no
violation", which is what the state is called. NOT_APPLICABLE is undetermined:
it says the rule cannot be expressed on this platform, not that the control is
met.

The headline is a fraction — controls fully satisfied, of controls assessed —
never a percentage, so it cannot be read as compliance with the whole catalog.
Undetermined and no-violation-found both count against it, so it can
understate compliance and cannot overstate it.

A declined mapping (`not_mapped`) never contributes: the roll-up reads
`frameworks` and nothing else, and a decline is the rule saying it does *not*
evidence that framework.

Clearing the queue does not clear UNKNOWN. A directive that is absent from the
file (nothing to review) or two lines that disagree stay UNKNOWN after review,
and stay visible here as undetermined. The gate proves the file was fully read,
not that every question was answerable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime

from api.comply.frameworks import (
    CatalogIndex,
    Coverage,
    explain_absence,
    indexes,
    refs_for_device,
    run_framework_view,
)
from api.models.enums import Framework, MappingCoverage, Verdict
from api.models.finding import Finding
from api.models.posture import (
    ControlPosture,
    ControlState,
    DevicePosture,
    FrameworkPosture,
    FrameworkStatus,
    Gate,
    GateState,
    ReviewProgress,
    RuleContribution,
)
from api.models.rule import ComplianceRule, FrameworkRef

REVIEW_PENDING_MESSAGE = "Review all unrecognised lines before a compliance score is shown."
RERUN_REQUIRED_MESSAGE = "Re-run the audit to include your review decisions."
EVALUATION_FILE_MESSAGE = (
    "Reserved for measurement — scored by the evaluation harness, not reviewed."
)


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value)


def decide_gate(
    *,
    run: Mapping | None,
    platform_identified: bool,
    review: ReviewProgress | None,
    last_decision_at: str | None,
    is_admin: bool,
    reserved_split: str | None = None,
) -> Gate:
    """The gate state for one device, from its latest run and its review queue.

    `review` counts entries in the queue for the file of `run`; `last_decision_at`
    is the newest administrator decision on any of them. Remediation review marks
    are not an input: they live in the browser, and a gate the server cannot see
    is not a gate.

    `reserved_split` is the corpus split that reserves this exact file for
    measurement (`evaluation` or `holdout`), read from the manifest. Such a file
    is neither scored nor reviewed: reviewing it would compile patterns from the
    data the parser is measured on (DEF-16).
    """
    if reserved_split is not None:
        return Gate(
            state=GateState.EVALUATION_FILE,
            message=EVALUATION_FILE_MESSAGE,
            next_step=(
                f"This file is in the corpus {reserved_split} split. Its lines are not "
                "reviewed here, so no compliance score is computed for it."
            ),
            audit_id=run.get("audit_id") if run else None,
            evaluated_at=run.get("evaluated_at") if run else None,
        )
    if not platform_identified:
        return Gate(
            state=GateState.NOT_AUDITED,
            message=(
                "The platform of this configuration was not identified, so no vendor "
                "pack applies and it cannot be audited or scored."
            ),
            next_step=(
                "Describe its platform from the file on the bootstrap page."
                if is_admin
                else "An administrator can describe its platform from the file."
            ),
        )
    if run is None:
        return Gate(
            state=GateState.NOT_AUDITED,
            message="This configuration has not been audited, so there is nothing to score.",
            next_step="Run an audit on this device.",
        )

    audit_id = run.get("audit_id")
    evaluated_at = run.get("evaluated_at")
    review = review or ReviewProgress(reviewed=0, total=0)

    if review.reviewed < review.total:
        return Gate(
            state=GateState.REVIEW_PENDING,
            message=REVIEW_PENDING_MESSAGE,
            next_step=(
                "Decide the remaining lines in Needs review."
                if is_admin
                else "An administrator must complete the review."
            ),
            review=review,
            audit_id=audit_id,
            evaluated_at=evaluated_at,
            last_decision_at=last_decision_at,
        )

    if last_decision_at and evaluated_at and _instant(last_decision_at) > _instant(evaluated_at):
        return Gate(
            state=GateState.RERUN_REQUIRED,
            message=RERUN_REQUIRED_MESSAGE,
            next_step="Re-run the audit on this device.",
            review=review,
            audit_id=audit_id,
            evaluated_at=evaluated_at,
            last_decision_at=last_decision_at,
        )

    return Gate(
        state=GateState.READY,
        message=(
            "Every unrecognised line has a decision, and the latest run includes them all."
            if review.total
            else "Every line was recognised by the vendor pack; nothing awaits review."
        ),
        review=review,
        audit_id=audit_id,
        evaluated_at=evaluated_at,
        last_decision_at=last_decision_at,
    )


def superseded_gate(run: Mapping, latest_evaluated_at: str | None) -> Gate:
    """For a report on a run that is not the device's latest."""
    return Gate(
        state=GateState.SUPERSEDED,
        message=(
            "A newer audit of this configuration exists. The review queue describes the "
            "newest parse, so whether this run read the whole file cannot be shown, and "
            "no compliance score is given for it."
        ),
        next_step="Generate the report from the latest run.",
        audit_id=run.get("audit_id"),
        evaluated_at=run.get("evaluated_at"),
        last_decision_at=latest_evaluated_at,
    )


# ---------------------------------------------------------------------------
# The roll-up
# ---------------------------------------------------------------------------


def _contribution(rule_id: str, ref: FrameworkRef, finding: Finding | None) -> RuleContribution:
    judged = {"coverage": ref.coverage, "coverage_reason": ref.coverage_reason}
    if finding is None:
        return RuleContribution(rule_id=rule_id, verdict=None, **judged)
    return RuleContribution(
        rule_id=rule_id,
        **judged,
        verdict=finding.status,
        finding_id=finding.finding_id,
        unknown_reason=finding.unknown_reason,
        absence_reason=finding.absence_reason,
        evidence=tuple(finding.evidence),
    )


def _why_not_passed(c: RuleContribution) -> str:
    if c.verdict is None:
        return f"{c.rule_id} was not evaluated in this run"
    if c.verdict is Verdict.UNKNOWN:
        why = c.unknown_reason.value if c.unknown_reason else "no reason recorded"
        return f"{c.rule_id} is UNKNOWN ({why})"
    if c.verdict is Verdict.NOT_APPLICABLE:
        return f"{c.rule_id} is not applicable on this platform"
    return f"{c.rule_id} is {c.verdict.value.upper()}"


def roll_up(control_id: str, contributions: tuple[RuleContribution, ...]) -> ControlPosture:
    """One control, from every rule mapped to it. See the module docstring."""
    failed = [c.rule_id for c in contributions if c.verdict is Verdict.FAIL]
    if failed:
        return ControlPosture(
            control_id=control_id,
            state=ControlState.VIOLATED,
            reason=f"{', '.join(failed)} failed; one failing mapped check is enough.",
            rules=contributions,
        )
    if contributions and all(c.verdict is Verdict.PASS for c in contributions):
        passed = ", ".join(c.rule_id for c in contributions)
        full = [c.rule_id for c in contributions if c.coverage is MappingCoverage.FULL]
        if full:
            return ControlPosture(
                control_id=control_id,
                state=ControlState.SATISFIED,
                reason=(
                    f"Every mapped check passed ({passed}), and {', '.join(full)} tests "
                    "the whole control."
                ),
                rules=contributions,
            )
        return ControlPosture(
            control_id=control_id,
            state=ControlState.NO_VIOLATION_FOUND,
            reason=(
                f"Every mapped check passed ({passed}), but each tests only part of this "
                "control, so a pass means no violation was found, not that it is met."
            ),
            rules=contributions,
        )
    open_ = [_why_not_passed(c) for c in contributions if c.verdict is not Verdict.PASS]
    return ControlPosture(
        control_id=control_id,
        state=ControlState.UNDETERMINED,
        reason="; ".join(open_) + ". Nothing failed, and not every mapped check could pass.",
        rules=contributions,
    )


def catalog_basis(index: CatalogIndex) -> tuple[int | None, str]:
    """The catalog's control total, and where it was derived from.

    Read from the pinned index, never typed. Withdrawn identifiers are not
    counted: a control that no longer exists cannot be assessed.
    """
    total = index.control_count
    if total <= 0:  # CatalogIndex refuses an empty index; kept honest here
        return None, f"The {index.document} index names no controls, so no total can be derived."
    if index.held_at:
        where = (
            f"the index re-derived from the edition's source file held in this repository "
            f"({index.held_at})"
        )
    else:
        where = (
            f"the pinned index for this edition (catalog sha256 {index.sha256[:12]}…); "
            "the catalog itself is not held in this repository"
        )
    return total, f"{total} live controls in {where}."


_STATE_ORDER = {
    ControlState.VIOLATED: 0,
    ControlState.UNDETERMINED: 1,
    ControlState.NO_VIOLATION_FOUND: 2,
    ControlState.SATISFIED: 3,
}


def framework_posture(
    framework: Framework,
    index: CatalogIndex,
    rules: Iterable[ComplianceRule],
    findings_by_rule: Mapping[str, Finding],
    vendor: str | None,
    os_family: str | None,
    os_version: str | None,
    effective_selection: frozenset[Framework] | None,
) -> FrameworkPosture:
    """One framework's posture on one device, from one run's findings.

    `effective_selection` is the run's benchmark scope after it was resolved
    against the device; None or empty means the run was unscoped.
    """
    total, basis = catalog_basis(index)
    base = {
        "framework": framework.value,
        "document": index.document,
        "edition": index.edition,
        "catalog_total": total,
        "catalog_basis": basis,
    }

    if index.coverage(vendor, os_family, os_version) is not Coverage.COVERED:
        return FrameworkPosture(
            **base,
            status=FrameworkStatus.NOT_APPLICABLE,
            reason=index.explain_coverage(vendor, os_family, os_version),
        )
    if effective_selection and framework not in effective_selection:
        return FrameworkPosture(
            **base,
            status=FrameworkStatus.NOT_IN_SCOPE,
            reason=(
                "This run was scoped to "
                + ", ".join(sorted(f.value.upper() for f in effective_selection))
                + f", so the checks mapped to {framework.value.upper()} were not all run. "
                "Run an unscoped audit, or one that selects it."
            ),
        )

    by_control: dict[str, list[RuleContribution]] = {}
    for rule in rules:
        if not rule.applies_to.matches(vendor, os_family):
            continue
        for ref in refs_for_device(rule.frameworks, vendor, os_family, os_version):
            if ref.framework is not framework:
                continue
            by_control.setdefault(ref.control_id, []).append(
                _contribution(rule.rule_id, ref, findings_by_rule.get(rule.rule_id))
            )

    controls = sorted(
        (roll_up(cid, tuple(contribs)) for cid, contribs in by_control.items()),
        key=lambda c: (_STATE_ORDER[c.state], c.control_id),
    )

    def count(state: ControlState) -> int:
        return sum(1 for c in controls if c.state is state)

    return FrameworkPosture(
        **base,
        status=FrameworkStatus.ASSESSED,
        satisfied=count(ControlState.SATISFIED),
        no_violation_found=count(ControlState.NO_VIOLATION_FOUND),
        violated=count(ControlState.VIOLATED),
        undetermined=count(ControlState.UNDETERMINED),
        controls=tuple(controls),
    )


def device_posture(
    gate: Gate,
    *,
    run: Mapping | None,
    findings: Iterable[Finding],
    rulepack_checksum: str | None,
    rulepack_version: str,
    rules: Iterable[ComplianceRule],
    vendor: str | None,
    os_family: str | None,
    os_version: str | None,
) -> DevicePosture:
    """The gate, and — only when it is `ready` — the posture per sourced framework.

    Mappings are attached exactly as the findings view attaches them: only when
    the run's recorded rulepack content is the active content (ADR 0056). When
    it is not, the reason is returned and no framework is scored.
    """
    if gate.state is not GateState.READY or run is None:
        return DevicePosture(gate=gate)

    rules = tuple(rules)
    view = run_framework_view(
        rulepack_checksum, rulepack_version, rules, dict(run), vendor, os_family, os_version
    )
    if not view.attached:
        return DevicePosture(
            gate=gate, mappings_attached=False, withheld_reason=view.withheld_reason
        )

    findings_by_rule = {f.rule_id: f for f in findings}
    effective = view.scope.effective if view.scope else frozenset()
    available = indexes()
    return DevicePosture(
        gate=gate,
        mappings_attached=True,
        frameworks=tuple(
            framework_posture(
                framework, index, rules, findings_by_rule, vendor, os_family, os_version, effective
            )
            for framework, index in sorted(available.items(), key=lambda kv: kv[0].value)
        ),
        unsourced={
            name: why
            for name, why in explain_absence(vendor, os_family, os_version).items()
            if Framework(name) not in available
        },
    )
