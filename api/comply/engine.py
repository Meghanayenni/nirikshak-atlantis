"""The deterministic rule engine — the only thing in NIRIKSHAK that says PASS.

DEVELOPER_GUIDE.md Rule 1 in code form. This module's inputs are a typed
`CanonicalSecurityModel` and a `Rulepack`, and there is no third parameter. Raw
configuration text and model output cannot reach a verdict because there is
nowhere for them to enter, which is asserted by import tests rather than trusted.

The verdict table, in full:

    CSM field state       policy consulted            verdict
    ----------------------------------------------------------------------
    PRESENT               —                           PASS / FAIL
    ABSENT_DEFAULT        on_absent_default           per policy
    ABSENT_UNSUPPORTED    on_absent_unsupported       per policy
    UNKNOWN               on_capability_unknown       UNKNOWN, always
    key absent            —                           UNKNOWN · no_match
    rule not applicable   —                           no finding at all

Two rules govern every row, and both are Rule 3 obligations:

**A verdict needs justification.** PASS and FAIL require the field's own evidence
or, for a documented default, the citation that default rests on. A field that is
PRESENT without evidence cannot exist — the `Field` contract forbids it — so this
is belt and braces, but the engine checks rather than assumes.

**An unanswerable question stays unanswered.** A condition that cannot be
evaluated against the value it was given abstains with `rule_type_mismatch`. It
never becomes FAIL, which is the tempting mistake: FAIL feels like the safe
direction for a security tool, and it is not. It is a claim about a device, made
without evidence, that an operator would spend time on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from api.comply.conditions import describe_all, evaluate_all
from api.models.csm import CanonicalSecurityModel
from api.models.enums import AbsenceAction, FieldState, Framework, UnknownReason, Verdict
from api.models.field import Field
from api.models.finding import Finding, FindingProvenance, ObservedValue
from api.models.rule import ComplianceRule, Rulepack

ENGINE_VERSION = "0.1.0"
"""The evaluator's own version, recorded on every finding.

Kept in step with the package version in `pyproject.toml`. It exists so a verdict
is reproducible: knowing which rules ran is not enough if the code that ran them
has changed.
"""


def new_audit_id() -> str:
    """One identifier per evaluation run.

    Also the subject of the run's `AUDIT_RUN` chain entry, so the audit log and
    the findings it describes share one key rather than being correlated by
    timestamp.
    """
    return uuid.uuid4().hex


def evaluate_device(
    csm: CanonicalSecurityModel,
    rulepack: Rulepack,
    *,
    audit_id: str,
    evaluated_at: datetime | None = None,
    frameworks: frozenset[Framework] | None = None,
) -> tuple[Finding, ...]:
    """Every applicable rule, against one device, in rulepack order.

    Deterministic: same model and same rulepack in, identical findings out,
    including their order. A report that reshuffles between runs cannot be
    diffed, and an audit trail that cannot be diffed is much less useful than it
    looks.

    `frameworks` scopes the audit to user-selected benchmarks. A rule mapping to
    none of them produces **no finding**, the same way a rule that does not
    apply to the platform produces none: out of scope and undetermined are
    different answers, and only the second belongs in a queue.

    The engine does not decide whether a framework may be selected. That is
    `comply.frameworks.resolve_selection`, which refuses one with no sourced
    catalog — so an empty selection here always means "no filter" and never
    "a benchmark we cannot evaluate".
    """
    when = evaluated_at or datetime.now(UTC)
    applicable = rulepack.applicable_to(
        csm.device.vendor, csm.device.os_family, frameworks=frameworks
    )

    return tuple(
        _evaluate_rule(rule, csm, rulepack, audit_id=audit_id, evaluated_at=when)
        for rule in applicable
    )


def _evaluate_rule(
    rule: ComplianceRule,
    csm: CanonicalSecurityModel,
    rulepack: Rulepack,
    *,
    audit_id: str,
    evaluated_at: datetime,
) -> Finding:
    field = csm.get(rule.check.field)

    if field is None:
        # The pack never declared this control, so nothing was even attempted.
        # Distinct from "the directive is absent", which P5 already resolved.
        return _abstain(
            rule, csm, rulepack, UnknownReason.NO_MATCH, audit_id, evaluated_at, observed=None
        )

    if field.state is FieldState.PRESENT:
        return _from_condition(rule, csm, rulepack, field, audit_id, evaluated_at)

    action = _action_for(rule, field.state)

    if action is AbsenceAction.EVALUATE:
        return _from_condition(rule, csm, rulepack, field, audit_id, evaluated_at)
    if action is AbsenceAction.NOT_APPLICABLE:
        return _finding(rule, csm, rulepack, field, Verdict.NOT_APPLICABLE, audit_id, evaluated_at)
    if action in (AbsenceAction.PASS, AbsenceAction.FAIL):
        verdict = Verdict.PASS if action is AbsenceAction.PASS else Verdict.FAIL
        return _finding(rule, csm, rulepack, field, verdict, audit_id, evaluated_at)

    return _abstain(
        rule,
        csm,
        rulepack,
        field.unknown_reason or UnknownReason.CAPABILITY_UNKNOWN,
        audit_id,
        evaluated_at,
        observed=field,
    )


def _action_for(rule: ComplianceRule, state: FieldState) -> AbsenceAction:
    """Which branch of the rule's absence policy applies to this state.

    `on_capability_unknown` is not consulted as a free choice: the contract
    restricts it to UNKNOWN (DEF-4), so an undocumented capability abstains
    whatever a rulepack author intended.
    """
    policy = rule.absence_policy
    if state is FieldState.ABSENT_DEFAULT:
        return policy.on_absent_default
    if state is FieldState.ABSENT_UNSUPPORTED:
        return policy.on_absent_unsupported
    return policy.on_capability_unknown


def _from_condition(
    rule: ComplianceRule,
    csm: CanonicalSecurityModel,
    rulepack: Rulepack,
    field: Field[Any],
    audit_id: str,
    evaluated_at: datetime,
) -> Finding:
    """Run the condition, and refuse to answer if it cannot be run."""
    outcome = evaluate_all(rule.check.conditions, field.value)

    if outcome is None:
        # The rule is wrong, not the device. Its own reason so it cannot be
        # mistaken for a control the vendor packs are unable to read.
        return _abstain(
            rule,
            csm,
            rulepack,
            UnknownReason.RULE_TYPE_MISMATCH,
            audit_id,
            evaluated_at,
            observed=field,
        )

    verdict = Verdict.PASS if outcome else Verdict.FAIL

    if not field.evidence and not field.default_ref:
        # Rule 2, checked here as well as in the contract. A verdict with nothing
        # behind it is the one output this system must never produce.
        return _abstain(
            rule, csm, rulepack, UnknownReason.NO_EVIDENCE, audit_id, evaluated_at, observed=field
        )

    return _finding(rule, csm, rulepack, field, verdict, audit_id, evaluated_at)


def _finding(
    rule: ComplianceRule,
    csm: CanonicalSecurityModel,
    rulepack: Rulepack,
    field: Field[Any],
    verdict: Verdict,
    audit_id: str,
    evaluated_at: datetime,
) -> Finding:
    return Finding(
        finding_id=_finding_id(audit_id, csm.device.device_id, rule.rule_id),
        audit_id=audit_id,
        device_id=csm.device.device_id,
        rule_id=rule.rule_id,
        status=verdict,
        base_severity=rule.severity,
        observed=_observed(field),
        expected=describe_all(rule.check.conditions),
        evidence=field.evidence,
        # Copied from what P5 resolved, never composed here: the engine does not
        # author citations, it carries them.
        absence_reason=field.default_ref,
        frameworks=rule.frameworks,
        # Always None, and not because P8 is unfinished (decision D26).
        # `comply` may not import `remediate` — a verdict is decided before
        # anything is proposed to fix it — so the engine has no way to resolve a
        # snippet and must not acquire one. Remediation is resolved downstream,
        # in `api/report/` and at the API edge, against a library whose version
        # the report then records.
        remediation=None,
        provenance=_provenance(csm, rulepack, evaluated_at),
    )


def _abstain(
    rule: ComplianceRule,
    csm: CanonicalSecurityModel,
    rulepack: Rulepack,
    reason: UnknownReason,
    audit_id: str,
    evaluated_at: datetime,
    *,
    observed: Field[Any] | None,
) -> Finding:
    """An UNKNOWN finding — a result that travels with its reason, not a gap."""
    return Finding(
        finding_id=_finding_id(audit_id, csm.device.device_id, rule.rule_id),
        audit_id=audit_id,
        device_id=csm.device.device_id,
        rule_id=rule.rule_id,
        status=Verdict.UNKNOWN,
        base_severity=rule.severity,
        observed=_observed(observed),
        expected=describe_all(rule.check.conditions),
        # Citations are kept even when abstaining: a conflicting-evidence field
        # carries the very lines an operator needs in order to see the conflict.
        evidence=observed.evidence if observed is not None else (),
        unknown_reason=reason,
        frameworks=rule.frameworks,
        provenance=_provenance(csm, rulepack, evaluated_at),
    )


def _observed(field: Field[Any] | None) -> ObservedValue:
    """What the canonical model actually held, including when it held nothing."""
    if field is None:
        from api.models.enums import ConfidenceMethod

        return ObservedValue(
            value=None,
            state=FieldState.UNKNOWN,
            confidence=0.0,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )
    return ObservedValue(
        value=field.value,
        state=field.state,
        confidence=field.confidence,
        confidence_method=field.confidence_method,
    )


def _provenance(
    csm: CanonicalSecurityModel, rulepack: Rulepack, evaluated_at: datetime
) -> FindingProvenance:
    """Which code and which data produced this verdict.

    `pack_versions` comes from the CSM rather than from whichever pack is active
    now, so a finding says which pack version actually read the line.
    """
    return FindingProvenance(
        engine_version=ENGINE_VERSION,
        rulepack_version=rulepack.version,
        pack_versions=dict(csm.source.pack_versions),
        evaluated_at=evaluated_at,
    )


def _finding_id(audit_id: str, device_id: str, rule_id: str) -> str:
    """Deterministic within a run, so re-evaluating produces the same ids."""
    return f"{audit_id}:{device_id}:{rule_id}"
