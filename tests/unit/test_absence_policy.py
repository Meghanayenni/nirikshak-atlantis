"""`on_capability_unknown` cannot be configured away (DEF-4 regression).

Until P6, `AbsencePolicy` *claimed* in its docstring that abstention on an
undocumented capability was "deliberately not overridable to PASS or FAIL by
accident". Nothing enforced it. A rulepack could set
`on_capability_unknown: pass` and the model accepted it.

That mattered more than it looked. No platform defaults ship, so
`capability_unknown` is the reason behind **every** absent field on **every**
corpus device — one line of YAML would have turned that entire surface into
passes.

The `Finding` contract would have refused the resulting verdict for lack of
evidence, so the failure mode was a crash rather than a false PASS. But that is
containment in the wrong place: a mid-audit validation error thrown from a
different contract, naming no rule. A guarantee documented in one place and
enforced three layers away is not a guarantee.

It is now checked at load, which is where a rulepack author will meet it.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.comply.errors import RulepackLoadError
from api.comply.rulepacks import load_rule
from api.models.enums import AbsenceAction
from api.models.rule import AbsencePolicy

REJECTED = [
    AbsenceAction.PASS,
    AbsenceAction.FAIL,
    AbsenceAction.NOT_APPLICABLE,
    AbsenceAction.EVALUATE,
]


@pytest.mark.parametrize("action", REJECTED, ids=lambda a: a.value)
def test_capability_unknown_rejects_every_other_action(action: AbsenceAction) -> None:
    with pytest.raises(ValidationError, match="on_capability_unknown may only be"):
        AbsencePolicy(on_capability_unknown=action)


def test_capability_unknown_plus_pass_is_rejected() -> None:
    """The dangerous one, named explicitly."""
    with pytest.raises(ValidationError, match="on_capability_unknown may only be"):
        AbsencePolicy(on_capability_unknown=AbsenceAction.PASS)


def test_capability_unknown_plus_fail_is_rejected() -> None:
    """FAIL is not the safe direction either — it is a claim without evidence."""
    with pytest.raises(ValidationError, match="on_capability_unknown may only be"):
        AbsencePolicy(on_capability_unknown=AbsenceAction.FAIL)


def test_capability_unknown_plus_unknown_is_accepted() -> None:
    policy = AbsencePolicy(on_capability_unknown=AbsenceAction.UNKNOWN)

    assert policy.on_capability_unknown is AbsenceAction.UNKNOWN


def test_not_applicable_is_rejected_too() -> None:
    """NOT_APPLICABLE asserts the control does not apply to this platform.

    Not knowing whether a platform supports a control is precisely not knowing
    that, so it is a different claim, not a softer one.
    """
    with pytest.raises(ValidationError, match="on_capability_unknown may only be"):
        AbsencePolicy(on_capability_unknown=AbsenceAction.NOT_APPLICABLE)


def test_the_default_is_already_correct() -> None:
    assert AbsencePolicy().on_capability_unknown is AbsenceAction.UNKNOWN


def test_the_other_two_branches_remain_configurable() -> None:
    """The fix is narrow. A documented default or capability may still decide."""
    policy = AbsencePolicy(
        on_absent_default=AbsenceAction.FAIL,
        on_absent_unsupported=AbsenceAction.PASS,
    )

    assert policy.on_absent_default is AbsenceAction.FAIL
    assert policy.on_absent_unsupported is AbsenceAction.PASS


# ---------------------------------------------------------------------------
# An invalid rulepack cannot enter evaluation
# ---------------------------------------------------------------------------


def test_a_rule_file_setting_it_fails_to_load(tmp_path) -> None:
    """Rejected at load, naming the file — not mid-audit from another contract."""
    path = tmp_path / "bad.yaml"
    path.write_text(
        "rule_id: NRK-BAD-001\n"
        "title: Undocumented capability treated as compliant\n"
        "severity: high\n"
        "rationale: A rule that should not be loadable.\n"
        "check:\n"
        "  field: ssh_version\n"
        "  condition: { op: equals, value: 2 }\n"
        "absence_policy:\n"
        "  on_capability_unknown: pass\n",
        encoding="utf-8",
    )

    with pytest.raises(RulepackLoadError, match="on_capability_unknown may only be"):
        load_rule(path)


def test_the_shipped_rules_all_abstain_on_unknown_capability() -> None:
    from api.comply.rulepacks import load_rulepack

    pack = load_rulepack()

    assert pack.rules, "guard against this passing because no rules shipped"
    assert all(r.absence_policy.on_capability_unknown is AbsenceAction.UNKNOWN for r in pack.rules)
