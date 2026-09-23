"""A check may bound a value at both ends — DEF-8.

`NRK-TIMEOUT-001` asked for `lte: 600` and therefore passed `exec-timeout 0 0`,
a management session that never expires. Zero satisfies "at most ten minutes"
numerically, so the least secure setting the platform offers was reported as
compliant. The correct check is *at most 600 **and** greater than zero*, and
`CheckSpec` examined one field with one operator from a closed set.

This module covers the contract change and the three-valued arithmetic beneath
it. The corpus device that demonstrates the defect is in
`tests/integration/test_cisco_compliance.py`.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.comply.conditions import describe_all, evaluate_all, self_check
from api.models.enums import ConditionOp
from api.models.rule import CheckSpec, Condition

GT_ZERO = Condition(op=ConditionOp.GT, value=0)
LTE_600 = Condition(op=ConditionOp.LTE, value=600)
BOUNDED = (GT_ZERO, LTE_600)


# ---------------------------------------------------------------------------
# The arithmetic
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, False),  # DEF-8 — never expires, and the old rule passed it
        (1, True),
        (300, True),
        (600, True),  # the bound is inclusive at the top
        (601, False),
        (1800, False),
        (-1, False),  # not expressible on a device; the rule still answers
    ],
)
def test_a_bounded_check_answers_at_both_ends(value: int, expected: bool) -> None:
    assert evaluate_all(BOUNDED, value) is expected


def test_an_unevaluable_conjunct_abstains_even_when_another_is_false() -> None:
    """`False and None` is False in Kleene logic. Here it must be None.

    A `None` outcome means *this comparison is not meaningful* — a defect in the
    rule, not uncertainty about the device. Returning FAIL would deliver a
    verdict while hiding an authoring error, and `rule_type_mismatch` exists
    precisely so a broken rule routes to whoever wrote it instead of vanishing
    into a coverage gap.
    """
    broken = (Condition(op=ConditionOp.LTE, value="600"), GT_ZERO)

    # lte against a string operand is unevaluable; gt 0 against 0 is plainly False.
    assert evaluate_all(broken, 0) is None
    assert evaluate_all((broken[0],), 0) is None
    assert evaluate_all((GT_ZERO,), 0) is False


def test_a_boolean_value_abstains_rather_than_comparing_as_an_integer() -> None:
    """`isinstance(True, int)` — the trap the ordered operators already guard."""
    assert evaluate_all(BOUNDED, True) is None


def test_the_expectation_names_every_condition_that_ran() -> None:
    """A rule that checked two things must not report one."""
    assert describe_all(BOUNDED) == "gt 0 and lte 600"
    assert describe_all((LTE_600,)) == "lte 600"


def test_the_rulepack_self_check_sees_every_condition() -> None:
    """A conjunction hiding one always-abstaining condition is still broken."""
    # An ordered operator with a string operand: no value shape can answer it.
    always_abstains = Condition(op=ConditionOp.GT, value="x")
    assert self_check(always_abstains)

    spec = CheckSpec(field="idle_timeout_seconds", all_of=(LTE_600, always_abstains))
    problems = [p for condition in spec.conditions for p in self_check(condition)]
    assert problems


# ---------------------------------------------------------------------------
# The contract
# ---------------------------------------------------------------------------


def test_either_form_yields_the_same_condition_sequence() -> None:
    """Consumers read `conditions` and never branch on how it was written."""
    single = CheckSpec(field="idle_timeout_seconds", condition=LTE_600)
    conjunction = CheckSpec(field="idle_timeout_seconds", all_of=BOUNDED)

    assert single.conditions == (LTE_600,)
    assert conjunction.conditions == BOUNDED


def test_a_check_declaring_neither_form_is_refused() -> None:
    with pytest.raises(ValidationError, match="either `condition` or `all_of`"):
        CheckSpec(field="idle_timeout_seconds")


def test_a_check_declaring_both_forms_is_refused() -> None:
    """Two sources for one expectation, and the engine would have to choose."""
    with pytest.raises(ValidationError, match="not both and not neither"):
        CheckSpec(field="idle_timeout_seconds", condition=LTE_600, all_of=BOUNDED)


def test_a_conjunction_of_one_is_refused() -> None:
    """One meaning, one spelling. Two spellings get diffed wrong."""
    with pytest.raises(ValidationError, match="write it as `condition` instead"):
        CheckSpec(field="idle_timeout_seconds", all_of=(LTE_600,))


def test_a_repeated_condition_is_refused() -> None:
    with pytest.raises(ValidationError, match="repeats the condition"):
        CheckSpec(field="idle_timeout_seconds", all_of=(LTE_600, GT_ZERO, LTE_600))


def test_a_collection_operand_does_not_break_duplicate_detection() -> None:
    """`in` takes a list, which is unhashable; the validator must survive it."""
    spec = CheckSpec(
        field="ssh_version",
        all_of=(
            Condition(op=ConditionOp.IN, value=[2]),
            Condition(op=ConditionOp.GTE, value=2),
        ),
    )
    assert len(spec.conditions) == 2


def test_disjunction_is_not_expressible() -> None:
    """The line between a conjunction and an expression language.

    Asserted rather than documented: `extra="forbid"` is what keeps someone from
    adding `any_of` to a YAML file and having it silently ignored.
    """
    with pytest.raises(ValidationError):
        CheckSpec(field="idle_timeout_seconds", any_of=BOUNDED)
