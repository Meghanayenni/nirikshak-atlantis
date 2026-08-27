"""The twelve condition operators, and what they refuse to answer (D18).

Two properties carry the whole module.

**A type mismatch abstains.** `evaluate` returns `None`, never `False`. `False`
would be a FAIL — a claim about a device made because a *rule* was wrong, which
an operator would then spend time on.

**Booleans are not numbers.** In Python `True == 1` and `isinstance(True, int)`,
so a boolean field compared with `gt: 0` would silently succeed. Every ordered
and equality operator here excludes booleans explicitly.
"""

from __future__ import annotations

import pytest

from api.comply.conditions import describe, evaluate, self_check
from api.models.enums import ConditionOp
from api.models.rule import Condition


def cond(op: ConditionOp, value: object = None) -> Condition:
    return Condition(op=op, value=value)


# ---------------------------------------------------------------------------
# Every operator, matching and non-matching
# ---------------------------------------------------------------------------

MATCHES = [
    (ConditionOp.EQUALS, 2, 2),
    (ConditionOp.NOT_EQUALS, 3, 2),
    (ConditionOp.GT, 10, 5),
    (ConditionOp.GTE, 5, 5),
    (ConditionOp.LT, 3, 5),
    (ConditionOp.LTE, 5, 5),
    (ConditionOp.IN, "ssh", ["ssh", "https"]),
    (ConditionOp.NOT_IN, "telnet", ["ssh", "https"]),
    (ConditionOp.CONTAINS, ["192.0.2.10"], "192.0.2.10"),
    (ConditionOp.IS_TRUE, True, None),
    (ConditionOp.IS_FALSE, False, None),
    (ConditionOp.NON_EMPTY, ["a"], None),
]

NON_MATCHES = [
    (ConditionOp.EQUALS, 1, 2),
    (ConditionOp.NOT_EQUALS, 2, 2),
    (ConditionOp.GT, 5, 10),
    (ConditionOp.GTE, 4, 5),
    (ConditionOp.LT, 5, 3),
    (ConditionOp.LTE, 6, 5),
    (ConditionOp.IN, "telnet", ["ssh", "https"]),
    (ConditionOp.NOT_IN, "ssh", ["ssh", "https"]),
    (ConditionOp.CONTAINS, ["192.0.2.10"], "192.0.2.99"),
    (ConditionOp.IS_TRUE, False, None),
    (ConditionOp.IS_FALSE, True, None),
    (ConditionOp.NON_EMPTY, [], None),
]


@pytest.mark.parametrize("op,value,operand", MATCHES, ids=lambda p: getattr(p, "value", str(p)))
def test_operator_matches(op: ConditionOp, value: object, operand: object) -> None:
    assert evaluate(cond(op, operand), value) is True


@pytest.mark.parametrize("op,value,operand", NON_MATCHES, ids=lambda p: getattr(p, "value", str(p)))
def test_operator_does_not_match(op: ConditionOp, value: object, operand: object) -> None:
    assert evaluate(cond(op, operand), value) is False


def test_every_operator_is_covered() -> None:
    """Guard against an operator being added and silently left untested."""
    covered = {op for op, _, _ in MATCHES} | {op for op, _, _ in NON_MATCHES}
    assert covered == set(ConditionOp)


# ---------------------------------------------------------------------------
# Boundaries
# ---------------------------------------------------------------------------


def test_lte_at_exactly_the_limit_passes() -> None:
    """The corpus lands on this: rtr-core-01's timeout is exactly 600."""
    assert evaluate(cond(ConditionOp.LTE, 600), 600) is True


def test_gte_at_exactly_the_limit_passes() -> None:
    assert evaluate(cond(ConditionOp.GTE, 600), 600) is True


def test_lt_at_exactly_the_limit_fails() -> None:
    assert evaluate(cond(ConditionOp.LT, 600), 600) is False


def test_non_empty_on_an_empty_string() -> None:
    assert evaluate(cond(ConditionOp.NON_EMPTY), "") is False


def test_contains_works_on_a_string_as_substring() -> None:
    assert evaluate(cond(ConditionOp.CONTAINS, "ssh"), "transport input ssh") is True


# ---------------------------------------------------------------------------
# Type mismatch abstains — never False
# ---------------------------------------------------------------------------

MISMATCHES = [
    ("quoted number against an int field", ConditionOp.LTE, 600, "600"),
    ("ordered op on a string", ConditionOp.GT, "abc", 5),
    ("ordered op on a list", ConditionOp.LT, ["a"], 5),
    ("equality across types", ConditionOp.EQUALS, 2, "2"),
    ("equality bool vs int", ConditionOp.EQUALS, True, 1),
    ("is_true on a non-boolean", ConditionOp.IS_TRUE, 1, None),
    ("is_false on a non-boolean", ConditionOp.IS_FALSE, 0, None),
    ("non_empty on a number", ConditionOp.NON_EMPTY, 5, None),
    ("contains on a boolean", ConditionOp.CONTAINS, True, "x"),
    ("contains on a number", ConditionOp.CONTAINS, 5, 5),
    ("in with a list-valued field", ConditionOp.IN, ["a"], ["a", "b"]),
]


@pytest.mark.parametrize("label,op,value,operand", MISMATCHES, ids=[m[0] for m in MISMATCHES])
def test_type_mismatch_abstains(
    label: str, op: ConditionOp, value: object, operand: object
) -> None:
    assert evaluate(cond(op, operand), value) is None, (
        f"{label}: returned a verdict for a comparison that has no meaning"
    )


@pytest.mark.parametrize("label,op,value,operand", MISMATCHES, ids=[m[0] for m in MISMATCHES])
def test_type_mismatch_is_never_false(
    label: str, op: ConditionOp, value: object, operand: object
) -> None:
    """The tempting mistake: FAIL feels safe for a security tool. It is not.

    A FAIL is a claim about a device. Producing one because the rule quoted its
    number sends an operator to investigate a device that is fine.
    """
    assert evaluate(cond(op, operand), value) is not False


def test_a_boolean_field_is_not_compared_as_a_number() -> None:
    """`isinstance(True, int)` is True, so this must be excluded deliberately."""
    assert evaluate(cond(ConditionOp.GT, 0), True) is None
    assert evaluate(cond(ConditionOp.GTE, 1), True) is None


def test_a_missing_value_abstains() -> None:
    assert evaluate(cond(ConditionOp.EQUALS, 2), None) is None
    assert evaluate(cond(ConditionOp.IS_TRUE), None) is None
    assert evaluate(cond(ConditionOp.NON_EMPTY), None) is None


# ---------------------------------------------------------------------------
# Self-check — the authoring-time half of D18
# ---------------------------------------------------------------------------


def test_a_usable_condition_self_checks_clean() -> None:
    assert self_check(cond(ConditionOp.LTE, 600)) == []
    assert self_check(cond(ConditionOp.IS_TRUE)) == []


def test_a_condition_that_can_never_evaluate_is_caught() -> None:
    """`lte: "600"` compares against nothing: no value shape can satisfy it."""
    failures = self_check(cond(ConditionOp.LTE, "600"))

    assert failures
    assert "abstain on every device" in failures[0]


# ---------------------------------------------------------------------------
# Rendering the expectation
# ---------------------------------------------------------------------------


def test_expected_text_is_rendered_from_the_rule() -> None:
    """So a report cannot describe an expectation the engine did not apply."""
    assert describe(cond(ConditionOp.IS_FALSE)) == "disabled"
    assert describe(cond(ConditionOp.IS_TRUE)) == "enabled"
    assert describe(cond(ConditionOp.NON_EMPTY)) == "at least one value configured"
    assert describe(cond(ConditionOp.LTE, 600)) == "lte 600"
