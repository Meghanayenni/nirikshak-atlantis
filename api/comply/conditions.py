"""Evaluating one condition against one canonical value.

Twelve operators, a closed set. Not an expression language, and deliberately so:
an expression language is where vendor logic and model calls reappear inside a
layer that is supposed to have neither.

**Type mismatch abstains — it never guesses** (decision D18). A rule declaring
`lte: "600"` against an integer field, or `contains` against a boolean, cannot be
evaluated. Python would happily compare some of those pairs and raise on others,
and either outcome would be wrong here: a silent coercion invents an answer, and
an exception stops an audit over one bad rule. Both are answered the same way —
`None`, which the engine turns into UNKNOWN with `rule_type_mismatch`.

That reason is distinct from `no_match` on purpose. `no_match` means the vendor
packs cannot read this control, which routes to administrator training.
`rule_type_mismatch` means the packs read it fine and the *rule* is wrong, which
routes to whoever wrote the rule. Collapsing them would hide a broken rule inside
a legitimate coverage gap, where it would abstain on every device forever.

Booleans are handled before numbers throughout. In Python `True == 1` and
`isinstance(True, int)`, so a boolean field compared with `gt: 0` would otherwise
silently succeed — a comparison nobody meant to write.
"""

from __future__ import annotations

from typing import Any

from api.models.enums import ConditionOp
from api.models.rule import Condition

Outcome = bool | None
"""`True` / `False` are verdicts. `None` means the comparison is not meaningful —
never "false", which would convert an unanswerable question into a FAIL."""

ORDERED_OPS = frozenset({ConditionOp.GT, ConditionOp.GTE, ConditionOp.LT, ConditionOp.LTE})
COLLECTION_TYPES = (list, tuple, set, frozenset)


def evaluate(condition: Condition, value: Any) -> Outcome:
    """Apply one condition to one canonical field value."""
    handler = _HANDLERS[condition.op]
    return handler(value, condition.value)


# -- equality ---------------------------------------------------------------


def _equals(value: Any, operand: Any) -> Outcome:
    if not _comparable_for_equality(value, operand):
        return None
    return value == operand


def _not_equals(value: Any, operand: Any) -> Outcome:
    result = _equals(value, operand)
    return None if result is None else not result


def _comparable_for_equality(value: Any, operand: Any) -> bool:
    """Equality is only meaningful between values of the same kind.

    `2 == "2"` is False in Python, which would read as a FAIL — a device reported
    non-compliant because the rule quoted its number. That is a rule defect
    wearing a verdict, so it abstains instead.
    """
    if value is None:
        return False
    if _is_bool(value) or _is_bool(operand):
        return _is_bool(value) and _is_bool(operand)
    if _is_number(value):
        return _is_number(operand)
    if isinstance(value, str):
        return isinstance(operand, str)
    if isinstance(value, COLLECTION_TYPES):
        return isinstance(operand, COLLECTION_TYPES)
    return type(value) is type(operand)


# -- ordering ---------------------------------------------------------------


def _ordered(op: ConditionOp):
    def compare(value: Any, operand: Any) -> Outcome:
        # Booleans first: isinstance(True, int) is True, so `gt: 0` against a
        # boolean field would otherwise quietly evaluate.
        if _is_bool(value) or _is_bool(operand):
            return None
        if not (_is_number(value) and _is_number(operand)):
            return None
        if op is ConditionOp.GT:
            return value > operand
        if op is ConditionOp.GTE:
            return value >= operand
        if op is ConditionOp.LT:
            return value < operand
        return value <= operand

    return compare


# -- membership -------------------------------------------------------------


def _in(value: Any, operand: Any) -> Outcome:
    if value is None or not isinstance(operand, COLLECTION_TYPES):
        return None
    if isinstance(value, COLLECTION_TYPES):
        # "is this list one of those values" is not a question the operator asks.
        return None
    return value in operand


def _not_in(value: Any, operand: Any) -> Outcome:
    result = _in(value, operand)
    return None if result is None else not result


def _contains(value: Any, operand: Any) -> Outcome:
    """Does the field's value contain the operand?

    Meaningful for a collection field (does this list of servers include that
    address) and for a string field (substring). Not meaningful for a number or a
    boolean, which contain nothing.
    """
    if isinstance(value, COLLECTION_TYPES):
        return operand in value
    if isinstance(value, str):
        return isinstance(operand, str) and operand in value
    return None


# -- unary ------------------------------------------------------------------


def _is_true(value: Any, _: Any) -> Outcome:
    return value is True if _is_bool(value) else None


def _is_false(value: Any, _: Any) -> Outcome:
    return value is False if _is_bool(value) else None


def _non_empty(value: Any, _: Any) -> Outcome:
    """Does the field hold anything at all?

    Defined for collections and strings. A number is not empty or non-empty, and
    answering `True` for one would make `non_empty` mean "is present", which is
    what the field's *state* already says.
    """
    if isinstance(value, COLLECTION_TYPES) or isinstance(value, str):
        return len(value) > 0
    return None


# -- helpers ----------------------------------------------------------------


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


_HANDLERS = {
    ConditionOp.EQUALS: _equals,
    ConditionOp.NOT_EQUALS: _not_equals,
    ConditionOp.GT: _ordered(ConditionOp.GT),
    ConditionOp.GTE: _ordered(ConditionOp.GTE),
    ConditionOp.LT: _ordered(ConditionOp.LT),
    ConditionOp.LTE: _ordered(ConditionOp.LTE),
    ConditionOp.IN: _in,
    ConditionOp.NOT_IN: _not_in,
    ConditionOp.CONTAINS: _contains,
    ConditionOp.IS_TRUE: _is_true,
    ConditionOp.IS_FALSE: _is_false,
    ConditionOp.NON_EMPTY: _non_empty,
}


def describe(condition: Condition) -> str:
    """Human-readable expectation, for `Finding.expected`.

    Rendered from the rule rather than authored per rule, so a report cannot
    describe an expectation the engine did not actually apply.
    """
    if condition.op is ConditionOp.IS_TRUE:
        return "enabled"
    if condition.op is ConditionOp.IS_FALSE:
        return "disabled"
    if condition.op is ConditionOp.NON_EMPTY:
        return "at least one value configured"
    return f"{condition.op.value.replace('_', ' ')} {condition.value!r}"


SAMPLE_VALUES: dict[str, Any] = {
    "bool": True,
    "int": 1,
    "str": "x",
    "list": ["x"],
}
"""Representative values for the rulepack self-check (D18).

The check asks: is there *any* value shape this condition could evaluate
against? A condition that returns `None` for every one of these can never
produce a verdict on any device, which makes it an authoring error rather than a
coverage gap.
"""


def self_check(condition: Condition) -> list[str]:
    """Problems that would make this condition abstain on every possible value."""
    outcomes = {name: evaluate(condition, sample) for name, sample in SAMPLE_VALUES.items()}
    if all(result is None for result in outcomes.values()):
        return [
            f"operator {condition.op.value!r} with operand {condition.value!r} cannot be "
            "evaluated against any value shape; it would abstain on every device"
        ]
    return []
