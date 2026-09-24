"""Every skip guard is paired, or is written down as deliberately unpaired.

**A test that skips is a test that does not test.** ADR 0041 recorded what that
costs: `skipif(availability().available)` on four PDF tests meant that on a
machine with GTK installed — this one — the PDF endpoint was exercised by
nothing at all, while three documents said the capability was blocked. The suite
stayed green for ten phases.

The same audit found two more (ADR 0042): `embed()` produced 384-dimension
vectors that no test asserted, and the training queue ranked suggestions that no
test asserted, both because the only tests touching them covered the *refusal*
and skipped wherever the thing worked.

So the rule this module enforces is:

  **For every `skipif(C)` in a test module, that module also contains a
  `skipif(not C)`** — the two together covering both states of whatever `C`
  probes — **or the pair is listed in `PAIRED_BY_HAND` with the reason.**

And, because an inline `pytest.skip()` cannot be paired structurally:

  **Every `pytest.skip()` call site is listed in `INLINE_SKIPS` with a
  reason.** A new one fails this test until somebody writes down why it is
  acceptable, which is the whole mechanism: the registry is a checklist that
  cannot drift, because drifting breaks the build.

This does not assert that the reasons are *good*. It asserts that somebody had
to write one down, beside the guard, in a file a reviewer reads.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS_ROOT = Path(__file__).resolve().parent.parent


PAIRED_BY_HAND: dict[tuple[str, str], str] = {
    (
        "test_training_api.py",
        "not model_availability().available",
    ): (
        "The counterpart is an inline skip inside "
        "test_an_unavailable_model_is_never_an_empty_suggestion_list, which walks "
        "the queue looking for a model_unavailable entry and skips when the model "
        "works. It cannot be a decorator because the condition is a property of "
        "the response, not of the environment."
    ),
}
"""`skipif` conditions whose opposite state is covered some other way."""


INLINE_SKIPS: dict[str, str] = {
    "test_eval_boundaries.py::test_the_label_side_cannot_reach_the_pipeline": (
        "Defensive only: skips if a parametrised eval module is missing, and every "
        "one is expected to exist. It does not skip on any checkout, so the "
        "assertion below it runs."
    ),
    "test_no_device_libraries.py::test_device_library_not_installed": (
        "`telnetlib` is standard library up to Python 3.12, so absence cannot be "
        "asserted. It is covered instead by test_no_device_library_imported_in_api, "
        "which runs unconditionally, and by test_detector_actually_fires, which "
        "proves that scan rejects a known-bad sample."
    ),
    "test_train_boundaries.py::test_no_trained_pack_quotes_an_evaluation_or_holdout_line": (
        "`packs/trained/` is gitignored deployment state (D45), so this scan skips "
        "on every checkout and on CI. The detection it performs is exercised by "
        "tests/integration/test_contamination_guard.py, which drives the real "
        "training loop to write a pack carrying the DEF-16 line and asserts the "
        "scan catches it, and which checks the live directory without skipping."
    ),
    "test_training_api.py::test_an_unavailable_model_is_never_an_empty_suggestion_list": (
        "Skips where the embedding model is installed. The ranked path it cannot "
        "reach is covered by test_a_present_model_actually_ranks_something, which "
        "skips in the opposite direction."
    ),
}
"""Inline `pytest.skip()` call sites, and why each is acceptable."""


def _test_modules() -> list[Path]:
    return sorted(p for p in TESTS_ROOT.rglob("test_*.py") if "__pycache__" not in p.parts)


def _skipif_conditions(tree: ast.AST) -> list[str]:
    """Source text of every `@pytest.mark.skipif(...)` condition in a module."""
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not decorator.args:
                continue
            target = decorator.func
            if isinstance(target, ast.Attribute) and target.attr == "skipif":
                found.append(ast.unparse(decorator.args[0]))
    return found


def _inline_skip_sites(tree: ast.AST) -> list[str]:
    """Names of functions containing a `pytest.skip(...)` call."""
    sites: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for inner in ast.walk(node):
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "skip"
                and isinstance(inner.func.value, ast.Name)
                and inner.func.value.id == "pytest"
            ):
                sites.append(node.name)
                break
    return sites


def _negate(condition: str) -> str:
    inner = condition.removeprefix("not ").strip()
    return inner if condition.startswith("not ") else f"not {condition}"


# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", _test_modules(), ids=lambda p: p.name)
def test_every_skipif_has_its_opposite(module: Path) -> None:
    """Both states of whatever the guard probes are covered somewhere."""
    tree = ast.parse(module.read_text(encoding="utf-8"))
    conditions = _skipif_conditions(tree)
    if not conditions:
        return

    present = set(conditions)
    unpaired = [
        condition
        for condition in sorted(present)
        if _negate(condition) not in present and (module.name, condition) not in PAIRED_BY_HAND
    ]

    assert unpaired == [], (
        f"{module.name} skips on a condition whose opposite nothing covers: {unpaired}.\n"
        "Add a test carrying the negated condition, or record the pair in "
        "PAIRED_BY_HAND with the reason. A capability exercised only when it is "
        "broken is a capability nothing tests (ADR 0041)."
    )


@pytest.mark.parametrize("module", _test_modules(), ids=lambda p: p.name)
def test_every_inline_skip_is_recorded(module: Path) -> None:
    """A new `pytest.skip()` fails here until its reason is written down."""
    tree = ast.parse(module.read_text(encoding="utf-8"))

    unrecorded = [
        f"{module.name}::{name}"
        for name in _inline_skip_sites(tree)
        if f"{module.name}::{name}" not in INLINE_SKIPS
    ]

    assert unrecorded == [], (
        f"inline pytest.skip() with no recorded justification: {unrecorded}.\n"
        "Add an entry to INLINE_SKIPS saying what covers the path this skips."
    )


def test_the_registries_describe_guards_that_still_exist() -> None:
    """The other direction: an entry outliving its guard is stale documentation.

    Without this, deleting a skip would leave a justification behind explaining
    a guard nobody can find — which is how the defect register went stale
    (ADR 0046) and how three documents kept saying PDF was blocked.
    """
    live_inline: set[str] = set()
    live_pairs: set[tuple[str, str]] = set()

    for module in _test_modules():
        tree = ast.parse(module.read_text(encoding="utf-8"))
        live_inline |= {f"{module.name}::{name}" for name in _inline_skip_sites(tree)}
        live_pairs |= {(module.name, c) for c in _skipif_conditions(tree)}

    assert set(INLINE_SKIPS) - live_inline == set(), (
        f"INLINE_SKIPS describes skips that no longer exist: {set(INLINE_SKIPS) - live_inline}"
    )
    assert set(PAIRED_BY_HAND) - live_pairs == set(), (
        f"PAIRED_BY_HAND describes guards that no longer exist: {set(PAIRED_BY_HAND) - live_pairs}"
    )


def test_every_recorded_reason_says_something() -> None:
    """A registry of empty strings would satisfy the tests above and nothing else."""
    for key, reason in {
        **INLINE_SKIPS,
        **{f"{m}:{c}": r for (m, c), r in PAIRED_BY_HAND.items()},
    }.items():
        assert len(reason.split()) >= 12, f"{key} is recorded without an explanation"


# ---------------------------------------------------------------------------
# The detector must be able to fail
# ---------------------------------------------------------------------------


UNPAIRED_SAMPLE = """
import pytest

@pytest.mark.skipif(probe().available, reason="skips where it works")
def test_only_the_refusal() -> None:
    assert True
"""

PAIRED_SAMPLE = """
import pytest

@pytest.mark.skipif(probe().available, reason="skips where it works")
def test_the_refusal() -> None:
    assert True

@pytest.mark.skipif(not probe().available, reason="skips where it does not")
def test_the_happy_path() -> None:
    assert True
"""

INLINE_SAMPLE = """
import pytest

def test_bails_out() -> None:
    if True:
        pytest.skip("no reason recorded anywhere")
"""


def test_the_pairing_detector_actually_fires() -> None:
    """A guardrail that cannot fail is not a guardrail.

    Without this, `test_every_skipif_has_its_opposite` would pass just as
    happily if `_skipif_conditions` returned nothing — which is precisely the
    failure mode it exists to catch, one level up.
    """
    unpaired = _skipif_conditions(ast.parse(UNPAIRED_SAMPLE))
    assert unpaired == ["probe().available"]
    assert _negate(unpaired[0]) not in unpaired, "the detector would miss an unpaired guard"

    paired = _skipif_conditions(ast.parse(PAIRED_SAMPLE))
    assert set(paired) == {"probe().available", "not probe().available"}
    assert all(_negate(c) in set(paired) for c in paired), "a paired module must pass"


def test_the_inline_detector_actually_fires() -> None:
    assert _inline_skip_sites(ast.parse(INLINE_SAMPLE)) == ["test_bails_out"]
    assert _inline_skip_sites(ast.parse(PAIRED_SAMPLE)) == []


def test_negation_round_trips() -> None:
    """`not not C` would never match anything, so the helper must not produce it."""
    assert _negate("x.available") == "not x.available"
    assert _negate("not x.available") == "x.available"
    assert _negate(_negate("x.available")) == "x.available"
