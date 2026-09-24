"""No test in this suite is shadowed by a later definition of its own name.

The collection hook in `tests/conftest.py` aborts a run that contains one. This
module is the readable, individually-runnable counterpart, plus the cross-module
survey the hook deliberately does not perform.

Both exist because the hook fails the *session* and a session failure names the
problem once, at the top, before anything else runs — useful, and not a place a
reviewer goes looking for the state of the suite.
"""

from __future__ import annotations

import ast
import collections
from pathlib import Path

import pytest

from tests.conftest import duplicate_test_names

TESTS_ROOT = Path(__file__).resolve().parent.parent


def _modules() -> list[Path]:
    """Named with a leading underscore on purpose.

    `test_modules` would be collected as a test by pytest and reported as
    returning a list instead of None — a helper masquerading as an
    assertion, which is a mild version of the thing this module guards.
    """
    return sorted(p for p in TESTS_ROOT.rglob("test_*.py") if "__pycache__" not in p.parts)


@pytest.mark.parametrize("module", _modules(), ids=lambda p: p.name)
def test_no_module_defines_a_test_name_twice(module: Path) -> None:
    """The defect, per module, so a failure names the file without reading a list."""
    duplicates = duplicate_test_names(module)

    assert duplicates == [], (
        f"{module.name} defines {duplicates} more than once. The earlier definition "
        "was replaced at import and never ran."
    )


def test_duplicate_names_across_modules_are_inventoried() -> None:
    """Harmless, and worth knowing about.

    Two modules may each define `test_discovery_is_ordered`; Python namespaces
    them separately and both run. This is not a failure and is not treated as
    one — it is pinned so that the set is *looked at* rather than assumed empty,
    and so a reviewer reading a failure elsewhere knows these repeats exist.

    **Expected to change** when a test is added or renamed. Updating it is a
    one-line edit and a glance at whether the new pair is really two different
    questions.
    """
    across: dict[str, list[str]] = collections.defaultdict(list)
    for module in _modules():
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
                "test_"
            ):
                across[node.name].append(module.name)

    repeated = {name: sorted(files) for name, files in across.items() if len(files) > 1}

    assert repeated == {
        "test_discovery_is_ordered": ["test_rulepack_loading.py", "test_snippet_library.py"],
        "test_no_calibrator_is_active": ["test_calibration.py", "test_learn_boundaries.py"],
        "test_oversized_file_is_rejected": ["test_ingest_validate.py", "test_ingestion.py"],
        "test_unknown_requires_a_reason": [
            "test_field_confidence.py",
            "test_finding_snippet_training_audit.py",
        ],
    }, (
        "the set of names repeated across modules has changed. None of these shadow "
        "anything — update the expectation, and check the new pair asks two "
        "different questions rather than one twice."
    )


# ---------------------------------------------------------------------------
# The detector must be able to fail
# ---------------------------------------------------------------------------


SHADOWED = """
def test_one() -> None:
    assert True

def test_one() -> None:
    assert False
"""

SCOPED = """
class TestA:
    def test_same(self) -> None: ...

class TestB:
    def test_same(self) -> None: ...

def test_same() -> None: ...
"""

SHADOWED_IN_CLASS = """
class TestA:
    def test_same(self) -> None: ...
    def test_same(self) -> None: ...
"""


def _write(tmp_path: Path, name: str, source: str) -> Path:
    path = tmp_path / name
    path.write_text(source, encoding="utf-8")
    return path


def test_the_detector_actually_fires(tmp_path: Path) -> None:
    """Without this, the parametrised test above would pass just as happily if
    `duplicate_test_names` always returned an empty list — which is the failure
    mode it exists to catch, one level up.
    """
    assert duplicate_test_names(_write(tmp_path, "test_dupe.py", SHADOWED)) == ["test_one"]


def test_the_same_name_in_different_scopes_is_not_shadowing(tmp_path: Path) -> None:
    """Three `test_same`, three namespaces, nothing replaced.

    Flagging these would be the guard crying wolf, and a guard people learn to
    ignore protects nothing.
    """
    assert duplicate_test_names(_write(tmp_path, "test_scoped.py", SCOPED)) == []


def test_shadowing_inside_a_class_is_caught(tmp_path: Path) -> None:
    """A class body is a namespace too, and the replacement is just as silent."""
    found = duplicate_test_names(_write(tmp_path, "test_cls.py", SHADOWED_IN_CLASS))

    assert found == ["test_same in class TestA"]


def test_a_module_that_cannot_be_parsed_is_not_reported_as_clean(tmp_path: Path) -> None:
    """A syntax error returns no duplicates, and that is safe here.

    Collection fails on the import long before this hook runs, so the run never
    reaches a point where an unparseable module could be mistaken for a clean
    one. Asserted so the swallowed exception is a decision rather than an
    oversight.
    """
    broken = _write(tmp_path, "test_broken.py", "def test_x(:\n")

    assert duplicate_test_names(broken) == []
