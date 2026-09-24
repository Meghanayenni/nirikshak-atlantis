"""Collection-time refusal to run a suite containing a shadowed test.

Two functions with one name in one module is not an error in Python. The second
definition replaces the first, the first stops existing before pytest ever sees
it, and the suite reports one test where two were written. It happened here:
`test_a_term_cites_every_line_that_built_it` was defined twice in
`test_junos_filter_extraction.py` and the flat-form one silently stopped running
(ADR 0047). Ruff caught it by luck of configuration; pytest collected it
happily.

**In a project whose entire argument rests on its test suite, a test that
silently stops running is the worst class of defect available.** Every other
failure this repository guards against is a wrong answer. This one is a question
nobody asks any more, with nothing to show it was ever asked.

The check has to read the source rather than the collected items, because by
collection time the shadowed function no longer exists — Python discarded it at
import. So it parses each collected module's AST and refuses the run.

It aborts rather than failing one test, deliberately. A suite that cannot say
how many of its assertions ran should not report a result.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

import pytest


def _definitions(body: Iterable[ast.stmt]) -> list[str]:
    """Test function names defined directly in one body (module or class)."""
    return [
        node.name
        for node in body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("test_")
    ]


def duplicate_test_names(path: Path) -> list[str]:
    """Names defined more than once in one scope of this module.

    Scopes are checked separately: two `test_x` in different classes shadow
    nothing, and flagging them would train people to ignore this. Module level
    and each class body are their own namespace, which is exactly where the
    replacement happens.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):  # pragma: no cover - collection would fail first
        return []

    scopes: list[tuple[str, list[str]]] = [("module", _definitions(tree.body))]
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            scopes.append((node.name, _definitions(node.body)))

    duplicates: list[str] = []
    for scope, names in scopes:
        seen: set[str] = set()
        for name in names:
            if name in seen:
                where = "" if scope == "module" else f" in class {scope}"
                duplicates.append(f"{name}{where}")
            seen.add(name)
    return duplicates


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Refuse the run if any collected module defines a test name twice."""
    offenders: list[str] = []
    for path in sorted({Path(str(item.fspath)) for item in items}):
        for name in duplicate_test_names(path):
            offenders.append(f"  {path.name}::{name}")

    if offenders:
        raise pytest.UsageError(
            "a test name is defined twice in one module, so the first definition "
            "was replaced and never ran:\n"
            + "\n".join(offenders)
            + "\n\nRename one of them. A test that silently stops running is the "
            "one defect this suite cannot report on itself."
        )
