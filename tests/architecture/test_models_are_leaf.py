"""The contracts must remain a leaf package.

`api/models/` is imported by every other layer, including `api/comply/`. If the
contracts themselves imported the parsing or learning layers, the forbidden
import edges in test_import_rules.py could be satisfied on paper while being
violated transitively — `comply` would reach `parse` by way of `models`.

Keeping the contracts dependency-free at the project level closes that route,
and is also what lets the compliance engine accept a typed CSM without dragging
the parser into its process.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_ROOT = REPO_ROOT / "api" / "models"

FORBIDDEN_FOR_MODELS = [
    "api.parse",
    "api.learn",
    "api.comply",
    "api.remediate",
    "api.analyse",
    "api.ingest",
    "api.report",
    "api.routers",
    "api.db",
]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module)
    return found


def _model_sources() -> list[Path]:
    return sorted(MODELS_ROOT.rglob("*.py")) if MODELS_ROOT.is_dir() else []


@pytest.mark.parametrize("forbidden", FORBIDDEN_FOR_MODELS)
def test_models_do_not_import_other_layers(forbidden: str) -> None:
    violations: list[str] = []
    for source in _model_sources():
        for module in _imports(source):
            if module == forbidden or module.startswith(f"{forbidden}."):
                violations.append(f"{source.relative_to(REPO_ROOT)} imports {module}")

    assert not violations, (
        f"api/models/ must not import {forbidden} — the contracts are a leaf "
        "package, or the forbidden import edges become reachable transitively\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_models_package_is_populated() -> None:
    """Guard against the test above passing because the package is empty."""
    sources = [p for p in _model_sources() if p.name != "__init__.py"]
    assert len(sources) >= 10, f"expected the contract modules, found {len(sources)}"


def test_contracts_are_importable_without_side_effects() -> None:
    """Importing the contracts must not require config, database or network."""
    import api.models as models

    assert len(models.__all__) > 50
