"""Architecture guards for the ingestion layer.

Ingestion answers what a file is, what platform it belongs to, and what its
lines are. Three things it must not be able to do — reach the network, reach a
model, or reach a verdict — are asserted here rather than left to intent.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INGEST = REPO_ROOT / "api" / "ingest"
API = REPO_ROOT / "api"

NETWORK_MODULES = [
    "httpx",
    "requests",
    "urllib",
    "socket",
    "http",
    "ftplib",
    "smtplib",
    "aiohttp",
    "websockets",
]

FORBIDDEN_LAYERS = ["api.comply", "api.normalise", "api.learn", "api.remediate", "api.report"]


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


def _sources(root: Path) -> list[Path]:
    return sorted(root.rglob("*.py")) if root.is_dir() else []


def test_ingest_package_is_populated() -> None:
    """Guard against every test below passing because the package is empty."""
    modules = [p for p in _sources(INGEST) if p.name != "__init__.py"]
    assert len(modules) >= 8, f"expected the ingestion modules, found {len(modules)}"


@pytest.mark.parametrize("module", NETWORK_MODULES)
def test_ingest_has_no_network_capability(module: str) -> None:
    """Configurations cannot be sent anywhere, because there is nothing to send them with.

    Stronger than a policy: with no client in the package, "do not silently send
    configurations to external services" is not a rule anyone has to follow.
    """
    violations = [
        f"{path.relative_to(REPO_ROOT)} imports {imported}"
        for path in _sources(INGEST)
        for imported in _imports(path)
        if imported == module or imported.startswith(f"{module}.")
    ]
    assert not violations, "ingestion must have no outbound capability:\n" + "\n".join(violations)


@pytest.mark.parametrize("layer", FORBIDDEN_LAYERS)
def test_ingest_does_not_reach_downstream_layers(layer: str) -> None:
    """Ingestion does not parse security fields, normalise, or decide anything."""
    violations = [
        f"{path.relative_to(REPO_ROOT)} imports {imported}"
        for path in _sources(INGEST)
        for imported in _imports(path)
        if imported == layer or imported.startswith(f"{layer}.")
    ]
    assert not violations, f"api/ingest/ must not import {layer}:\n" + "\n".join(violations)


SPLITLINES_EXEMPT: dict[str, str] = {
    "api/audit/verify.py": "splits a pydantic exception message for display, not a config file",
    "api/db/migrate.py": "splits SQL migration text; produces no evidence line number",
}
"""Uses of `.splitlines()` that cannot affect a citation.

Each is exempt because the text it splits is not configuration and its line
numbers never reach a piece of evidence. Anything not listed here is a bug.
"""


def _splitlines_calls(path: Path) -> list[int]:
    """AST-detected `.splitlines()` calls — docstrings and comments do not count."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "splitlines"
    ]


def test_no_configuration_text_is_split_with_splitlines() -> None:
    """Finding F1, enforced repository-wide with justified exemptions.

    `str.splitlines()` splits on nine characters beyond CR/LF/CRLF — a vertical
    tab in a banner becomes an extra line. Anywhere that produces a line number
    an operator will read, that puts our citations out of step with their editor
    and nothing surfaces the error.
    """
    offenders: list[str] = []
    for path in _sources(API):
        rel = path.relative_to(REPO_ROOT).as_posix()
        calls = _splitlines_calls(path)
        if not calls or rel in SPLITLINES_EXEMPT:
            continue
        offenders.extend(f"{rel}:{line}" for line in calls)

    assert not offenders, (
        "use api.ingest.lines.split_lines instead — splitlines() disagrees with "
        "an editor's line numbering (F1). If the text is genuinely not a "
        "configuration, add it to SPLITLINES_EXEMPT with a reason:\n" + "\n".join(offenders)
    )


def test_splitlines_exemptions_are_real() -> None:
    """An exemption for a file that no longer uses splitlines is stale."""
    for rel in SPLITLINES_EXEMPT:
        path = REPO_ROOT / rel
        assert path.is_file(), f"exemption names a missing file: {rel}"
        assert _splitlines_calls(path), f"stale exemption — {rel} no longer calls splitlines()"


def test_line_splitting_module_does_not_use_splitlines() -> None:
    """The one module that must never make this mistake."""
    assert _splitlines_calls(INGEST / "lines.py") == []


def test_ingest_makes_no_compliance_decision() -> None:
    """No verdict vocabulary anywhere in the package."""
    forbidden = ("Verdict", "ComplianceRule", "Finding", "CanonicalSecurityModel")
    offenders: list[str] = []
    for path in _sources(INGEST):
        source = path.read_text(encoding="utf-8")
        for name in forbidden:
            if name in source:
                offenders.append(f"{path.relative_to(REPO_ROOT)} references {name}")
    assert not offenders, "ingestion must not touch compliance types:\n" + "\n".join(offenders)


def test_detection_never_uses_a_model() -> None:
    """Vendor identity is decided by data-driven signatures, never by inference."""
    source = (INGEST / "vendor_detect.py").read_text(encoding="utf-8")
    for banned in ("sentence_transformers", "torch", "faiss", "ollama", "openai"):
        assert banned not in source
