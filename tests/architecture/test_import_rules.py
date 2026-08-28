"""Architecture tests: the module dependency rules that carry Rules 1 and 4.

Most of the safety argument in NIRIKSHAK rests on one structural property: the
compliance engine can only see the typed Canonical Security Model. It has no
import path to raw vendor syntax or to model output, so a verdict *cannot* be
influenced by either. That property is cheap to state and easy to erode, so it
is asserted here rather than documented and hoped for.

These tests pass vacuously while the packages are empty. They begin genuinely
constraining at P4 (parse), P6 (comply) and P10 (learn).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
API_ROOT = REPO_ROOT / "api"

# (importing package, forbidden package, why it matters)
FORBIDDEN_EDGES: list[tuple[str, str, str]] = [
    ("comply", "learn", "Rule 1 — no model output may reach a compliance verdict"),
    ("comply", "parse", "Rule 1 — no vendor syntax may reach a compliance verdict"),
    ("remediate", "learn", "Rule 4 — no model output may reach a remediation command"),
    ("learn", "comply", "Rule 1 — the suggestion layer must not see verdict logic"),
    ("audit", "comply", "the audit layer records events; it does not judge them"),
    ("audit", "learn", "the audit layer must not depend on the suggestion layer"),
    ("audit", "parse", "the audit layer must not depend on vendor syntax"),
    ("ingest", "comply", "ingestion identifies files; it does not judge them"),
    ("ingest", "normalise", "ingestion does not build the canonical model"),
    ("ingest", "learn", "vendor identity is decided by data, never by a model"),
    ("ingest", "remediate", "ingestion has nothing to do with remediation"),
    ("parse", "learn", "parsing is deterministic; no model may reach a fact"),
    ("parse", "comply", "the parser produces facts; it does not judge them"),
    ("parse", "remediate", "parsing has nothing to do with remediation"),
    ("parse", "normalise", "the canonical model is built downstream, at P5"),
    ("normalise", "comply", "Rule 1 — the canonical model is built, then judged separately"),
    ("normalise", "learn", "Rule 1 — no model output may reach the canonical model"),
    ("normalise", "remediate", "normalisation has nothing to do with remediation"),
    ("normalise", "report", "the canonical model does not know how it will be rendered"),
    ("comply", "ingest", "Rule 1 — the engine judges a model, not a file"),
    ("comply", "normalise", "Rule 1 — the engine receives a CSM, it does not build one"),
    ("comply", "remediate", "a verdict is decided before anything is proposed to fix it"),
    ("comply", "report", "the engine does not know how its findings will be rendered"),
    ("comply", "analyse", "Rule 1 — a verdict rests on the canonical model alone (D22)"),
    ("analyse", "comply", "an ACL observation is a fact, not a verdict (D22)"),
    ("analyse", "learn", "Rule 1 — no model output may reach an analysis result"),
    ("analyse", "parse", "analysis reads the canonical model, never vendor syntax"),
    ("analyse", "ingest", "analysis has no business with files"),
    ("analyse", "normalise", "analysis receives a CSM; it does not build one"),
    ("analyse", "remediate", "analysis reports; it does not propose fixes"),
    ("analyse", "report", "analysis does not know how it will be rendered"),
    # P8 — the reporting and remediation layers (decision D26).
    ("remediate", "comply", "Rule 4 — a snippet is keyed by rule id, not by a verdict"),
    ("remediate", "parse", "remediation reads a vetted library, never vendor syntax"),
    ("remediate", "normalise", "remediation has nothing to do with the canonical model"),
    ("remediate", "ingest", "remediation has no business with uploaded files"),
    ("remediate", "analyse", "remediation is resolved from a rule, not from an observation"),
    ("remediate", "report", "a snippet does not know how it will be rendered"),
    ("report", "comply", "a report renders persisted findings; it must not re-evaluate (D23)"),
    ("report", "parse", "a report renders findings, never raw vendor syntax"),
    ("report", "normalise", "a report receives findings; it does not build a model"),
    ("report", "ingest", "the renderer has no route to an uploaded file"),
    ("report", "learn", "Rule 1 — no model output may reach a document a human acts on"),
    ("report", "db", "the router performs the I/O; the renderer stays free of storage"),
    # P10 — the similarity layer (decisions D38, D42).
    ("learn", "normalise", "Rule 1 — a suggestion must not reach the canonical model"),
    ("learn", "analyse", "a suggestion is not an observation about an access list"),
    ("learn", "report", "the suggestion layer does not know how it will be rendered"),
    ("learn", "remediate", "Rule 4 — no model output may reach a remediation command"),
    ("learn", "db", "suggestions are produced, not persisted, until P11 records a decision"),
]


def _imported_modules(path: Path) -> set[str]:
    """Return every module name imported by a Python source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Relative import; resolve against the file's own package.
                rel = path.relative_to(REPO_ROOT).parent.as_posix().replace("/", ".")
                found.add(f"{rel}.{node.module}" if node.module else rel)
            elif node.module:
                found.add(node.module)
    return found


def _python_files(package: str) -> list[Path]:
    pkg_dir = API_ROOT / package
    return sorted(pkg_dir.rglob("*.py")) if pkg_dir.is_dir() else []


@pytest.mark.parametrize(
    ("importer", "forbidden", "reason"),
    FORBIDDEN_EDGES,
    ids=[f"{a}-must-not-import-{b}" for a, b, _ in FORBIDDEN_EDGES],
)
def test_forbidden_import_edge(importer: str, forbidden: str, reason: str) -> None:
    """`api/<importer>/` must never import `api/<forbidden>/`."""
    violations: list[str] = []

    for source in _python_files(importer):
        for module in _imported_modules(source):
            if module == f"api.{forbidden}" or module.startswith(f"api.{forbidden}."):
                rel = source.relative_to(REPO_ROOT)
                violations.append(f"{rel} imports {module}")

    assert not violations, (
        f"Forbidden import edge api/{importer}/ -> api/{forbidden}/\n"
        f"{reason}\n" + "\n".join(f"  {v}" for v in violations)
    )
