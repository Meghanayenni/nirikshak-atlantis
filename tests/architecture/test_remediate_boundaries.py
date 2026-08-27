"""Boundaries around remediation (P8).

Rule 4 is the clause with the sharpest failure mode in the whole project: a
model-generated command, pasted into a production device on NIRIKSHAK's
authority. The defence is structural rather than procedural, and this is where it
is asserted.

Three properties, in descending order of how much they matter:

    1. `api/remediate/` cannot reach a model. No ML library, no LLM client, no
       `api.learn`.
    2. Nothing in the package composes a command. Commands are read from YAML
       under `snippets/` and returned unchanged.
    3. The package carries no verdict vocabulary, so remediation cannot become a
       second place where something resembling a compliance decision is made.

The `comply -> remediate` edge is asserted in `test_import_rules.py` alongside
the rest of the module graph; it is the reason `Finding.remediation` is `None`
everywhere and resolution happens downstream.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REMEDIATE = REPO_ROOT / "api" / "remediate"
COMPLY = REPO_ROOT / "api" / "comply"
SNIPPETS = REPO_ROOT / "snippets"

ML_MODULES = ["sentence_transformers", "torch", "faiss", "sklearn", "transformers", "ollama"]
NETWORK_MODULES = ["netmiko", "napalm", "paramiko", "requests", "httpx", "socket", "telnetlib"]


def _sources(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def _offending(root: Path, module: str) -> list[str]:
    return [
        f"{path.relative_to(REPO_ROOT)} imports {imported}"
        for path in _sources(root)
        for imported in _imports(path)
        if imported == module or imported.startswith(f"{module}.")
    ]


def test_remediate_package_is_populated() -> None:
    modules = [p for p in _sources(REMEDIATE) if p.name != "__init__.py"]
    assert len(modules) >= 3, f"expected the remediation modules, found {len(modules)}"


# ---------------------------------------------------------------------------
# Rule 4 — no model may reach a command
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ML_MODULES)
def test_remediate_uses_no_machine_learning(module: str) -> None:
    """The one that matters most.

    A remediation command is the single most dangerous thing this system can
    emit. If a model cannot be imported here, a model cannot have written what
    the operator types.
    """
    assert _offending(REMEDIATE, module) == []


def test_remediate_cannot_import_the_suggestion_layer() -> None:
    assert _offending(REMEDIATE, "api.learn") == []


@pytest.mark.parametrize("module", NETWORK_MODULES)
def test_remediate_has_no_network_capability(module: str) -> None:
    """R1 — NIRIKSHAK recommends; it never applies. Nothing here may connect."""
    assert _offending(REMEDIATE, module) == []


def test_remediate_imports_only_the_contracts_and_itself() -> None:
    """A whitelist, so layers not yet written are forbidden too."""
    violations: list[str] = []
    for path in _sources(REMEDIATE):
        for imported in _imports(path):
            if not imported.startswith("api."):
                continue
            top = ".".join(imported.split(".")[:2])
            if top not in {"api.models", "api.remediate"}:
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert violations == [], "\n".join(violations)


def test_remediate_makes_no_compliance_decision() -> None:
    """No verdict vocabulary anywhere in the package.

    The resolver is *told* whether a finding is actionable. It must not be able
    to work that out for itself, or remediation becomes a second place where
    something shaped like a verdict is decided (Rule 1).
    """
    forbidden = ("Verdict", "ComplianceRule", "Rulepack", "AbsenceAction", "evaluate_device")
    offenders = [
        f"{path.relative_to(REPO_ROOT)} references {name}"
        for path in _sources(REMEDIATE)
        for name in forbidden
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# Commands are read, never composed
# ---------------------------------------------------------------------------

COMMAND_COMPOSITION = re.compile(
    r"""(
        commands\s*=\s*\(\s*["'f]      |   # a literal command tuple
        commands\s*=\s*\[\s*["'f]      |
        \.format\(                     |   # building a command by substitution
        commands\.append                |
        \+\s*["'][^"']*\s(?:terminal|interface|line|set|no)\b
    )""",
    re.VERBOSE,
)


def test_no_module_composes_a_command() -> None:
    """Rule 4, as a grep for the shape of the mistake.

    Every command NIRIKSHAK can emit must be traceable to a line in a file under
    `snippets/`. A format string, a concatenation or a literal tuple assigned to
    `commands` would each be a command this repository authored rather than
    resolved - which is the thing the vetted library exists to prevent.
    """
    offenders: list[str] = []
    for path in _sources(REMEDIATE):
        source = path.read_text(encoding="utf-8")
        # Strip docstrings and comments: the modules explain the rule at length,
        # and prose about commands is not a command.
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        for match in COMMAND_COMPOSITION.finditer(code):
            offenders.append(f"{path.relative_to(REPO_ROOT)}: {match.group(0)!r}")

    assert offenders == [], (
        "Rule 4 - remediation commands are resolved from the vetted library, "
        "never composed:\n" + "\n".join(f"  {o}" for o in offenders)
    )


def test_the_only_command_source_is_the_snippet_library() -> None:
    """The loader is the sole route from bytes to a RemediationSnippet."""
    constructors = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in _sources(REMEDIATE)
        if "RemediationSnippet(" in path.read_text(encoding="utf-8")
    ]
    assert constructors == ["api/remediate/library.py"], (
        f"RemediationSnippet is constructed outside the loader: {constructors}"
    )


# ---------------------------------------------------------------------------
# The shipped library
# ---------------------------------------------------------------------------


def test_the_snippet_library_is_empty() -> None:
    """D27 - zero vetted snippets ship at P8.

    A command written from general vendor knowledge would be attributed to
    nobody and checked against nothing, and an operator would paste it into a
    production device on this project's authority.

    **This test is expected to be deleted** by the change that adds the first
    sourced snippet. It fails loudly at that point so the author has to confront
    the vetting requirement rather than adding commands quietly. See
    `docs/SOURCING_BACKLOG.md` gap 6.
    """
    from api.remediate.library import load_library

    library = load_library()
    offenders = [f"{s.snippet_id} ({s.vendor}/{s.os_family})" for s in library.snippets]

    assert offenders == [], (
        "the snippet library is no longer empty; confirm every entry names a real "
        "vetter and a real vendor document:\n" + "\n".join(f"  {o}" for o in offenders)
    )


def test_the_snippet_schema_is_present() -> None:
    """The schema is what makes an unvetted snippet unloadable, not a convention."""
    schema = SNIPPETS / "schema" / "snippet.schema.json"
    assert schema.is_file(), "snippets/schema/snippet.schema.json is missing"

    import json

    body = json.loads(schema.read_text(encoding="utf-8"))
    required = set(body["required"])
    assert {"vetted_by", "reference", "commands"} <= required, (
        "a snippet must be unable to load without a vetter and a cited document"
    )


def test_the_library_documents_why_it_is_empty() -> None:
    readme = SNIPPETS / "README.md"
    assert readme.is_file(), "snippets/README.md is missing"
    assert readme.stat().st_size > 0


def test_comply_still_cannot_reach_remediation() -> None:
    """Restated here beside the Rule 4 tests, because it is a Rule 4 property.

    If the engine could resolve a snippet, `Finding.remediation` would be
    populated at evaluation time and a verdict and its proposed fix would be
    decided together. They are decided apart, and the import graph is what makes
    that true rather than a convention (decision D26).
    """
    assert _offending(COMPLY, "api.remediate") == []
