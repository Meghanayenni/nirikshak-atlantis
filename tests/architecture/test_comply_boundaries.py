"""Boundaries around the compliance engine (P6).

This is the layer NIRIKSHAK's whole safety argument is about. The claim is one
sentence:

    the compliance engine can only see the typed Canonical Security Model, so a
    verdict cannot be influenced by raw vendor syntax or by model output.

That is either structurally true or it is marketing, and the difference is
whether the imports say so. Everything here exists to make it the first.

The strongest test in this module is the **whitelist**: `api/comply/` may import
`api.models`, `api.audit` and nothing else from `api/`. A blacklist only forbids
the layers we thought of; a whitelist also forbids the ones P7 and P8 have not
written yet.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPLY = REPO_ROOT / "api" / "comply"

ML_MODULES = ["sentence_transformers", "torch", "faiss", "sklearn", "transformers", "ollama"]
NETWORK_MODULES = ["netmiko", "napalm", "paramiko", "requests", "httpx", "socket", "telnetlib"]

PERMITTED_API_IMPORTS = {"api.models", "api.comply", "api.audit"}
"""What the engine may reach.

`api.models` is the contracts — the CSM, the rulepack, the finding.
`api.audit` is the append-only chain, used by `service.py` to record that a run
happened. It writes identifiers and counts, never configuration content, and
`api.audit` itself is forbidden from importing `comply`, so the edge cannot
become a route in the other direction.
"""


def _sources() -> list[Path]:
    return sorted(p for p in COMPLY.rglob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def _offending(module: str) -> list[str]:
    return [
        f"{path.relative_to(REPO_ROOT)} imports {imported}"
        for path in _sources()
        for imported in _imports(path)
        if imported == module or imported.startswith(f"{module}.")
    ]


def test_comply_package_is_populated() -> None:
    """Guard against every test below passing because the package is empty."""
    modules = [p for p in _sources() if p.name != "__init__.py"]
    assert len(modules) >= 4, f"expected the comply modules, found {len(modules)}"


# ---------------------------------------------------------------------------
# Rule 1 — the whitelist
# ---------------------------------------------------------------------------


def test_comply_imports_only_permitted_api_packages() -> None:
    """A whitelist, so layers that do not exist yet are forbidden too."""
    violations: list[str] = []
    for path in _sources():
        for imported in _imports(path):
            if not imported.startswith("api."):
                continue
            top = ".".join(imported.split(".")[:2])
            if top not in PERMITTED_API_IMPORTS:
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert violations == [], (
        "the compliance engine may see the canonical model and the audit chain, "
        "and nothing else:\n" + "\n".join(violations)
    )


@pytest.mark.parametrize(
    "layer",
    ["api.parse", "api.learn", "api.ingest", "api.normalise", "api.remediate", "api.report"],
)
def test_comply_cannot_reach_these_layers(layer: str) -> None:
    """Named individually as well, so a failure says which rule broke."""
    assert _offending(layer) == []


@pytest.mark.parametrize("module", ML_MODULES)
def test_comply_uses_no_machine_learning(module: str) -> None:
    """Rule 1 — AI never issues a compliance verdict."""
    assert _offending(module) == []


@pytest.mark.parametrize("module", NETWORK_MODULES)
def test_comply_has_no_network_capability(module: str) -> None:
    assert _offending(module) == []


def test_the_audit_layer_cannot_import_comply_back() -> None:
    """The one permitted edge must not become bidirectional."""
    audit_root = REPO_ROOT / "api" / "audit"
    offenders = [
        f"{path.relative_to(REPO_ROOT)} imports api.comply"
        for path in sorted(audit_root.rglob("*.py"))
        for imported in _imports(path)
        if imported.startswith("api.comply")
    ]
    assert offenders == []


# ---------------------------------------------------------------------------
# Rule 5 — rules are data, not code
# ---------------------------------------------------------------------------

VENDOR_LITERALS = [
    "cisco",
    "ios",
    "nxos",
    "arista",
    "eos",
    "juniper",
    "junos",
    "paloalto",
    "panos",
    "fortinet",
    "fortios",
    "sonic",
]


@pytest.mark.parametrize("vendor", VENDOR_LITERALS)
def test_comply_names_no_vendor(vendor: str) -> None:
    """A vendor name in the engine means vendor logic came back into the rules.

    DEVELOPER_GUIDE.md §13 forbids it by name. Adding a platform must stay a data change.
    """
    word = re.compile(rf"\b{re.escape(vendor)}\b", re.IGNORECASE)
    offenders = [
        f"{path.relative_to(REPO_ROOT)} names {vendor!r}"
        for path in _sources()
        if word.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], "\n".join(offenders)


def test_comply_names_no_canonical_field() -> None:
    """Every check is uniform. A field name here means one control got special
    behaviour the others do not have, which is how a rule engine stops being one."""
    from api.models.csm import CANONICAL_FIELD_NAMES

    offenders = [
        f"{path.relative_to(REPO_ROOT)} names {name!r}"
        for path in _sources()
        for name in CANONICAL_FIELD_NAMES
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], "\n".join(offenders)


def test_comply_hardcodes_no_thresholds() -> None:
    """A threshold in code is a rule that cannot be edited as data."""
    suspicious = ("THRESHOLDS", "RULES = ", "KNOWN_RULES", "DEFAULT_RULES")
    offenders = [
        f"{path.relative_to(REPO_ROOT)} defines {name}"
        for path in _sources()
        for name in suspicious
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


# ---------------------------------------------------------------------------
# Rule 1 — no model may write into a verdict
# ---------------------------------------------------------------------------


def test_the_finding_contract_has_no_field_a_model_could_write() -> None:
    """Asserted on the contract, because that is where it must hold.

    No explanation string that could carry a verdict, no suggested value, no
    model-derived score. A model has nowhere to write here even if something
    tried to give it one.
    """
    from api.models.finding import Finding

    forbidden = {
        "explanation",
        "suggestion",
        "suggested_value",
        "model_output",
        "llm_explanation",
        "raw_score",
        "similarity",
    }
    assert not (forbidden & set(Finding.model_fields))
