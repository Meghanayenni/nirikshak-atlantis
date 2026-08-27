"""Boundaries around the normalise layer (P5).

The canonical model is the trust boundary. Everything upstream of it may deal in
vendor syntax; nothing downstream may. That property is what makes Rule 1
structural rather than aspirational, and it is cheap to erode, so it is asserted
here rather than documented and hoped for.

The Rule 5 test in this module is the one that matters most for P5. Absence
resolution is *entirely* data-driven — the truth table reads pack capabilities
and pack defaults and knows nothing about any vendor. A convenience dictionary of
"known Cisco defaults" inside `api/normalise/` would satisfy every behavioural
test in the suite while quietly making new-vendor support a code change, which is
exactly the clause the problem statement is really testing.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
NORMALISE = REPO_ROOT / "api" / "normalise"
SECURITY = REPO_ROOT / "api" / "security"

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


def test_normalise_package_is_populated() -> None:
    """Guard against every test below passing because the package is empty."""
    modules = [p for p in _sources(NORMALISE) if p.name != "__init__.py"]
    assert len(modules) >= 4, f"expected the normalise modules, found {len(modules)}"


# ---------------------------------------------------------------------------
# Rule 1 — nothing downstream, and no model
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("layer", ["api.comply", "api.learn", "api.remediate", "api.report"])
def test_normalise_does_not_reach_downstream_layers(layer: str) -> None:
    assert _offending(NORMALISE, layer) == []


@pytest.mark.parametrize("module", ML_MODULES)
def test_normalise_uses_no_machine_learning(module: str) -> None:
    """Normalisation is deterministic. A model has no route into the CSM."""
    assert _offending(NORMALISE, module) == []


@pytest.mark.parametrize("module", NETWORK_MODULES)
def test_normalise_has_no_network_capability(module: str) -> None:
    assert _offending(NORMALISE, module) == []


def test_normalise_makes_no_compliance_decision() -> None:
    """No verdict vocabulary anywhere in the package.

    Normalisation produces typed claims. Whether a claim is *secure* is decided
    at P6 by an engine that cannot import this package.
    """
    forbidden = ("Verdict", "ComplianceRule", "Finding", "AbsenceAction", "Severity")
    offenders = [
        f"{path.relative_to(REPO_ROOT)} references {name}"
        for path in _sources(NORMALISE)
        for name in forbidden
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


# ---------------------------------------------------------------------------
# Rule 5 — platform knowledge is data, never code
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
def test_normalise_names_no_vendor(vendor: str) -> None:
    """A vendor name in this package means a default was hard-coded somewhere.

    Adding a platform's defaults must be a pack edit. The moment
    `api/normalise/` knows that Cisco disables something by default, supporting a
    new vendor stops being a data change.
    """
    import re

    # Word-boundary rather than substring: `ios` must not fire on `previous`.
    # Still catches every real mention, including inside a docstring, which is
    # where a hard-coded assumption usually gets explained before it gets written.
    word = re.compile(rf"\b{re.escape(vendor)}\b", re.IGNORECASE)
    offenders = [
        f"{path.relative_to(REPO_ROOT)} names {vendor!r}"
        for path in _sources(NORMALISE)
        if word.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], "\n".join(offenders)


def test_normalise_names_no_canonical_field() -> None:
    """The absence table must not special-case any control.

    Every field is resolved by the same uniform rules. A canonical field name
    appearing here would mean one control had been given behaviour the others do
    not have, which is how a table stops being a table.
    """
    from api.models.csm import CANONICAL_FIELD_NAMES

    offenders = [
        f"{path.relative_to(REPO_ROOT)} names {name!r}"
        for path in _sources(NORMALISE)
        for name in CANONICAL_FIELD_NAMES
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], "\n".join(offenders)


def test_no_default_values_are_embedded_in_code() -> None:
    """No dictionary of platform knowledge masquerading as configuration."""
    suspicious = ("DEFAULTS", "PLATFORM_DEFAULTS", "KNOWN_DEFAULTS", "VENDOR_DEFAULTS")
    offenders = [
        f"{path.relative_to(REPO_ROOT)} defines {name}"
        for path in _sources(NORMALISE)
        for name in suspicious
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


# ---------------------------------------------------------------------------
# Rule 6 — the scrubber sits at the inference boundary
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ML_MODULES + NETWORK_MODULES)
def test_the_scrubber_itself_reaches_nothing(module: str) -> None:
    """It prepares data for inference; it does not perform or transmit any."""
    assert _offending(SECURITY, module) == []


def test_the_scrubber_does_not_touch_storage() -> None:
    """D12 — scrubbing happens on the way to inference, never at rest.

    Redacting the stored configuration would destroy evidence fidelity, which is
    what every finding in the system rests on.
    """
    for layer in ("api.ingest", "api.db"):
        assert _offending(SECURITY, layer) == []
