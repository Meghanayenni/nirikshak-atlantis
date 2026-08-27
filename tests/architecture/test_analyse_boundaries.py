"""Boundaries around structural analysis and the security layer (P7).

The edge that matters most here is **`comply` must not import `analyse`**. If the
compliance engine could reach the ACL analyser, a verdict would become
influenceable by analysis performed outside the canonical security model — which
is precisely what the trust boundary exists to prevent. The two rails are
separate by construction (decision D22), and this is where that is asserted
rather than assumed.

`api/analyse/` itself is pure interval arithmetic over contract objects. It needs
no parser, no engine, no database and no network, so the whitelist admits
`api.models` and nothing else.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYSE = REPO_ROOT / "api" / "analyse"
SECURITY = REPO_ROOT / "api" / "security"
COMPLY = REPO_ROOT / "api" / "comply"

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


def test_analyse_package_is_populated() -> None:
    modules = [p for p in _sources(ANALYSE) if p.name != "__init__.py"]
    assert len(modules) >= 3, f"expected the analyse modules, found {len(modules)}"


# ---------------------------------------------------------------------------
# The rails stay separate (D22)
# ---------------------------------------------------------------------------


def test_comply_cannot_import_analyse() -> None:
    """The important one.

    A verdict must rest on the canonical model alone. If the engine could reach
    the ACL analyser, structural analysis performed outside the CSM could shape a
    PASS or FAIL, which is the exact influence Rule 1 forbids.
    """
    assert _offending(COMPLY, "api.analyse") == []


def test_analyse_cannot_import_comply() -> None:
    """And back the other way: an observation is not a verdict."""
    assert _offending(ANALYSE, "api.comply") == []


def test_analyse_imports_only_the_contracts() -> None:
    """A whitelist, so layers not yet written are forbidden too."""
    violations: list[str] = []
    for path in _sources(ANALYSE):
        for imported in _imports(path):
            if not imported.startswith("api."):
                continue
            top = ".".join(imported.split(".")[:2])
            if top not in {"api.models", "api.analyse"}:
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert violations == [], "\n".join(violations)


@pytest.mark.parametrize("module", ML_MODULES)
def test_analyse_uses_no_machine_learning(module: str) -> None:
    """Interval logic is computation. A model has no route into an observation."""
    assert _offending(ANALYSE, module) == []


@pytest.mark.parametrize("module", NETWORK_MODULES)
def test_analyse_has_no_network_capability(module: str) -> None:
    assert _offending(ANALYSE, module) == []


def test_analyse_makes_no_compliance_decision() -> None:
    """No verdict vocabulary anywhere in the package."""
    forbidden = ("Verdict", "ComplianceRule", "Finding", "AbsenceAction", "Rulepack")
    offenders = [
        f"{path.relative_to(REPO_ROOT)} references {name}"
        for path in _sources(ANALYSE)
        for name in forbidden
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_an_acl_observation_is_not_a_finding() -> None:
    """Structurally separate types, so nothing can merge the two rails."""
    from api.models.analysis import AclObservation
    from api.models.finding import Finding

    assert AclObservation is not Finding
    # An observation has no verdict, and cannot acquire one.
    assert "status" not in AclObservation.model_fields
    assert "base_severity" not in AclObservation.model_fields


# ---------------------------------------------------------------------------
# Rule 5 — no vendor knowledge in the analyser
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
def test_analyse_names_no_vendor(vendor: str) -> None:
    """Interval arithmetic has no business knowing whose list it is reading."""
    word = re.compile(rf"\b{re.escape(vendor)}\b", re.IGNORECASE)
    offenders = [
        f"{path.relative_to(REPO_ROOT)} names {vendor!r}"
        for path in _sources(ANALYSE)
        if word.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], "\n".join(offenders)


def test_analyse_names_no_canonical_field() -> None:
    from api.models.csm import CANONICAL_FIELD_NAMES

    offenders = [
        f"{path.relative_to(REPO_ROOT)} names {name!r}"
        for path in _sources(ANALYSE)
        for name in CANONICAL_FIELD_NAMES
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# The security layer
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ML_MODULES + NETWORK_MODULES)
def test_security_layer_reaches_nothing(module: str) -> None:
    assert _offending(SECURITY, module) == []


def test_password_hashing_uses_the_standard_library() -> None:
    """No invented cryptography, and no new dependency.

    `hashlib.scrypt` is RFC 7914 — a memory-hard KDF designed for passwords.
    Rolling one, or reaching for a fast general-purpose hash, are the two ways
    this goes wrong.
    """
    source = (SECURITY / "passwords.py").read_text(encoding="utf-8")

    assert "hashlib.scrypt" in source
    for wrong in ("md5", "sha1(", "hashlib.sha256(password"):
        assert wrong not in source


def test_no_module_stores_a_plaintext_password() -> None:
    """A grep for the shape of the mistake, across the whole backend."""
    api_root = REPO_ROOT / "api"
    banned = re.compile(r"(password\s*=\s*password\b|plaintext_password|password_plain)")
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in sorted(api_root.rglob("*.py"))
        if banned.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_the_user_contract_carries_no_credential() -> None:
    from api.models.auth import User

    forbidden = {"password", "password_hash", "hash", "secret", "salt", "token"}
    assert not (forbidden & set(User.model_fields))


def test_no_route_returns_a_password_field() -> None:
    """Checked against the generated schema, not against intent."""
    from api.main import app

    schema = app.openapi()
    blob = str(schema).lower()

    assert "password_hash" not in blob
    assert "scrypt" not in blob
