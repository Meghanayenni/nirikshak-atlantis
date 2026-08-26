"""Architecture test for R1: NIRIKSHAK is configuration-file-only.

The Concept Report and DEVELOPER_GUIDE.md §9 both forbid live device access, network
scanning and credentialed connections. Ratified decision R1 removed Netmiko and
NAPALM from the dependency set entirely, so the guarantee is enforced by what is
*absent* rather than by what the code chooses not to call.

Two independent checks, because a rule with real-world consequences should not
depend on a single mechanism:

  1. No source file under api/ imports a device-connection library.
  2. No such library is present in the resolved environment at all.

The second is the stronger claim: a library that is not installed cannot be
called by any future contributor in a hurry.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
API_ROOT = REPO_ROOT / "api"

BANNED_LIBRARIES: list[str] = [
    "netmiko",
    "napalm",
    "paramiko",
    "scrapli",
    "ncclient",
    "pysnmp",
    "telnetlib",
    "asyncssh",
]


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and not node.level:
                found.add(node.module.split(".")[0])
    return found


def test_no_device_library_imported_in_api() -> None:
    """No source file under api/ may import a device-connection library."""
    violations: list[str] = []

    for source in sorted(API_ROOT.rglob("*.py")):
        for module in _top_level_imports(source):
            if module in BANNED_LIBRARIES:
                violations.append(f"{source.relative_to(REPO_ROOT)} imports {module}")

    assert not violations, "R1 violation — NIRIKSHAK must not access live devices.\n" + "\n".join(
        f"  {v}" for v in violations
    )


@pytest.mark.parametrize("library", BANNED_LIBRARIES)
def test_device_library_not_installed(library: str) -> None:
    """No device-connection library may exist in the resolved environment.

    `telnetlib` is a standard-library module up to Python 3.12, so it is
    expected to be findable and is checked by the source-import test above
    rather than by absence.
    """
    if library == "telnetlib":
        pytest.skip("stdlib module until 3.13; covered by the source-import test")

    assert importlib.util.find_spec(library) is None, (
        f"R1 violation — {library!r} is installed. NIRIKSHAK is "
        f"configuration-file-only and must not carry device-connection "
        f"libraries in its environment."
    )


def test_detector_actually_fires() -> None:
    """The import detector must reject a known-bad sample.

    Without this, the checks above would pass just as happily if the AST walk
    were broken — a guardrail that cannot fail is not a guardrail. The fixture
    is stored with a .txt suffix so pytest never collects or executes it.
    """
    fixture = REPO_ROOT / "tests" / "fixtures" / "banned_import_sample.py.txt"
    assert fixture.is_file(), "missing violating fixture"

    tree = ast.parse(fixture.read_text(encoding="utf-8"), filename=str(fixture))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module and not node.level:
                found.add(node.module.split(".")[0])

    detected = found & set(BANNED_LIBRARIES)
    assert detected == {"netmiko", "napalm", "paramiko"}, (
        f"import detector failed to spot the planted violations; saw {detected}"
    )
