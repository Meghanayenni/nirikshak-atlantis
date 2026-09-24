"""Every self-description is derived, or reconciled against what it describes.

`VendorPack.is_detection_only` returned `True` for a pack that read firewall
filters in two surfaces and four identity fields, and `README.md` and
`docs/SOURCING_BACKLOG.md` both repeated it (ADR 0047). `/health` reported
`phase: "P12"` from P12 until P18, the UI displayed it, and a test asserted it —
**a test defending a claim that had been false for six phases** (ADR 0048).

Both are the same failure as the defect register's: a fact about the system
**declared beside** the thing it describes rather than **derived from** it. A
declaration cannot be wrong at the moment it is written and cannot stay right
without somebody remembering.

So: derive it, or reconcile it. This module holds the reconciliations for the
declarations that cannot be derived, each of which would otherwise be a sentence
somewhere downstream that nobody can check.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
import yaml

from api.comply.engine import ENGINE_VERSION
from api.comply.rulepacks import CANONICAL_RULEPACK_VERSION, RULES_ROOT, load_rulepack
from api.ingest.packs import PACK_ROOTS
from api.models.pack import PackStatus

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def pack_files() -> list[Path]:
    roots = [*PACK_ROOTS, REPO_ROOT / "packs" / "archive"]
    return sorted(
        path
        for root in roots
        if root.is_dir()
        for path in root.rglob("*.yaml")
        if not path.name.startswith("activation")
    )


# ---------------------------------------------------------------------------
# A pack's version, declared twice
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", pack_files(), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_a_pack_version_matches_its_filename(path: Path) -> None:
    """`1.3.0.yaml` must declare `pack_version: 1.3.0`.

    The version is written twice — once as a filename the loader sorts by, once
    as a field every stored finding cites through `pack_versions`. Nothing
    reconciled them outside `packs/archive/`, so a pack could have been
    activated under one number and cited under another, and the mismatch would
    have surfaced only as a provenance lookup that quietly found the wrong file.

    This is DEF-18's shape without the deletion: a finding naming a version that
    does not resolve to the bytes that produced it.
    """
    declared = yaml.safe_load(path.read_text(encoding="utf-8")).get("pack_version")

    assert declared == path.stem, (
        f"{path.parent.name}/{path.name} declares {declared!r}; the filename says {path.stem!r}"
    )


def test_exactly_one_pack_per_platform_is_active_on_disk() -> None:
    """The `status:` field against what the loader would accept.

    `active_packs()` raises on two ACTIVE versions of one platform (D46), so a
    second one is caught at load. This catches it in the files, where the fix is
    a one-word edit rather than a deployment that will not start.
    """
    active: dict[str, list[str]] = {}
    for root in PACK_ROOTS:
        if not root.is_dir():
            continue
        for path in root.rglob("*.yaml"):
            if path.name.startswith("activation"):
                continue
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if raw.get("status") != PackStatus.ACTIVE.value:
                continue
            platform = f"{raw['vendor']}/{raw['os_family']}"
            active.setdefault(platform, []).append(raw["pack_version"])

    duplicated = {k: sorted(v) for k, v in active.items() if len(v) > 1}
    assert duplicated == {}, f"two packs declare themselves active: {duplicated}"


# ---------------------------------------------------------------------------
# The rulepack's version, declared with nothing binding it to the rules
# ---------------------------------------------------------------------------


def rulepack_digest() -> str:
    """A digest over the rule files the canonical rulepack is built from.

    Derived, deliberately, and in the same spirit as the vendor-pack checksum:
    the bytes decide the value rather than an author remembering to change one.
    """
    digest = hashlib.sha256()
    for path in sorted(RULES_ROOT.rglob("*.yaml")):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


RULEPACK_CONTENT: dict[str, str] = {
    "1.0.0": "6aa678d256ec5ba9808f3b72631f87aa893af0afc775cbfb8de22cb39a69d218",
    # ADR 0052 — DISA STIG and CIS mappings, and the recorded framework gaps.
    "1.1.0": "930f28a3c270e7d4f1c055cef49097e1dcdc0971ef1249a066a61fc238933a81",
}
"""`rulepack_version` -> the digest of the rules that version contains.

`Rulepack` has no `checksum` field, and ADR 0013 gave the reason: pack checksums
were *declared and never verified* at the time, and copying an unverified
integrity mechanism into a second contract would have doubled the problem rather
than solved it.

**That reasoning expired at P11**, when DEF-13 was fixed and pack checksums
began verifying against file bytes on every load. Since then the rulepack has
been the only versioned artefact in the system with nothing binding its version
to its contents: a rule could be edited, every stored finding would go on citing
`rulepack_version: 1.0.0`, and nothing anywhere would notice.

This is the binding, kept as a test fixture rather than a field because the
version is a *decision* — editing a rule without bumping it is sometimes right
and sometimes not, and a human should have to say which.
"""


def test_the_rulepack_version_matches_the_rules_it_contains() -> None:
    """Change a rule and this fails until somebody decides about the version.

    Failing here is not an error. It is the question *"is this the same rulepack
    as before?"* arriving at the moment somebody can answer it — and the answer
    is either a new version with a new digest, or the same version with the
    digest updated and a reason in the commit.
    """
    version = load_rulepack().version
    assert version == CANONICAL_RULEPACK_VERSION

    recorded = RULEPACK_CONTENT.get(version)
    assert recorded is not None, (
        f"rulepack {version} has no recorded content digest. Add one to "
        "RULEPACK_CONTENT so a later edit to the rules cannot pass unnoticed."
    )
    assert recorded == rulepack_digest(), (
        f"the rules under {RULES_ROOT.name}/ have changed but rulepack {version} has "
        "not. Either mint a new version, or update the digest here and say in the "
        "commit why the version did not move."
    )


def test_every_recorded_rulepack_version_is_plausible() -> None:
    """A digest of the wrong length is a placeholder somebody meant to fill."""
    for version, digest in RULEPACK_CONTENT.items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), version
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{version} has no sha256"


# ---------------------------------------------------------------------------
# Versions restated across files
# ---------------------------------------------------------------------------


def pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    found = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert found is not None, "pyproject declares no version"
    return found.group(1)


def test_the_engine_version_matches_the_package() -> None:
    """`ENGINE_VERSION` says it is "kept in step with pyproject". Now it is.

    It is stamped onto every `Finding` so a verdict can name the code that
    produced it, and it was kept in step by convention — which is to say by
    somebody remembering, twice, in two files.
    """
    assert ENGINE_VERSION == pyproject_version()


def test_the_served_version_is_not_restated_in_source() -> None:
    """`/health` and the OpenAPI document both read the installed distribution.

    A literal here would be a third copy. The check is on the source rather than
    the response because a literal that happens to be *correct today* is exactly
    what this module exists to catch.
    """
    source = (REPO_ROOT / "api" / "main.py").read_text(encoding="utf-8")
    literals = re.findall(r'version\s*=\s*"(\d+\.\d+\.\d+)"', source)
    literals += re.findall(r'"version":\s*"(\d+\.\d+\.\d+)"', source)

    assert literals == [], f"api/main.py restates a version literal: {literals}"


def test_health_serves_no_phase_label() -> None:
    """A phase has no runtime source, so serving one guarantees it goes stale.

    It read `P12` from P12 until P18 — declared by the endpoint, displayed by
    the interface, and asserted by a test. Removed rather than corrected: the
    next correct value has the same lifespan as the last one.
    """
    source = (REPO_ROOT / "api" / "main.py").read_text(encoding="utf-8")

    assert '"phase"' not in source
