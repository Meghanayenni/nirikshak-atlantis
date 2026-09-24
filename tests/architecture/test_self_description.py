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

import re
from pathlib import Path

import pytest
import yaml

from api.comply.engine import ENGINE_VERSION
from api.comply.rulepacks import MANIFEST_PATH, RULES_ROOT, load_rulepack, rulepack_checksum
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
# The rulepack's version, bound to its contents at load (ADR 0056)
# ---------------------------------------------------------------------------
#
# D125 (ADR 0048) bound version to digest in a test fixture here, and said a
# rule edit could legitimately keep its version "with the digest updated and a
# reason in the commit". That escape is exactly what the report's mapping guard
# could not survive: it compared versions, and `1.0.0` had already named three
# rule sets. The binding now lives in `rules/rulepack.yaml`, is verified by the
# loader on every load, and the run records the checksum rather than trusting
# the label. What remains for a test is the manifest's own discipline.


def _manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_the_rulepack_loads_only_as_the_version_its_manifest_names() -> None:
    manifest = _manifest()
    pack = load_rulepack()
    assert pack.version == str(manifest["version"])
    assert pack.checksum == manifest["checksum"] == rulepack_checksum()


def test_no_version_is_reused_and_no_content_is_relabelled() -> None:
    """A version names one content; one content has one version.

    The first closes D125's escape — a version kept while its rules changed. The
    second refuses the mirror image: the same rules minted twice under different
    labels, which would make two runs look different when they were not.
    """
    manifest = _manifest()
    entries = [{"version": manifest["version"], "checksum": manifest["checksum"]}]
    entries += list(manifest.get("history") or ())

    versions = [str(e["version"]) for e in entries]
    assert len(versions) == len(set(versions)), f"a version repeats: {versions}"
    checksums = [e["checksum"] for e in entries if e["checksum"]]
    assert len(checksums) == len(set(checksums)), "one content carries two versions"
    for version in versions:
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), version


def test_the_loader_refuses_rules_that_are_not_the_declared_version(tmp_path: Path) -> None:
    """Change one byte of one rule; the rulepack must not load.

    Proved on a copy, so the shipped rules are never touched. This is what makes
    the version mean something at runtime rather than only in CI.
    """
    import shutil

    from api.comply.errors import RulepackIntegrityError

    base = tmp_path / "rules"
    shutil.copytree(RULES_ROOT.parent, base)
    load_rulepack(base / "canonical", manifest=base / "rulepack.yaml")  # the copy is intact

    target = base / "canonical" / "NRK-NTP-001.yaml"
    target.write_text(target.read_text(encoding="utf-8") + "# edited\n", encoding="utf-8")
    with pytest.raises(RulepackIntegrityError, match="do not match rulepack"):
        load_rulepack(base / "canonical", manifest=base / "rulepack.yaml")


def test_a_framework_index_is_part_of_what_a_version_means(tmp_path: Path) -> None:
    """The indexes decide which identifiers a finding carries, and where."""
    import shutil

    from api.comply.errors import RulepackIntegrityError

    base = tmp_path / "rules"
    shutil.copytree(RULES_ROOT.parent, base)
    index = next((base / "frameworks").glob("disa-*.index.yaml"))
    index.write_text(index.read_text(encoding="utf-8").replace("^17", "^1[67]"), encoding="utf-8")
    with pytest.raises(RulepackIntegrityError):
        load_rulepack(base / "canonical", manifest=base / "rulepack.yaml")


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
