"""No CIS Benchmark material is held in this repository, in any form.

The CIS Cisco IOS XE 17.x Benchmark's own first page says it is never acceptable
to host a CIS Benchmark in any format on a third-party site, and asks that CIS
Legal be contacted about using portions of its recommendations. This repository
has a public remote. So the benchmark is **referenced by** the repository and
never held **in** it (ADR 0052): its edition and sha256 are recorded, its
recommendation *numbers* are indexed, and nothing else crosses into the tree.

This project makes no legal claim about those terms either way (ADR 0005). It
records that they were read and that the conservative reading was taken.

The `.gitignore` entry is the accident guard. This module is the check, and it
deliberately walks the **filesystem** rather than `git ls-files`: an ignored copy
sitting in the working tree is one `git add -f` from the remote, and that is the
state this session found the file in.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
import yaml

from api.comply.frameworks import FRAMEWORK_INDEX_ROOT, indexes
from api.comply.rulepacks import load_rulepack
from api.models.enums import Framework

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CIS_NAME = re.compile(r"cis.*benchmark|benchmark.*\bcis\b|CIS_Cisco_IOS", re.IGNORECASE)
"""A filename a CIS Benchmark, or an extract of one, would plausibly carry."""

SKIP_DIRS = frozenset({".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"})

LARGE = 256 * 1024
"""Files at least this big are hashed against the pinned digest, whatever their name."""


def _walk(root: Path) -> list[Path]:
    out: list[Path] = []
    for path in root.iterdir():
        if path.name in SKIP_DIRS:
            continue
        if path.is_dir():
            out += _walk(path)
        elif path.is_file():
            out.append(path)
    return out


def cis_named(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in _walk(root) if CIS_NAME.search(p.name))


def cis_by_digest(root: Path, digest: str) -> list[str]:
    """Files whose bytes are the pinned benchmark, whatever they are called."""
    found: list[str] = []
    for path in _walk(root):
        if path.suffix.lower() == ".pdf" or path.stat().st_size >= LARGE:
            if hashlib.sha256(path.read_bytes()).hexdigest() == digest:
                found.append(str(path.relative_to(root)))
    return sorted(found)


@pytest.fixture(scope="module")
def cis_index():
    index = indexes().get(Framework.CIS)
    assert index is not None, "the CIS index is expected to exist once sourced (ADR 0052)"
    return index


# ---------------------------------------------------------------------------
# The file itself
# ---------------------------------------------------------------------------


def test_no_file_named_like_a_cis_benchmark_is_in_the_tree() -> None:
    offenders = cis_named(REPO_ROOT)
    assert offenders == [], (
        "a file named like a CIS Benchmark is inside the repository. The benchmark "
        "is read from outside the tree and never held (ADR 0052):\n" + "\n".join(offenders)
    )


def test_no_file_in_the_tree_is_the_pinned_benchmark(cis_index) -> None:
    """A renamed copy is still the benchmark."""
    offenders = cis_by_digest(REPO_ROOT, cis_index.sha256)
    assert offenders == [], "the pinned CIS Benchmark is in the tree:\n" + "\n".join(offenders)


def test_the_gitignore_carries_the_accident_guard() -> None:
    text = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "*CIS*Benchmark*" in text
    assert "ADR 0052" in text, "the entry should say why it is there"


def test_both_detectors_actually_fire(tmp_path: Path) -> None:
    """A guard that cannot fail is not a guard."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "CIS_Cisco_IOS_XE_17_x_Benchmark_v2_2_1.pdf").write_bytes(b"x")
    (tmp_path / "renamed.pdf").write_bytes(b"the pinned bytes")
    assert cis_named(tmp_path) == [str(Path("docs") / "CIS_Cisco_IOS_XE_17_x_Benchmark_v2_2_1.pdf")]

    digest = hashlib.sha256(b"the pinned bytes").hexdigest()
    assert cis_by_digest(tmp_path, digest) == ["renamed.pdf"]


def test_the_name_detector_leaves_ordinary_files_alone(tmp_path: Path) -> None:
    for name in ("test_cisco_ios.py", "CIS.md", "benchmark_results.txt", "disco.yaml"):
        (tmp_path / name).write_text("", encoding="utf-8")
    assert cis_named(tmp_path) == []


# ---------------------------------------------------------------------------
# What IS recorded: numbers, an edition and a digest
# ---------------------------------------------------------------------------


def test_the_cis_index_records_numbers_and_nothing_else(cis_index) -> None:
    """Recommendation numbers only. The heading text was read to find them and discarded."""
    path = next(
        p
        for p in FRAMEWORK_INDEX_ROOT.glob("*.index.yaml")
        if yaml.safe_load(p.read_text(encoding="utf-8"))["framework"] == "cis"
    )
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert set(raw) == {
        "framework",
        "document",
        "edition",
        "source_note",
        "catalog_sha256",
        "covers",
        "controls",
        "withdrawn",
    }, "a new key in the CIS index is a new kind of material; decide it deliberately"
    assert all(re.fullmatch(r"\d+(\.\d+)+", str(c)) for c in raw["controls"])
    assert "held_at" not in raw and "source_url" not in raw, "referenced, not held"


def test_every_cis_citation_is_an_identifier_not_a_title(cis_index) -> None:
    """Document, edition, number. No recommendation wording travels with it."""
    rulepack = load_rulepack()
    for rule in rulepack.rules:
        for ref in rule.frameworks:
            if ref.framework is Framework.CIS:
                assert ref.citation == cis_index.cite(ref.control_id), rule.rule_id


def test_the_sourcing_script_refuses_a_benchmark_inside_the_tree() -> None:
    """The last place a copy could be introduced: the tool that reads it."""
    from scripts.fetch_framework_catalog import main

    with pytest.raises(SystemExit, match="inside the repository"):
        main(["cis", "--catalog", str(REPO_ROOT / "docs" / "sources" / "anything.pdf")])
