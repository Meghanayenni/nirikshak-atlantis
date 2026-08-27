"""Corpus policy — decision R9, enforced mechanically rather than remembered.

An evaluation is only worth its separation guarantees. These tests make the
separation a property of the repository instead of a promise in a document:

  * every corpus file is accounted for, with a matching checksum
  * no file appears in two splits
  * vendor packs are authored from `dev` only
  * the held-out vendor has no pack and no seed example
  * nothing in the corpus is represented as real-world data
  * sanitisation is checked, not asserted
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest
import yaml

from api.ingest.packs import load_active_packs

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS = REPO_ROOT / "corpus"
MANIFEST_PATH = CORPUS / "MANIFEST.yaml"


@pytest.fixture(scope="module")
def manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))


def corpus_files() -> list[Path]:
    return sorted(
        p for p in CORPUS.rglob("*") if p.is_file() and p.name not in ("MANIFEST.yaml", ".gitkeep")
    )


# ---------------------------------------------------------------------------
# Manifest completeness and integrity
# ---------------------------------------------------------------------------


def test_manifest_exists_and_parses(manifest: dict) -> None:
    assert manifest["files"], "the manifest lists no files"
    assert manifest["held_out_vendor"] == "paloalto"


def test_every_corpus_file_is_in_the_manifest(manifest: dict) -> None:
    """An unlisted file could quietly enter a metric."""
    listed = {entry["path"] for entry in manifest["files"]}
    actual = {p.relative_to(CORPUS).as_posix() for p in corpus_files()}
    assert actual == listed, f"unlisted: {actual - listed}; missing: {listed - actual}"


def test_every_checksum_matches(manifest: dict) -> None:
    """A file edited after labelling would silently invalidate its labels."""
    for entry in manifest["files"]:
        path = CORPUS / entry["path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"{entry['path']} has changed since it was recorded"


def test_no_file_is_in_two_splits(manifest: dict) -> None:
    """Training and evaluating on the same bytes measures memorisation."""
    seen: dict[str, str] = {}
    for entry in manifest["files"]:
        assert entry["path"] not in seen, f"{entry['path']} listed twice"
        seen[entry["path"]] = entry["split"]
    assert set(seen.values()) <= {"dev", "eval", "holdout"}


def test_split_directory_matches_declared_split(manifest: dict) -> None:
    """The directory layout and the manifest must agree."""
    for entry in manifest["files"]:
        parts = Path(entry["path"]).parts
        if entry["split"] == "holdout":
            assert parts[0] == "holdout", f"{entry['path']} is holdout but not under holdout/"
        else:
            assert parts[1] == entry["split"], (
                f"{entry['path']} is declared {entry['split']} but sits under {parts[1]}/"
            )


# ---------------------------------------------------------------------------
# Provenance honesty
# ---------------------------------------------------------------------------


def test_nothing_is_represented_as_real_world_data(manifest: dict) -> None:
    """Synthetic data must never be presented as captured from a real network."""
    for entry in manifest["files"]:
        assert entry["is_real_world_data"] is False
        assert entry["source_type"] == "synthetic"


def test_every_file_records_its_provenance(manifest: dict) -> None:
    required = {
        "path",
        "split",
        "vendor",
        "os_family",
        "source_type",
        "source_ref",
        "authored_by",
        "sanitised",
        "is_real_world_data",
        "sha256",
        "added",
    }
    for entry in manifest["files"]:
        missing = required - set(entry)
        assert not missing, f"{entry['path']} lacks {sorted(missing)}"


def test_manifest_states_the_synthetic_caveat() -> None:
    """The P9 report inherits this wording; it must exist to be inherited."""
    text = MANIFEST_PATH.read_text(encoding="utf-8")
    assert "SYNTHETIC" in text
    assert "must not claim universal vendor coverage" in text


# ---------------------------------------------------------------------------
# Sanitisation, checked rather than promised
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = [
    re.compile(r"password\s+7\s+[0-9A-Fa-f]{4,}"),
    re.compile(r"secret\s+5\s+\$1\$"),
    re.compile(r"\$6\$[./A-Za-z0-9]{8,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"snmp-server community\s+(?!public\b|private\b)\S+"),
]

RESERVED_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.", "10.", "172.16.", "192.168.")
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_no_credentials_in_the_corpus(path: Path) -> None:
    """Hashed credentials are still credentials — a type-7 hash is crackable."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for pattern in CREDENTIAL_PATTERNS:
        assert not pattern.search(text), f"{path.name} contains {pattern.pattern!r}"


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_only_documentation_addressing(path: Path) -> None:
    """RFC 5737 and RFC 1918 only — no real routable addresses."""
    text = path.read_text(encoding="utf-8", errors="replace")
    for address in IPV4.findall(text):
        if address.startswith(("0.", "255.")) or address.endswith(".0") or "255.255" in address:
            continue  # masks and wildcards
        assert address.startswith(RESERVED_PREFIXES), (
            f"{path.name} contains non-documentation address {address}"
        )


@pytest.mark.parametrize("path", corpus_files(), ids=lambda p: p.name)
def test_hostnames_use_reserved_domains(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="replace")
    domains = re.findall(r"domain[- ]name[> ]+([A-Za-z0-9.-]+)", text)
    for domain in domains:
        assert domain.endswith((".example", "example.com", ".invalid", ".test")), (
            f"{path.name} uses non-reserved domain {domain}"
        )


# ---------------------------------------------------------------------------
# Train / evaluation separation
# ---------------------------------------------------------------------------


def _pack_examples() -> list[tuple[str, str, str]]:
    """(pack_id, source_id, example) for every literal example a pack declares."""
    out: list[tuple[str, str, str]] = []
    for pack in load_active_packs(use_cache=False):
        for pattern in pack.patterns:
            out += [(pack.pack_id, pattern.id, ex) for ex in pattern.examples]
        for identity in pack.identity:
            out += [(pack.pack_id, f"identity:{identity.field}", ex) for ex in identity.examples]
    return out


def _lines_in_split(manifest: dict, *splits: str) -> set[str]:
    lines: set[str] = set()
    for entry in manifest["files"]:
        if entry["split"] in splits:
            text = (CORPUS / entry["path"]).read_text(encoding="utf-8", errors="replace")
            lines |= {ln.strip() for ln in text.splitlines() if ln.strip()}
    return lines


def test_every_pack_example_comes_from_the_development_split(manifest: dict) -> None:
    """The rule that keeps a pattern honest.

    An example is the evidence a pattern was authored from. Requiring every one
    to appear verbatim in a development file catches two different failures with
    one check:

      * an example found only in eval or holdout means the pattern was authored
        from data reserved for measuring it — memorisation dressed as accuracy;
      * an example found nowhere at all means the pattern was written from
        general vendor knowledge and verified against nothing.

    The second is not hypothetical. It caught five invented Cisco patterns at P4.
    """
    dev_lines = _lines_in_split(manifest, "dev")

    violations = [
        f"{pack_id} {source_id}: {example!r} appears in no development file"
        for pack_id, source_id, example in _pack_examples()
        if example.strip() not in dev_lines
    ]

    assert not violations, (
        "every pattern example must be a line someone actually read in "
        "corpus/*/dev/:\n" + "\n".join(violations)
    )


def test_no_example_is_unique_to_a_protected_file(manifest: dict) -> None:
    """The original check, kept explicit for the message it gives.

    Subsumed by the test above, but stated separately so a failure says
    'authored from evaluation data' rather than the more general
    'not found in development data'.
    """
    dev_lines = _lines_in_split(manifest, "dev")
    protected_lines = _lines_in_split(manifest, "eval", "holdout")

    violations = [
        f"{pack_id} {source_id}: {example!r} appears only in eval/holdout"
        for pack_id, source_id, example in _pack_examples()
        if example.strip() in protected_lines and example.strip() not in dev_lines
    ]

    assert not violations, "packs were authored from protected files:\n" + "\n".join(violations)


def test_pack_examples_exist_at_all() -> None:
    """Guard against both tests above passing because no pack declares examples."""
    assert len(_pack_examples()) >= 15


# ---------------------------------------------------------------------------
# Platform knowledge provenance (decision D11)
# ---------------------------------------------------------------------------


def _platform_claims() -> list[tuple[str, str, object]]:
    """(pack_id, field, provenance) for every default and capability claim shipped."""
    out: list[tuple[str, str, object]] = []
    for pack in load_active_packs(use_cache=False):
        out += [(pack.pack_id, d.field, d.provenance) for d in pack.defaults]
        out += [
            (pack.pack_id, c.field, c.provenance)
            for c in pack.capabilities
            if c.provenance is not None
        ]
    return out


def test_the_synthetic_corpus_is_never_cited_for_a_platform_default() -> None:
    """A platform default is a claim about the PLATFORM, not about a device.

    Every corpus file is synthetic — written by the team to be realistic, not
    captured from a real network — so no corpus file can establish what a vendor
    documents as its default. Citing one would dress a fixture up as vendor
    documentation, which is the most convincing way this system could be wrong.
    """
    corpus_markers = ("corpus/", ".cfg", ".conf", "rtr-core", "sw-access", "sw-leaf", "srx-")

    violations = [
        f"{pack_id} default for {field!r} cites {marker!r} — a synthetic corpus file"
        for pack_id, field, prov in _platform_claims()
        for marker in corpus_markers
        if marker in f"{getattr(prov, 'source_id', '')} {getattr(prov, 'locator', '')}".lower()
    ]

    assert not violations, "\n".join(violations)


def test_every_sourced_platform_claim_is_actually_findable() -> None:
    """D11 — a 'sourced' claim names a document and a place inside it.

    The contract enforces this at construction. Asserting it again over the
    shipped packs is what catches a default added later with a plausible-looking
    but empty citation.
    """
    from api.models.enums import ProvenanceStatus

    violations = [
        f"{pack_id} claim for {field!r}: sourced but names {prov.source_id!r} / {prov.locator!r}"
        for pack_id, field, prov in _platform_claims()
        if prov.status is ProvenanceStatus.SOURCED
        and not (prov.source_id.strip() and prov.locator.strip())
    ]

    assert not violations, "\n".join(violations)


def test_project_asserted_claims_are_labelled_as_such() -> None:
    """An assertion must never be presented as externally verified."""
    from api.models.enums import PlatformSourceType, ProvenanceStatus

    violations = [
        f"{pack_id} claim for {field!r} mixes assertion and sourcing"
        for pack_id, field, prov in _platform_claims()
        if (prov.source_type is PlatformSourceType.PROJECT_ASSERTED)
        != (prov.status is ProvenanceStatus.PROJECT_ASSERTED)
    ]

    assert not violations, "\n".join(violations)


def test_no_platform_defaults_are_shipped_yet() -> None:
    """P5 ships the absence engine with no authored defaults, deliberately.

    No vendor documentation has been sourced, and the corpus cannot substitute
    for it. Rather than manufacture defaults to make the pipeline look complete,
    every absent field abstains — see ADR 0012 and CORPUS_PREREQUISITES.

    **This test is expected to be deleted** by the change that authors the first
    genuinely sourced default. It fails loudly at that point so the author has to
    look at the provenance tests above rather than adding data quietly.
    """
    packs = load_active_packs(use_cache=False)
    declared = {p.pack_id: (len(p.defaults), len(p.capabilities)) for p in packs}

    assert all(counts == (0, 0) for counts in declared.values()), (
        f"platform knowledge appeared without a sourcing review: {declared}"
    )


def test_held_out_vendor_has_no_pack(manifest: dict) -> None:
    """The generalisation experiment is only real if nothing was ever authored."""
    held_out = manifest["held_out_vendor"]
    packs = load_active_packs(use_cache=False)

    assert all(p.vendor != held_out for p in packs), f"a pack exists for {held_out}"

    pack_files = list((REPO_ROOT / "packs").rglob("*.yaml"))
    for path in pack_files:
        assert held_out not in path.read_text(encoding="utf-8").lower(), (
            f"{path.name} mentions the held-out vendor"
        )


def test_held_out_vendor_files_are_all_in_holdout(manifest: dict) -> None:
    held_out = manifest["held_out_vendor"]
    for entry in manifest["files"]:
        if entry["vendor"] == held_out:
            assert entry["split"] == "holdout", (
                f"{entry['path']} is {held_out} but not in the holdout split"
            )


def test_holdout_contains_only_the_held_out_vendor(manifest: dict) -> None:
    held_out = manifest["held_out_vendor"]
    for entry in manifest["files"]:
        if entry["split"] == "holdout":
            assert entry["vendor"] == held_out


def test_corpus_has_the_four_planned_vendors(manifest: dict) -> None:
    vendors = {e["vendor"] for e in manifest["files"]}
    assert vendors == {"cisco", "arista", "juniper", "paloalto"}


def test_ios_and_arista_are_both_present(manifest: dict) -> None:
    """Kept deliberately: their similarity is what tests the ambiguity rule."""
    dev = {e["vendor"] for e in manifest["files"] if e["split"] == "dev"}
    assert {"cisco", "arista"} <= dev


def test_every_split_has_files(manifest: dict) -> None:
    from collections import Counter

    counts = Counter(e["split"] for e in manifest["files"])
    assert counts["dev"] >= 4
    assert counts["eval"] >= 2
    assert counts["holdout"] >= 1
