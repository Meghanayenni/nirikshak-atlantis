"""Repository content policy test for R16.

Ratified decision R16 takes the conservative engineering approach to framework
content: the repository stores framework and control *identifiers*, our own rule
metadata, and rationale text we wrote. It does not accumulate large amounts of
framework prose.

This test enforces that policy mechanically. It makes no legal claim of any
kind; it simply keeps the repository's content to what we can account for.
See docs/CONTENT_POLICY.md.

Passes vacuously until rulepacks are authored at P6.
"""

from __future__ import annotations

from pathlib import Path

from tests.architecture.team import TEAM_VETTERS

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_ROOT = REPO_ROOT / "rules"
SNIPPETS_ROOT = REPO_ROOT / "snippets"

# Field names that would hold verbatim framework prose rather than an
# identifier or our own words.
FORBIDDEN_FIELDS: set[str] = {
    "control_text",
    "benchmark_text",
    "standard_text",
    "control_description_verbatim",
    "annex_text",
    "stig_text",
    "cis_text",
    "iso_text",
    "nist_text",
    "verbatim",
}

# Our own rationale should be a sentence or two explaining why the check exists,
# not a transcription. A generous ceiling: this catches wholesale pasting, not
# thorough writing.
MAX_RATIONALE_CHARS = 1200


def _rule_files() -> list[Path]:
    if not RULES_ROOT.is_dir():
        return []
    return sorted(p for p in RULES_ROOT.rglob("*.yaml") if "schema" not in p.parts)


def test_no_verbatim_text_fields() -> None:
    """No rule file may carry a field intended to hold framework prose."""
    import yaml

    violations: list[str] = []
    for path in _rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        for field in sorted(set(data) & FORBIDDEN_FIELDS):
            violations.append(f"{path.relative_to(REPO_ROOT)} carries {field!r}")

    assert not violations, (
        "R16 content policy — rules store identifiers and our own rationale, "
        "not framework prose.\n" + "\n".join(f"  {v}" for v in violations)
    )


def test_every_rule_has_original_rationale() -> None:
    """Every rule must explain itself in our own words, within a sane length."""
    import yaml

    violations: list[str] = []
    for path in _rule_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict) or "rule_id" not in data:
            continue

        rationale = data.get("rationale")
        rel = path.relative_to(REPO_ROOT)
        if not rationale or not str(rationale).strip():
            violations.append(f"{rel} has no rationale")
        elif len(str(rationale)) > MAX_RATIONALE_CHARS:
            violations.append(
                f"{rel} rationale is {len(str(rationale))} chars "
                f"(limit {MAX_RATIONALE_CHARS}) — is this our own text?"
            )

    assert not violations, "R16 content policy:\n" + "\n".join(f"  {v}" for v in violations)


def test_content_policy_document_exists() -> None:
    """The policy the tests enforce must be written down for contributors."""
    policy = REPO_ROOT / "docs" / "CONTENT_POLICY.md"
    assert policy.is_file(), "docs/CONTENT_POLICY.md is missing"
    assert policy.stat().st_size > 0, "docs/CONTENT_POLICY.md is empty"


# ---------------------------------------------------------------------------
# Remediation snippets (P8)
#
# `CONTENT_POLICY.md` has named `snippets/` since P0 and nothing read it until
# now. The policy is that each snippet cites the vendor document it was checked
# against; Rule 4 adds that a human must have done the checking. Both are
# properties of a file on disk, so both are checkable here rather than at load.
# ---------------------------------------------------------------------------


def _snippet_files() -> list[Path]:
    if not SNIPPETS_ROOT.is_dir():
        return []
    return sorted(p for p in SNIPPETS_ROOT.rglob("*.yaml") if "schema" not in p.parts)


def test_every_snippet_names_a_human_vetter() -> None:
    """Rule 4 — an unvetted snippet is not a snippet.

    Vacuous while the library is empty (decision D27), and deliberately so: this
    is the test that bites on the day someone adds the first one.
    """
    import yaml

    violations: list[str] = []
    for path in _snippet_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue

        rel = path.relative_to(REPO_ROOT)
        vetter = str(data.get("vetted_by", "")).strip()
        if not vetter:
            violations.append(f"{rel} has no vetted_by")
        elif vetter not in TEAM_VETTERS:
            violations.append(
                f"{rel} names {vetter!r} as its vetter — only a named team member vets a command"
            )

    assert not violations, "Rule 4 — commands come from a vetted library:\n" + "\n".join(
        f"  {v}" for v in violations
    )


def test_every_snippet_cites_the_document_it_was_checked_against() -> None:
    """CONTENT_POLICY.md — 'Each snippet cites the document it was checked against.'

    A command with no citation cannot be re-verified by anyone, which makes it
    indistinguishable from one written from memory.
    """
    import yaml

    violations: list[str] = []
    for path in _snippet_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        if not str(data.get("reference", "")).strip():
            violations.append(f"{path.relative_to(REPO_ROOT)} cites no source document")

    assert not violations, "\n".join(f"  {v}" for v in violations)


def test_no_snippet_carries_verbatim_vendor_prose() -> None:
    """The same policy the rules are held to, applied to the other data tree."""
    import yaml

    forbidden = FORBIDDEN_FIELDS | {"vendor_text", "documentation_text", "guide_text"}
    violations: list[str] = []
    for path in _snippet_files():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        for field in sorted(set(data) & forbidden):
            violations.append(f"{path.relative_to(REPO_ROOT)} carries {field!r}")

    assert not violations, "\n".join(f"  {v}" for v in violations)


def test_every_snippet_file_loads_through_the_library() -> None:
    """Whatever is on disk must satisfy the schema and the contract.

    A file that parses as YAML but fails `RemediationSnippet` would sit in the
    tree looking like a shipped snippet while resolving for nobody.
    """
    from api.remediate.library import load_library

    load_library()  # raises on schema, contract or consistency failure
