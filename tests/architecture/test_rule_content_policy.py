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

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_ROOT = REPO_ROOT / "rules"

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
