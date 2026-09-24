"""No document in this repository may claim coverage it cannot source.

One framework of four is sourced. NIST SP 800-53 Rev 5 was obtained as OSCAL and
every mapping is validated against it; CIS Benchmarks are behind registration,
DISA's STIG index serves no resolvable file URL, and ISO/IEC 27001 is purchased
(ADR 0035).

**The temptation to round that up is the single largest risk to this project's
integrity argument.** Everything NIRIKSHAK claims rests on refusing to state
more than it can show — the abstentions, the disclosures, the empty selector,
the `project_asserted` provenance on every mapping. One sentence in a README
saying "CIS, NIST, STIG and ISO" undoes all of it, because a reader who checks
one claim and finds it inflated has no reason to believe the rest.

`tests/architecture/test_architecture_document.py` guards one file. This guards
every prose document in the repository, and does it by asking the code which
frameworks are sourced rather than by holding a list of its own.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from api.comply.frameworks import sourced_frameworks
from api.models.enums import Framework

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DOCUMENTS: tuple[Path, ...] = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "DEVELOPER_GUIDE.md",
    REPO_ROOT / "docs" / "architecture.md",
    REPO_ROOT / "docs" / "SOURCING_BACKLOG.md",
    REPO_ROOT / "docs" / "CORPUS_PREREQUISITES.md",
    REPO_ROOT / "docs" / "CONTENT_POLICY.md",
    REPO_ROOT / "docs" / "data-contracts.md",
)
"""Prose a reviewer reads. ADRs are excluded deliberately — see below."""

IDENTIFIER_PATTERNS: dict[Framework, tuple[str, str]] = {
    Framework.CIS: (r"\bCIS[\s-]?\d+(\.\d+)+", "a CIS recommendation number"),
    Framework.STIG: (r"\bV-\d{5,}", "a DISA STIG identifier"),
    Framework.ISO: (r"\bA\.\d+\.\d+(\.\d+)?\b", "an ISO/IEC 27001 Annex A reference"),
    Framework.NIST: (r"\b[A-Z]{2}-\d{2}(\(\d{2}\))?\b", "a NIST SP 800-53 control identifier"),
}

COVERAGE_CLAIMS: tuple[str, ...] = (
    r"compliant with (CIS|DISA|STIG|ISO)",
    r"(CIS|DISA|STIG|ISO)[- ]compliant",
    r"certified",
    r"full coverage",
    r"complete coverage",
)
"""Phrasings that would assert more than a validated identifier ever supports.

`certified` is included for every framework, sourced or not. A validated control
identifier says *this check evidences that control, in our judgement*. It does
not say anybody certified anything, and the mappings are `project_asserted`.
"""


def documents() -> list[Path]:
    return [path for path in DOCUMENTS if path.is_file()]


# ---------------------------------------------------------------------------


@pytest.mark.parametrize("document", documents(), ids=lambda p: p.name)
def test_no_unsourced_framework_identifier_appears(document: Path) -> None:
    """An identifier for a framework with no catalog is an invented citation.

    Keyed off `sourced_frameworks()` rather than a hand-kept list, so the guard
    tightens by itself if a catalog is withdrawn and relaxes only when one is
    added — the property the defect register lost by being maintained by hand
    (ADR 0046).
    """
    text = document.read_text(encoding="utf-8")
    sourced = sourced_frameworks()

    for framework, (pattern, description) in IDENTIFIER_PATTERNS.items():
        if framework in sourced:
            continue
        found = re.search(pattern, text)
        assert found is None, (
            f"{document.name} writes {description} ({found.group(0)!r}) and no "
            f"{framework.value} catalog has been sourced. An identifier nobody can "
            "look up is an invented citation."
        )


@pytest.mark.parametrize("document", documents(), ids=lambda p: p.name)
def test_no_document_claims_certification_or_full_coverage(document: Path) -> None:
    """Validated identifiers are evidence about a configuration, not a certificate."""
    text = document.read_text(encoding="utf-8")

    offenders: list[str] = []
    for pattern in COVERAGE_CLAIMS:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            lines = text.splitlines()
            line = text[: match.start()].count("\n") + 1
            # A denial is not a claim — "none of the four supports a claim of
            # certified compliance" has to be allowed to say the word it denies.
            # The window spans neighbouring lines because these documents are
            # hard-wrapped, and a negation routinely sits one line above the
            # word it governs.
            context = " ".join(lines[max(0, line - 2) : line + 1])
            if re.search(r"\b(no|none|not|never|cannot|nothing|refus)\w*\b", context, re.I):
                continue
            offenders.append(f"{document.name}:{line}: {lines[line - 1].strip()}")

    assert offenders == [], "coverage claimed rather than shown:\n" + "\n".join(offenders)


def test_exactly_one_framework_is_sourced() -> None:
    """The fact every document above is measured against.

    **Expected to change**, and to be changed deliberately: adding a catalog
    relaxes the identifier guard for that framework across every document at
    once, so whoever adds one should have to come here and say so.
    """
    assert sourced_frameworks() == frozenset({Framework.NIST})


def test_the_unsourced_three_are_named_somewhere() -> None:
    """Silence about CIS, STIG and ISO would read as coverage by omission.

    The problem statement names four frameworks. A repository that mapped one
    and simply stopped mentioning the others would leave a reader to assume,
    which is the failure this whole apparatus exists to prevent.
    """
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    for name in ("CIS", "STIG", "ISO/IEC 27001"):
        assert name in text, f"README does not say where {name} stands"


def test_the_identifier_guard_actually_fires() -> None:
    """A guardrail that cannot fail is not a guardrail."""
    cis_pattern = IDENTIFIER_PATTERNS[Framework.CIS][0]
    iso_pattern = IDENTIFIER_PATTERNS[Framework.ISO][0]

    assert re.search(cis_pattern, "see CIS 1.2.3 for details") is not None
    assert re.search(iso_pattern, "mapped to A.9.4.2") is not None
    assert re.search(cis_pattern, "the CIS Benchmarks are behind registration") is None
