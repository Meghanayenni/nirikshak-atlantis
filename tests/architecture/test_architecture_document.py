"""`docs/architecture.md` must keep describing the system that exists.

An architecture document is the easiest file in a repository to leave behind. It
is written once, read by reviewers who cannot check it, and quietly becomes a
description of the previous release. This project already refuses that pattern
elsewhere — P8's report disclosures are computed from the findings rather than
typed, so a sentence stops being emitted the day its gap closes — and the same
discipline applies here.

So every structural claim the document makes is checked against the thing it
claims about: the packages that exist, the forbidden-edge count, the ADRs on
disk, and the defects that are genuinely open.

**These tests are read-only and deterministic.** They open exactly two files —
`docs/architecture.md` and, for the ADR index, the names of the files in
`docs/adr/`. They start nothing, write nothing, and read nothing under
`corpus/`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.architecture.test_import_rules import FORBIDDEN_EDGES

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = REPO_ROOT / "docs" / "architecture.md"
API_ROOT = REPO_ROOT / "api"
ADR_ROOT = REPO_ROOT / "docs" / "adr"


@pytest.fixture(scope="module")
def text() -> str:
    assert DOCUMENT.is_file(), "docs/architecture.md is missing"
    return DOCUMENT.read_text(encoding="utf-8")


def api_packages() -> set[str]:
    """Every package under `api/`, as it exists on disk."""
    return {
        path.name
        for path in API_ROOT.iterdir()
        if path.is_dir() and path.name != "__pycache__" and (path / "__init__.py").is_file()
    }


# ---------------------------------------------------------------------------
# Packages — named accurately, and completely
# ---------------------------------------------------------------------------


def test_every_package_the_document_names_exists(text: str) -> None:
    """A document naming a package that was renamed or removed is a map to nowhere."""
    named = {match.group(1) for match in re.finditer(r"`api/(\w+)/`", text)}
    missing = sorted(named - api_packages())
    assert missing == [], f"the document names packages that do not exist: {missing}"


def test_every_package_that_exists_is_represented(text: str) -> None:
    """The reverse, which is the direction that rots silently.

    A package added in a later phase and never written up leaves a reader with a
    map missing a room. The responsibilities table in §4 is the place it belongs.
    """
    unnamed = sorted(
        p for p in api_packages() if f"`{p}/`" not in text and f"`api/{p}/`" not in text
    )
    assert unnamed == [], f"packages exist but the document does not mention them: {unnamed}"


def test_the_module_count_is_accurate(text: str) -> None:
    """The document quotes a module count; it must be the real one."""
    actual = len(list(API_ROOT.rglob("*.py")))
    quoted = re.search(r"(\d+)\s+modules", text)
    assert quoted is not None, "the document should state how many modules api/ holds"
    assert int(quoted.group(1)) == actual, (
        f"the document says {quoted.group(1)} modules; api/ holds {actual}"
    )


# ---------------------------------------------------------------------------
# The forbidden-edge count — the number the whole Rule 1 argument rests on
# ---------------------------------------------------------------------------


def test_the_forbidden_edge_count_matches_the_constant(text: str) -> None:
    """Checked against `FORBIDDEN_EDGES` itself, not against a copy of it.

    This is the number a reviewer is most likely to quote back, and the one most
    likely to drift: every phase since P5 has added edges.
    """
    actual = len(FORBIDDEN_EDGES)
    quoted = {int(m) for m in re.findall(r"(\d+)\s+forbidden import edges", text)}
    quoted |= {int(m) for m in re.findall(r"\*\*(\d+)\s+forbidden import edges\*\*", text)}

    assert quoted, "the document should state the forbidden-edge count"
    assert quoted == {actual}, (
        f"the document quotes {sorted(quoted)} forbidden edges; FORBIDDEN_EDGES holds {actual}"
    )


def test_the_per_package_edge_counts_are_accurate(text: str) -> None:
    """The document breaks the edges down by source package."""
    actual: dict[str, int] = {}
    for importer, _, _ in FORBIDDEN_EDGES:
        actual[importer] = actual.get(importer, 0) + 1

    # Lines of the form "analyse 8 · audit 3 · comply 9 · ..."
    for package, count in re.findall(r"(\w+) (\d+) ·", text) + re.findall(r"· (\w+) (\d+)", text):
        if package in actual:
            assert actual[package] == int(count), (
                f"the document says {package} has {count} forbidden edges; it has {actual[package]}"
            )


# ---------------------------------------------------------------------------
# ADRs — every reference resolves
# ---------------------------------------------------------------------------


def test_every_adr_referenced_exists(text: str) -> None:
    """A citation to a document that is not there is worse than no citation."""
    on_disk = {path.name.split("-")[0] for path in ADR_ROOT.glob("*.md")}
    referenced = set(re.findall(r"ADR (\d{4})", text)) | set(
        re.findall(r"^\| (\d{4}) \|", text, re.M)
    )

    missing = sorted(referenced - on_disk)
    assert missing == [], f"the document cites ADRs that do not exist: {missing}"


def test_every_adr_on_disk_appears_in_the_index(text: str) -> None:
    """§10 is an index; an index missing an entry is a broken promise."""
    on_disk = {path.name.split("-")[0] for path in ADR_ROOT.glob("*.md")}
    indexed = set(re.findall(r"^\| (\d{4}) \|", text, re.M))

    missing = sorted(on_disk - indexed)
    assert missing == [], f"ADRs exist but are absent from the decision index: {missing}"


# ---------------------------------------------------------------------------
# The defect register — the claim most costly to get wrong
# ---------------------------------------------------------------------------

OPEN_DEFECTS = {"DEF-3", "DEF-8"}
"""The defects that are genuinely open at this commit.

Kept here as an explicit constant rather than parsed from prose: the point of the
test is to fail when reality and the document diverge, and both sides being
derived from the same text would make it pass vacuously.

Updating this set is a deliberate act. Closing DEF-3 or DEF-8 means changing a
contract or a measurement, and whoever does that should also have to say so here.
"""


def test_the_document_lists_every_defect(text: str) -> None:
    """DEF-1 through DEF-15 all appear in the register."""
    listed = set(re.findall(r"DEF-\d+", text))
    expected = {f"DEF-{n}" for n in range(1, 16)}
    missing = sorted(expected - listed, key=lambda d: int(d.split("-")[1]))
    assert missing == [], f"the defect register omits: {missing}"


def test_the_open_defects_are_marked_open(text: str) -> None:
    """DEF-3 and DEF-8 must be visibly open, not softened into 'deferred'.

    A register that reported an open defect as handled would be the one failure
    this document could commit that actually misleads somebody making a decision.
    """
    for defect in sorted(OPEN_DEFECTS):
        row = next((line for line in text.splitlines() if f"**{defect}**" in line), None)
        assert row is not None, f"{defect} should be emphasised as open in the register"
        assert "**OPEN**" in row, f"{defect} is open but its row does not say so: {row.strip()}"


def test_no_fixed_defect_is_claimed_open(text: str) -> None:
    """The converse. A fixed defect still listed as open would understate the work."""
    fixed = {f"DEF-{n}" for n in range(1, 16)} - OPEN_DEFECTS
    for line in text.splitlines():
        if "| **OPEN**" not in line and "**OPEN**" not in line:
            continue
        for defect in fixed:
            assert f"**{defect}**" not in line, (
                f"{defect} is fixed but appears in a row marked OPEN: {line.strip()}"
            )


def test_the_document_explains_why_the_open_defects_stay_open(text: str) -> None:
    """Recording a defect without its reason invites somebody to 'just fix it'."""
    assert "Why the two open defects remain open" in text
    assert "content hash" in text, "DEF-3's actual consequence should be stated"
    assert "exec-timeout 0 0" in text, "DEF-8's failing case should be stated"


# ---------------------------------------------------------------------------
# The document must not invent what the system refuses to claim
# ---------------------------------------------------------------------------


def test_no_framework_identifier_is_written(text: str) -> None:
    """Every rule ships `frameworks: []`.

    A plausible-looking `CIS 1.2.3` in an architecture document is exactly the
    failure `docs/CONTENT_POLICY.md` exists to prevent: it would be read as
    coverage by anyone who did not open `rules/`.
    """
    forbidden = [
        (r"CIS[\s-]?\d+\.\d+", "a CIS control identifier"),
        (r"\bAC-\d+", "a NIST SP 800-53 control identifier"),
        (r"\bV-\d{5,}", "a DISA STIG identifier"),
        (r"ISO\s*A\.\d+\.\d+", "an ISO/IEC 27001 control identifier"),
    ]
    for pattern, description in forbidden:
        assert re.search(pattern, text) is None, f"the document writes {description}"


def test_no_device_command_is_written(text: str) -> None:
    """The vetted snippet library is empty (Rule 4).

    A command in prose here would be a command attributed to nobody, checked
    against nothing, that somebody could paste into a production device on
    NIRIKSHAK's authority.
    """
    forbidden = ["transport input ssh", "configure terminal", "write memory", "no ip http server"]
    written = [command for command in forbidden if command in text]
    assert written == [], f"the document contains device commands: {written}"


def test_no_accuracy_figure_is_claimed(text: str) -> None:
    """No precision, recall, accuracy or detection rate belongs in this document.

    The harness reports measurements in `eval/reports/evaluation.txt`, where they
    carry their own caveats. A percentage quoted here would travel without them.
    """
    offenders: list[str] = []
    for line in text.splitlines():
        if not re.search(r"\d+(\.\d+)?\s*%", line):
            continue
        offenders.append(line.strip())
    assert offenders == [], f"the document quotes a percentage: {offenders}"


def test_the_document_states_what_is_not_claimed(text: str) -> None:
    """§7 is the section that keeps the rest of the document honest."""
    for phrase in [
        "does not currently claim",
        "the vetted snippet library is empty",
        "no access list in any split",
        "never been opened",
    ]:
        assert phrase.lower() in text.lower(), f"the document should state: {phrase!r}"


# ---------------------------------------------------------------------------
# The holdout
# ---------------------------------------------------------------------------


def test_the_document_records_the_sealed_holdout(text: str) -> None:
    """The single-use experiment, and the fact that it has not been spent.

    This test reads the document only. It does not open, hash or parse any file
    under `corpus/holdout/`, and neither may anything else in this module.
    """
    assert "PAN-OS" in text
    assert "never been opened" in text
    assert "UnsupportedSyntaxModeError" in text, (
        "the document should say why a held-out file cannot enter the pipeline"
    )


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_the_document_covers_every_required_section(text: str) -> None:
    """The scope P14 was approved to deliver."""
    for heading in [
        "The pipeline",
        "The six rules",
        "Packages and responsibilities",
        "One audit, end to end",
        "Two databases",
        "does not currently claim",
        "The sealed holdout",
        "Defect register",
        "Decision index",
    ]:
        assert heading.lower() in text.lower(), f"the document is missing a section on: {heading}"


def test_the_advisory_branch_is_described_as_advisory(text: str) -> None:
    """Rule 1, in the one place a reader forms their mental model of the system."""
    assert "advisory branch" in text.lower()
    assert "AI suggests. Rules decide." in text
    for phrase in ["never inside it", "not a verdict"]:
        assert phrase.lower() in text.lower(), f"the document should state: {phrase!r}"
