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
from dataclasses import dataclass
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

OPEN_DEFECTS = {"DEF-3", "DEF-16", "DEF-18", "DEF-19"}
"""The defects that are genuinely open at this commit.

Kept as an explicit constant rather than parsed from the document: a test whose
expectation and subject are both derived from the same prose passes vacuously.
Updating this set is a deliberate act, and whoever closes a defect should have
to say so here.

**It went stale anyway.** It read `{"DEF-3", "DEF-8"}` while DEF-16, DEF-17 and
DEF-18 existed, so two open defects were unguarded and one fixed defect was
still listed. A hand-maintained list beside a document drifts from it; the fix
is not a more careful list but
`test_the_register_and_the_guard_agree`, which fails the moment they disagree.
"""


@dataclass(frozen=True)
class DefectRow:
    """One row of the register table in `docs/architecture.md` §9."""

    number: int
    identifier: str
    description: str
    status: str

    @property
    def is_open(self) -> bool:
        return "OPEN" in self.status.upper()


def _register_rows(text: str) -> list[DefectRow]:
    """Parse the defect register out of the document.

    The table is the source of truth for *what the document says*; the constant
    above is the source of truth for *what is true*. Keeping them separate is
    what lets a test compare them.
    """
    rows: list[DefectRow] = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) < 3:
            continue
        identifier = cells[0].replace("*", "").strip()
        found = re.fullmatch(r"DEF-(\d+)", identifier)
        if found is None:
            continue
        rows.append(
            DefectRow(
                number=int(found.group(1)),
                identifier=identifier,
                description=cells[1],
                status=cells[2],
            )
        )
    return rows


def test_the_register_is_contiguous_from_one(text: str) -> None:
    """Every defect number up to the highest issued has a row.

    Replaces a hardcoded `range(1, 16)`, which stopped covering DEF-16, -17 and
    -18 the moment they were opened and said nothing about it. The bound is now
    the register's own highest row, so a numbering gap fails rather than a
    number somebody forgot to raise.
    """
    rows = _register_rows(text)
    assert rows, "the defect register has no parseable rows"

    numbers = {row.number for row in rows}
    expected = set(range(1, max(numbers) + 1))
    missing = sorted(expected - numbers)

    assert missing == [], f"the defect register omits: {[f'DEF-{n}' for n in missing]}"


def test_no_defect_is_listed_twice(text: str) -> None:
    """Two rows for one defect is how a register starts contradicting itself."""
    numbers = [row.number for row in _register_rows(text)]
    duplicates = sorted({n for n in numbers if numbers.count(n) > 1})

    assert duplicates == [], f"duplicated rows: {[f'DEF-{n}' for n in duplicates]}"


def test_the_register_and_the_guard_agree(text: str) -> None:
    """**The guard against this guard going stale.**

    `OPEN_DEFECTS` is maintained by hand so the comparison is not vacuous, and
    the document is maintained by hand because it is prose. Either can drift.
    This fails the moment they disagree, in whichever direction — which is the
    only arrangement in which the hand-kept list cannot quietly rot.
    """
    in_document = {row.identifier for row in _register_rows(text) if row.is_open}

    unguarded = sorted(in_document - OPEN_DEFECTS)
    overstated = sorted(OPEN_DEFECTS - in_document)

    assert unguarded == [], (
        f"the register marks {unguarded} OPEN and OPEN_DEFECTS does not list them. "
        "Every open defect must be covered by the guard, or opening one silently "
        "escapes it."
    )
    assert overstated == [], (
        f"OPEN_DEFECTS lists {overstated} but the register does not mark them open. "
        "Either the defect was fixed and the constant was not updated, or the row "
        "was softened without the fix."
    )


def test_the_open_defects_are_marked_open(text: str) -> None:
    """An open defect must be visibly open, not softened into 'deferred'.

    A register that reported an open defect as handled would be the one failure
    this document could commit that actually misleads somebody making a decision.
    """
    rows = {row.identifier: row for row in _register_rows(text)}
    for defect in sorted(OPEN_DEFECTS):
        row = rows.get(defect)
        assert row is not None, f"{defect} has no row in the register"
        assert row.is_open, f"{defect} is open but its row says {row.status!r}"
        assert f"**{defect}**" in text, f"{defect} should be emphasised as open"


def test_no_fixed_defect_is_claimed_open(text: str) -> None:
    """The converse. A fixed defect still listed as open would understate the work.

    The bound is the register's own contents rather than a literal, which is what
    the previous `range(1, 19)` had to be raised by hand and was not.
    """
    for row in _register_rows(text):
        if row.identifier in OPEN_DEFECTS:
            continue
        assert not row.is_open, f"{row.identifier} is fixed but its row says {row.status!r}"


def test_the_headline_count_matches_the_rows(text: str) -> None:
    """The sentence above the table is a claim too, and it is the one people read.

    "Eighteen numbered defects. Three are open." — both halves are checkable
    against the rows beneath them, and a table edited without the sentence is
    exactly the drift this section keeps producing.
    """
    rows = _register_rows(text)
    spelled = {
        1: "One",
        2: "Two",
        3: "Three",
        4: "Four",
        5: "Five",
        6: "Six",
        7: "Seven",
        8: "Eight",
        9: "Nine",
        10: "Ten",
    }
    open_count = sum(1 for row in rows if row.is_open)

    assert f"{len(rows)} numbered defects" in text or _spelled_total(len(rows)) in text, (
        f"the register holds {len(rows)} rows and the headline does not say so"
    )
    phrase = f"**{spelled.get(open_count, open_count)} are open.**"
    assert phrase in text or f"**{open_count} are open.**" in text, (
        f"{open_count} defects are open and the headline does not say so"
    )


def _spelled_total(count: int) -> str:
    words = {
        15: "Fifteen",
        16: "Sixteen",
        17: "Seventeen",
        18: "Eighteen",
        19: "Nineteen",
        20: "Twenty",
    }
    return f"{words.get(count, count)} numbered defects"


def test_the_document_explains_why_the_open_defects_stay_open(text: str) -> None:
    """Recording a defect without its reason invites somebody to 'just fix it'."""
    assert "Why the remaining defects are open" in text
    assert "content hash" in text, "DEF-3's actual consequence should be stated"
    assert "exec-timeout 0 0" in text, "DEF-8's failing case should stay stated"
    assert "cannot name the pack" in text, "DEF-18's consequence should be stated"
    assert "corpus split" in text, "DEF-16's consequence should be stated"


# ---------------------------------------------------------------------------
# The document must not invent what the system refuses to claim
# ---------------------------------------------------------------------------


def test_no_unsourced_framework_identifier_is_written(text: str) -> None:
    r"""An identifier may appear only for a framework with a sourced catalog.

    A plausible-looking `CIS 1.2.3` in an architecture document is exactly the
    failure `docs/CONTENT_POLICY.md` exists to prevent: it would be read as
    coverage by anyone who did not open `rules/`.

    Until P17 no framework had a catalog and the answer was "none, ever". NIST
    now does — its identifiers are validated against a content-addressed OSCAL
    edition (ADR 0035) — so the guard keys off `sourced_frameworks()` rather
    than a fixed list. It re-tightens by itself if a catalog is withdrawn, and
    relaxes only when one is added, which is the property a hand-maintained
    list would lose on its first edit.
    """
    from api.comply.frameworks import sourced_frameworks
    from api.models.enums import Framework

    patterns = {
        Framework.CIS: (r"CIS[\s-]?\d+\.\d+", "a CIS recommendation number"),
        Framework.NIST: (r"\bAC-\d+", "a NIST SP 800-53 control identifier"),
        Framework.STIG: (r"\bV-\d{5,}", "a DISA STIG identifier"),
        Framework.ISO: (r"ISO\s*A\.\d+\.\d+", "an ISO/IEC 27001 control identifier"),
    }
    sourced = sourced_frameworks()

    for framework, (pattern, description) in patterns.items():
        if framework in sourced:
            continue
        assert re.search(pattern, text) is None, (
            f"the document writes {description}, and no {framework.value} catalog has been sourced"
        )


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
        # Was "the vetted snippet library is empty" until the library was
        # sourced. The document must still account for what left this section,
        # so the phrase is replaced rather than dropped: a claim quietly
        # disappearing from §7 is exactly what §7 exists to prevent.
        "shipped empty until every entry could name",
        # Was "no access list in any split", true until P16 put access lists in
        # the corpus and a parser behind them. The claim §7 must still carry is
        # the one that replaced it: the analyser runs, on data this team wrote.
        "still measured on synthetic data written by this team",
        # Was "never been opened" — false: two integrity guards read the
        # held-out files on every run. The true claim is narrower and checked.
        "never been parsed",
    ]:
        assert phrase.lower() in text.lower(), f"the document should state: {phrase!r}"


# ---------------------------------------------------------------------------
# The holdout
# ---------------------------------------------------------------------------


def test_the_document_records_the_sealed_holdout(text: str) -> None:
    """The single-use experiment, and the fact that it has not been spent.

    This test reads the document only. It does not open, hash or parse any file
    under `corpus/holdout/`, and neither may anything else in this module.

    Until the pre-submission audit it asserted "never been opened", and so
    defended a sentence two integrity guards contradicted on every run. It now
    asserts the narrower true claim, and that the document names both guards
    that do read the files — so the disclosure cannot quietly disappear.
    """
    assert "PAN-OS" in text
    assert "never been parsed" in text
    assert "never been opened" not in text, "the files are read by two guards; say so"
    assert "test_every_checksum_matches" in text
    assert "tests/integration/test_corpus_policy.py" in text
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


# ---------------------------------------------------------------------------
# The register guard must be able to fail
# ---------------------------------------------------------------------------


DOCTORED = """
| # | Description | Status |
| --- | --- | --- |
| DEF-1 | something | Fixed (ADR 0001) |
| **DEF-2** | **something open** | **OPEN** |
| DEF-4 | a gap where DEF-3 should be | Fixed (ADR 0002) |
| DEF-4 | the same number twice | Fixed (ADR 0003) |
"""


def test_the_register_parser_reads_both_row_styles() -> None:
    """Fixed rows are plain; open rows are bold. Both must parse.

    If `_register_rows` silently skipped the emphasised rows, every test above
    would pass while covering nothing — the failure mode `test_detector_actually_fires`
    exists for elsewhere in this suite.
    """
    rows = {row.identifier: row for row in _register_rows(DOCTORED)}

    assert set(rows) == {"DEF-1", "DEF-2", "DEF-4"}
    assert rows["DEF-2"].is_open
    assert not rows["DEF-1"].is_open


def test_the_contiguity_check_actually_fires() -> None:
    """DEF-3 is missing from the doctored register and must be caught."""
    numbers = {row.number for row in _register_rows(DOCTORED)}
    missing = set(range(1, max(numbers) + 1)) - numbers

    assert missing == {3}, "a numbering gap would go unnoticed"


def test_the_duplicate_check_actually_fires() -> None:
    numbers = [row.number for row in _register_rows(DOCTORED)]

    assert numbers.count(4) == 2, "a repeated defect number would go unnoticed"


def test_the_reconciliation_actually_fires() -> None:
    """A defect open in the document and absent from the guard is caught.

    This is the exact drift that happened: `OPEN_DEFECTS` read
    `{"DEF-3", "DEF-8"}` while DEF-16 and DEF-18 were open in the register, so
    two open defects were unguarded for three phases.
    """
    in_document = {row.identifier for row in _register_rows(DOCTORED) if row.is_open}
    pretend_guard = {"DEF-1"}

    assert in_document - pretend_guard == {"DEF-2"}, "an unguarded open defect must show up"
    assert pretend_guard - in_document == {"DEF-1"}, "a stale guard entry must show up"


def test_an_open_row_with_a_trailing_note_still_reads_as_open() -> None:
    """DEF-18's row is `**OPEN** — evidence secured (ADR 0031)`.

    A status cell that qualifies itself must not read as closed; softening a row
    into prose is precisely how an open defect would disappear.
    """
    row = next(
        r for r in _register_rows("| **DEF-9** | **x** | **OPEN** — mitigated, not closed |")
    )

    assert row.is_open
