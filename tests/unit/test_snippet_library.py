"""The vetted snippet library: loading, validating, and refusing (P8).

Rule 4 says commands come from a vetted library and nowhere else. That makes the
loader a safety component, not plumbing: everything it lets through becomes text
an operator may paste into a production device.

So the assertions here are mostly about what it **refuses**. A loader that
accepts a snippet with no vetter, or one whose dependency does not exist, has
quietly widened the set of things that can reach an operator.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from api.models.enums import LockoutRisk
from api.remediate.errors import SnippetLibraryError, SnippetLoadError
from api.remediate.library import (
    EMPTY_LIBRARY_VERSION,
    check_consistency,
    compute_version,
    load_library,
    load_snippet,
    snippet_files,
)
from tests.fixtures.snippets import (
    FIXTURE_OS_FAMILY,
    FIXTURE_VENDOR,
    NO_DOCUMENT,
    NOT_VETTED,
    SNIPPET_YAML,
    snippet,
)


def write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# The shipped library
# ---------------------------------------------------------------------------


def test_the_shipped_library_is_empty_and_says_so() -> None:
    """D27 — the honest state while no vendor documentation has been sourced."""
    library = load_library()

    assert library.is_empty
    assert library.snippets == ()
    assert library.version == EMPTY_LIBRARY_VERSION


def test_an_empty_library_is_not_an_error() -> None:
    """Loading nothing must succeed. Resolving nothing is a valid answer."""
    library = load_library()
    assert library.lookup("cisco", "ios", "NRK-TELNET-001") is None


def test_an_empty_library_does_not_report_a_hash_as_its_version() -> None:
    """A hash of nothing looks exactly like a hash of something.

    A report footer reading `library e3b0c442` would suggest content that is not
    there, in the one place a reader looks to find out what it resolved against.
    """
    assert compute_version([]) == EMPTY_LIBRARY_VERSION
    assert EMPTY_LIBRARY_VERSION.isalpha()


# ---------------------------------------------------------------------------
# Loading one file
# ---------------------------------------------------------------------------


def test_a_well_formed_snippet_loads(tmp_path: Path) -> None:
    loaded = load_snippet(write(tmp_path, "alpha.yaml", SNIPPET_YAML))

    assert loaded.snippet_id == "fixture-alpha"
    assert loaded.commands == ("fixture-command-alpha",)
    assert loaded.key == (FIXTURE_VENDOR, FIXTURE_OS_FAMILY, "NRK-FIXTURE-001")


def test_a_snippet_without_a_vetter_is_refused(tmp_path: Path) -> None:
    """Rule 4, at the gate. An unvetted snippet is not a snippet."""
    body = SNIPPET_YAML.replace(f"vetted_by: {NOT_VETTED}\n", "")
    with pytest.raises(SnippetLoadError, match="vetted_by"):
        load_snippet(write(tmp_path, "no-vetter.yaml", body))


def test_a_snippet_without_a_citation_is_refused(tmp_path: Path) -> None:
    """CONTENT_POLICY.md — a command nobody can re-verify is a command from memory."""
    body = SNIPPET_YAML.replace(f"reference: {NO_DOCUMENT}\n", "")
    with pytest.raises(SnippetLoadError, match="reference"):
        load_snippet(write(tmp_path, "no-citation.yaml", body))


def test_a_snippet_with_no_commands_is_refused(tmp_path: Path) -> None:
    body = SNIPPET_YAML.replace("  - fixture-command-alpha\n", "")
    with pytest.raises(SnippetLoadError):
        load_snippet(write(tmp_path, "no-commands.yaml", body))


def test_an_unknown_field_is_refused(tmp_path: Path) -> None:
    """The schema forbids extras, so a typo cannot become a silently ignored field.

    `rollbcak:` accepted and dropped would hand an operator a service-affecting
    change with no way back, and nothing would have said so.
    """
    with pytest.raises(SnippetLoadError, match="schema violation"):
        load_snippet(write(tmp_path, "typo.yaml", SNIPPET_YAML + "rollbcak:\n  - undo\n"))


def test_invalid_yaml_names_the_file(tmp_path: Path) -> None:
    with pytest.raises(SnippetLoadError, match="broken.yaml"):
        load_snippet(write(tmp_path, "broken.yaml", "commands: [unclosed\n"))


def test_a_non_mapping_is_refused(tmp_path: Path) -> None:
    with pytest.raises(SnippetLoadError, match="mapping"):
        load_snippet(write(tmp_path, "list.yaml", "- one\n- two\n"))


def test_a_service_affecting_snippet_needs_a_rollback(tmp_path: Path) -> None:
    """The contract's own invariant, reached through the loader.

    A change the operator cannot undo is a trap, and the moment they discover it
    is the moment they most need the way back.
    """
    body = SNIPPET_YAML + "impact:\n  service_affecting: true\n"
    with pytest.raises(SnippetLoadError, match="rollback"):
        load_snippet(write(tmp_path, "no-way-back.yaml", body))


def test_a_high_lockout_risk_must_explain_itself(tmp_path: Path) -> None:
    body = SNIPPET_YAML + "impact:\n  lockout_risk: high\n"
    with pytest.raises(SnippetLoadError):
        load_snippet(write(tmp_path, "silent-lockout.yaml", body))


# ---------------------------------------------------------------------------
# Consistency across the set
# ---------------------------------------------------------------------------


def test_duplicate_ids_are_a_library_problem() -> None:
    problems = check_consistency([snippet("dup"), snippet("dup")])
    assert any("duplicate" in p for p in problems)


def test_a_dependency_on_a_missing_snippet_is_reported() -> None:
    """Silently ignoring it would produce a plan missing a prerequisite step."""
    problems = check_consistency([snippet("beta", depends_on=("absent",))])
    assert any("absent" in p and "not in the library" in p for p in problems)


def test_a_dependency_cycle_is_reported() -> None:
    problems = check_consistency([snippet("a", depends_on=("b",)), snippet("b", depends_on=("a",))])
    assert any("cycle" in p for p in problems)


def test_a_clean_set_reports_nothing() -> None:
    assert check_consistency([snippet("a"), snippet("b", depends_on=("a",))]) == []


def test_loading_an_inconsistent_directory_raises(tmp_path: Path) -> None:
    write(tmp_path, "one.yaml", SNIPPET_YAML)
    write(tmp_path, "two.yaml", SNIPPET_YAML.replace("fixture-alpha", "fixture-alpha"))

    with pytest.raises(SnippetLibraryError, match="duplicate"):
        load_library(tmp_path)


# ---------------------------------------------------------------------------
# Discovery and versioning
# ---------------------------------------------------------------------------


def test_the_schema_directory_is_not_searched_for_snippets() -> None:
    """`schema/` describes snippets; it is not one."""
    assert all("schema" not in p.parts for p in snippet_files())


def test_discovery_is_ordered(tmp_path: Path) -> None:
    """A library must load identically on every machine, or its version drifts."""
    for name in ("zulu.yaml", "alpha.yaml", "mike.yaml"):
        write(tmp_path, name, SNIPPET_YAML.replace("fixture-alpha", f"fixture-{name[:4]}"))

    found = [p.name for p in snippet_files(tmp_path)]
    assert found == sorted(found)


def test_the_version_changes_when_content_changes(tmp_path: Path) -> None:
    """The report footer records this so two reports can be compared."""
    path = write(tmp_path, "alpha.yaml", SNIPPET_YAML)
    before = compute_version([path])

    path.write_text(SNIPPET_YAML.replace("alpha", "revised"), encoding="utf-8")
    assert compute_version([path]) != before


def test_the_version_is_stable_for_unchanged_content(tmp_path: Path) -> None:
    path = write(tmp_path, "alpha.yaml", SNIPPET_YAML)
    assert compute_version([path]) == compute_version([path])


def test_a_missing_directory_yields_no_snippets(tmp_path: Path) -> None:
    assert snippet_files(tmp_path / "absent") == []
    assert load_library(tmp_path / "absent").is_empty


# ---------------------------------------------------------------------------
# Lookup
# ---------------------------------------------------------------------------


def test_lookup_matches_on_all_three_key_parts(tmp_path: Path) -> None:
    write(tmp_path, "alpha.yaml", SNIPPET_YAML)
    library = load_library(tmp_path)

    assert library.lookup(FIXTURE_VENDOR, FIXTURE_OS_FAMILY, "NRK-FIXTURE-001") is not None
    assert library.lookup("other-vendor", FIXTURE_OS_FAMILY, "NRK-FIXTURE-001") is None
    assert library.lookup(FIXTURE_VENDOR, "other-os", "NRK-FIXTURE-001") is None
    assert library.lookup(FIXTURE_VENDOR, FIXTURE_OS_FAMILY, "NRK-OTHER-001") is None


def test_lookup_never_falls_back_to_a_near_match(tmp_path: Path) -> None:
    """Close enough is how a command for one platform is pasted into another.

    There is no fuzzy match, no vendor family fallback and no generic snippet.
    A miss is a complete and final answer.
    """
    write(tmp_path, "alpha.yaml", SNIPPET_YAML)
    library = load_library(tmp_path)

    assert library.lookup(FIXTURE_VENDOR.upper(), FIXTURE_OS_FAMILY, "NRK-FIXTURE-001") is None
    assert library.lookup(FIXTURE_VENDOR, FIXTURE_OS_FAMILY + "-xe", "NRK-FIXTURE-001") is None


def test_the_library_cannot_be_added_to_after_loading(tmp_path: Path) -> None:
    """A snippet enters by being a file that passed every gate, or not at all."""
    library = load_library(tmp_path)

    assert not hasattr(library, "add")
    assert not hasattr(library, "register")
    with pytest.raises(dataclasses.FrozenInstanceError):
        library.snippets = (snippet("smuggled"),)  # type: ignore[misc]


def test_by_id_finds_a_loaded_snippet(tmp_path: Path) -> None:
    write(tmp_path, "alpha.yaml", SNIPPET_YAML)
    library = load_library(tmp_path)

    assert library.by_id("fixture-alpha") is not None
    assert library.by_id("never-written") is None


def test_the_lockout_risk_property_reads_the_impact_block() -> None:
    assert snippet("risky", lockout_risk=LockoutRisk.HIGH).is_lockout_risk
    assert not snippet("safe").is_lockout_risk
