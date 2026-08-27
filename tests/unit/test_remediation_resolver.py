"""Resolving and ordering remediation (P8).

Two halves, and they fail differently.

**Resolution** must never invent. Every path that does not find a snippet has to
return the same operator-facing sentence, so an empty library and an unidentified
platform produce identical advice rather than one of them looking like a fix that
merely failed to render.

**Ordering** must never strand an operator. A high-lockout-risk change applied
before its prerequisite is how someone loses access to their own device, and the
sequence is where that is prevented.

The ordering tests run entirely on constructed snippets. **They have never
ordered a real one**, because the shipped library is empty (decision D27), and no
claim beyond "correct on the cases tested" is made anywhere.
"""

from __future__ import annotations

import pytest

from api.models.enums import LockoutRisk
from api.remediate.errors import SnippetLibraryError
from api.remediate.library import SnippetLibrary, load_library
from api.remediate.resolver import (
    NO_REMEDIATION_STATEMENT,
    RemediationResolution,
    ResolutionOutcome,
    order_snippets,
    resolve,
)
from tests.fixtures.snippets import FIXTURE_OS_FAMILY, FIXTURE_VENDOR, snippet

EMPTY = SnippetLibrary(snippets=(), version="empty")


def library_of(*snippets) -> SnippetLibrary:
    return SnippetLibrary(snippets=tuple(snippets), version="test")


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_an_empty_library_yields_the_mandated_sentence() -> None:
    """The current outcome for every finding on every real device."""
    result = resolve(
        EMPTY, rule_id="NRK-TELNET-001", vendor="cisco", os_family="ios", actionable=True
    )

    assert result.outcome is ResolutionOutcome.NO_SNIPPET
    assert result.statement == NO_REMEDIATION_STATEMENT
    assert result.snippet is None
    assert not result.has_commands


def test_the_shipped_library_resolves_nothing_for_any_real_rule() -> None:
    """Stated over the real rulepack rather than a fixture, because it is the claim.

    Every rule NIRIKSHAK ships, against the platform it parses best, resolves to
    no command. That is the honest state of the project and it should fail
    visibly if it ever silently stops being true.
    """
    from api.comply.rulepacks import load_rulepack

    library = load_library()
    for rule in load_rulepack().rules:
        result = resolve(
            library, rule_id=rule.rule_id, vendor="cisco", os_family="ios", actionable=True
        )
        assert result.outcome is ResolutionOutcome.NO_SNIPPET
        assert result.statement == NO_REMEDIATION_STATEMENT


def test_an_unidentified_platform_does_not_guess() -> None:
    """A snippet key needs a vendor and an OS family. Without them, nothing.

    Falling back to "probably Cisco" is how a command for one platform is
    offered for another.
    """
    result = resolve(EMPTY, rule_id="NRK-TELNET-001", vendor=None, os_family=None, actionable=True)

    assert result.outcome is ResolutionOutcome.PLATFORM_UNKNOWN
    assert result.statement == NO_REMEDIATION_STATEMENT


@pytest.mark.parametrize(
    ("vendor", "os_family"),
    [(None, "ios"), ("cisco", None), ("", "ios"), ("cisco", "")],
)
def test_a_half_identified_platform_is_also_unknown(vendor, os_family) -> None:
    result = resolve(
        EMPTY, rule_id="NRK-TELNET-001", vendor=vendor, os_family=os_family, actionable=True
    )
    assert result.outcome is ResolutionOutcome.PLATFORM_UNKNOWN


def test_a_non_failing_finding_gets_no_remediation() -> None:
    """Having no fix and needing no fix are opposite messages.

    A report that renders them identically teaches the reader to ignore both.
    """
    result = resolve(
        EMPTY, rule_id="NRK-SSH-001", vendor="cisco", os_family="ios", actionable=False
    )

    assert result.outcome is ResolutionOutcome.NOT_ACTIONABLE
    assert result.statement != NO_REMEDIATION_STATEMENT
    assert "not a failure" in result.statement


def test_a_matching_snippet_resolves() -> None:
    library = library_of(snippet("alpha", rule_id="NRK-FIXTURE-001"))
    result = resolve(
        library,
        rule_id="NRK-FIXTURE-001",
        vendor=FIXTURE_VENDOR,
        os_family=FIXTURE_OS_FAMILY,
        actionable=True,
    )

    assert result.outcome is ResolutionOutcome.RESOLVED
    assert result.has_commands
    assert result.snippet is not None
    assert result.snippet.snippet_id == "alpha"


def test_a_resolved_statement_names_the_vetter_and_the_document() -> None:
    """Rule 4 — the operator should be able to see who checked this, and against what."""
    library = library_of(snippet("alpha", rule_id="NRK-FIXTURE-001"))
    result = resolve(
        library,
        rule_id="NRK-FIXTURE-001",
        vendor=FIXTURE_VENDOR,
        os_family=FIXTURE_OS_FAMILY,
        actionable=True,
    )

    assert result.snippet is not None
    assert result.snippet.vetted_by in result.statement
    assert result.snippet.reference in result.statement


def test_a_snippet_for_another_platform_does_not_resolve() -> None:
    library = library_of(snippet("alpha", rule_id="NRK-FIXTURE-001"))
    result = resolve(
        library, rule_id="NRK-FIXTURE-001", vendor="cisco", os_family="ios", actionable=True
    )

    assert result.outcome is ResolutionOutcome.NO_SNIPPET


# ---------------------------------------------------------------------------
# The resolution object cannot be malformed
# ---------------------------------------------------------------------------


def test_a_resolved_outcome_must_carry_its_snippet() -> None:
    with pytest.raises(ValueError, match="must carry the snippet"):
        RemediationResolution(outcome=ResolutionOutcome.RESOLVED)


def test_an_unresolved_outcome_must_not_carry_a_snippet() -> None:
    """Otherwise a template could render commands from a "no snippet" result."""
    with pytest.raises(ValueError, match="must not carry a snippet"):
        RemediationResolution(outcome=ResolutionOutcome.NO_SNIPPET, snippet=snippet("x"))


def test_every_resolution_carries_a_statement() -> None:
    """A caller cannot obtain one with no explanation attached."""
    for outcome in ResolutionOutcome:
        if outcome is ResolutionOutcome.RESOLVED:
            continue
        assert RemediationResolution(outcome=outcome).statement.strip()


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


def test_an_empty_set_orders_to_nothing() -> None:
    assert order_snippets(()) == ()


def test_a_dependency_is_applied_first() -> None:
    later = snippet("later", depends_on=("earlier",))
    earlier = snippet("earlier")

    ordered = [s.snippet_id for s in order_snippets((later, earlier))]
    assert ordered.index("earlier") < ordered.index("later")


def test_high_lockout_risk_is_applied_last() -> None:
    """The rule that matters.

    Disabling an insecure management protocol before its replacement is verified
    is precisely how an operator is stranded outside their own device.
    """
    risky = snippet("risky", lockout_risk=LockoutRisk.HIGH, notes="could strand the operator")
    mild = snippet("mild", lockout_risk=LockoutRisk.LOW)
    safe = snippet("safe", lockout_risk=LockoutRisk.NONE)

    ordered = [s.snippet_id for s in order_snippets((risky, mild, safe))]
    assert ordered == ["safe", "mild", "risky"]


def test_a_dependency_outranks_lockout_risk() -> None:
    """A prerequisite is applied first even when it is the riskier of the two.

    The dependency was declared by whoever vetted the snippet; the lockout
    ordering is our heuristic. The explicit statement wins.
    """
    risky_prerequisite = snippet(
        "prerequisite", lockout_risk=LockoutRisk.HIGH, notes="risky but required first"
    )
    dependent = snippet("dependent", depends_on=("prerequisite",), lockout_risk=LockoutRisk.NONE)

    ordered = [s.snippet_id for s in order_snippets((dependent, risky_prerequisite))]
    assert ordered == ["prerequisite", "dependent"]


def test_order_hint_breaks_a_tie() -> None:
    first = snippet("b-name", order_hint=10)
    second = snippet("a-name", order_hint=20)

    assert [s.snippet_id for s in order_snippets((second, first))] == ["b-name", "a-name"]


def test_the_snippet_id_makes_the_order_total() -> None:
    """Two runs over the same set must produce the same list, or a plan is not diffable."""
    a, b, c = snippet("aaa"), snippet("bbb"), snippet("ccc")

    assert order_snippets((c, a, b)) == order_snippets((b, c, a))
    assert [s.snippet_id for s in order_snippets((c, a, b))] == ["aaa", "bbb", "ccc"]


def test_a_dependency_outside_the_set_is_ignored() -> None:
    """A per-device plan resolves only the rules that failed on that device.

    A snippet may legitimately depend on one whose rule passed here. Refusing to
    order the set because of that would deny the operator a sequence over a
    prerequisite that is already satisfied.
    """
    lone = snippet("lone", depends_on=("applied-elsewhere",))
    assert [s.snippet_id for s in order_snippets((lone,))] == ["lone"]


def test_a_cycle_raises_rather_than_dropping_a_command() -> None:
    """A truncated ordering loses work silently.

    An operator counting six fixes and receiving five has no way to know which
    one is missing, or that anything is.
    """
    a = snippet("a", depends_on=("b",))
    b = snippet("b", depends_on=("a",))

    with pytest.raises(SnippetLibraryError, match="cycle"):
        order_snippets((a, b))


def test_every_supplied_snippet_appears_exactly_once() -> None:
    items = tuple(snippet(f"s{i}") for i in range(6))
    ordered = order_snippets(items)

    assert len(ordered) == len(items)
    assert {s.snippet_id for s in ordered} == {s.snippet_id for s in items}


def test_a_self_dependency_does_not_deadlock() -> None:
    """The contract already rejects one, so the orderer must not rely on that alone."""
    lone = snippet("lone")
    object.__setattr__(lone, "depends_on", ("lone",))

    assert [s.snippet_id for s in order_snippets((lone,))] == ["lone"]
