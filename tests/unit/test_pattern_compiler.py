"""The pattern compiler — boring on purpose (DEVELOPER_GUIDE.md §4, P11).

The tests here are mostly about what the compiler *refuses*. A generated regex
that is merely valid is not good enough: it has to be one an administrator can
read and check, because their confirmation enters a vendor pack permanently and
nothing downstream will question it again.
"""

from __future__ import annotations

import re

import pytest

from api.models.enums import CastType, PatternSource, TrainingOutcome
from api.models.training import Suggestion, TrainingExample
from api.train.compile import (
    CompileRequest,
    build_regex,
    build_scope,
    check_editable_pattern,
    compile_pattern,
    next_pattern_id,
)
from api.train.errors import NotConfirmedError, PatternCompileError, PatternRejectedError


def example(
    line: str = "logging host 192.0.2.10",
    *,
    field: str | None = "logging_hosts",
    outcome: TrainingOutcome = TrainingOutcome.ACCEPTED_RANK_1,
    confirmed_by: str = "alice",
    suggestions: tuple[Suggestion, ...] | None = None,
    audit_seq: int | None = 7,
) -> TrainingExample:
    if suggestions is None and outcome.accepted_rank is not None:
        suggestions = (Suggestion(rank=1, field=field or "x", raw_score=0.9),)
    return TrainingExample(
        example_id="trn-0001",
        vendor="arista",
        os_family="eos",
        raw_line_scrubbed=line,
        field=field,
        outcome=outcome,
        confirmed_by=confirmed_by,
        suggestions_shown=suggestions or (),
        audit_seq=audit_seq,
    )


# ---------------------------------------------------------------------------
# The generated regex
# ---------------------------------------------------------------------------


def test_the_generated_pattern_is_anchored_at_both_ends() -> None:
    """Anchored at `$` too, because the engine matches with `re.match`.

    Without a closing anchor, a pattern for `ip ssh version 2` also fires on
    `ip ssh version 2 extra` — which is a different statement, and which the
    hand-written Cisco pack lists as a negative example for exactly this reason.
    """
    pattern = build_regex("ip ssh version 2", 3)

    assert pattern.startswith("^")
    assert pattern.endswith("$")
    assert re.match(pattern, "ip ssh version 2") is not None
    assert re.match(pattern, "ip ssh version 2 extra") is None


def test_every_token_but_the_captured_one_is_escaped() -> None:
    """A dot in an address must not become "any character"."""
    pattern = build_regex("logging host 192.0.2.10", 2)

    assert pattern == r"^logging\s+host\s+(\S+)$"
    assert re.match(pattern, "logging host 192.0.2.10") is not None
    # The escaped literal cannot match a different word of the same length.
    assert re.match(build_regex("logging host 192.0.2.10", None), "loggingXhost 1") is None


def test_the_captured_token_is_the_one_the_administrator_named() -> None:
    captured = re.match(build_regex("ntp server 192.0.2.20", 2), "ntp server 192.0.2.20")
    assert captured is not None
    assert captured.group(1) == "192.0.2.20"


def test_tokens_are_joined_by_flexible_whitespace() -> None:
    """Alignment varies between exports; the meaning does not."""
    pattern = build_regex("logging host 192.0.2.10", 2)
    assert re.match(pattern, "logging  host   192.0.2.10") is not None


def test_a_single_token_line_cannot_be_all_capture() -> None:
    """`^(\\S+)$` matches every single-word line in the configuration."""
    with pytest.raises(PatternCompileError, match="every"):
        build_regex("shutdown", 0)


def test_a_blank_line_compiles_to_nothing() -> None:
    with pytest.raises(PatternCompileError, match="blank"):
        build_regex("   ", None)


def test_a_value_token_outside_the_line_is_refused() -> None:
    with pytest.raises(PatternCompileError, match="outside"):
        build_regex("logging host 192.0.2.10", 9)


def test_prose_is_refused_rather_than_compiled() -> None:
    """A forty-token line is a banner body or a certificate, not a command."""
    with pytest.raises(PatternCompileError, match="token limit"):
        build_regex(" ".join(["word"] * 40), 0)


# ---------------------------------------------------------------------------
# Scope (D9, ADR 0011)
# ---------------------------------------------------------------------------


def test_scope_defaults_to_the_literal_confirmed_header() -> None:
    """`line vty 0 4` and `line vty 0 15` are different scopes."""
    scope = build_scope(("line vty 0 4",))

    assert scope.block is not None
    assert re.fullmatch(scope.block[0], "line vty 0 4") is not None
    assert re.fullmatch(scope.block[0], "line vty 0 15") is None


def test_numeric_generalisation_is_an_explicit_opt_in() -> None:
    """Never assumed. The administrator asks for it and sees the result."""
    scope = build_scope(("line vty 0 4",), generalise_numeric=True)

    assert scope.block is not None
    assert re.fullmatch(scope.block[0], "line vty 0 4") is not None
    assert re.fullmatch(scope.block[0], "line vty 0 15") is not None


def test_a_root_level_line_scopes_to_root_only() -> None:
    assert build_scope(()).block is None


# ---------------------------------------------------------------------------
# Editing (D51)
# ---------------------------------------------------------------------------


def test_an_unanchored_edit_is_refused() -> None:
    with pytest.raises(PatternRejectedError, match="anchored"):
        check_editable_pattern(r"logging\s+host\s+(\S+)$")


def test_an_invalid_regex_edit_is_refused() -> None:
    with pytest.raises(PatternRejectedError, match="not a valid regex"):
        check_editable_pattern(r"^logging\s+host\s+((\S+)$")


@pytest.mark.parametrize("pattern", [r"^logging host (.*)$", r"^logging (.+)$", r"^(a+)+$"])
def test_unsafe_constructs_are_refused(pattern: str) -> None:
    """`.*` is not a pattern; it is the absence of one. A nested quantifier is
    a way to make a parser hang on a line somebody uploads."""
    with pytest.raises(PatternRejectedError, match="refused"):
        check_editable_pattern(pattern)


def test_an_edit_that_no_longer_matches_the_confirmed_line_is_refused() -> None:
    """The failure that would otherwise be silent.

    A hand-edited regex which stops matching the line it was confirmed from has
    stopped meaning what the human agreed to, and nothing downstream would ever
    notice — the pack would simply produce no field.
    """
    with pytest.raises(PatternRejectedError, match="does not match the line"):
        compile_pattern(
            example(),
            CompileRequest(value_token=2, cast=CastType.LIST),
            pattern_override=r"^ntp\s+server\s+(\S+)$",
        )


def test_a_valid_edit_is_accepted_and_marked() -> None:
    """Editing is a requirement, not a concession (DEVELOPER_GUIDE.md §4)."""
    pattern = compile_pattern(
        example(),
        CompileRequest(value_token=2, cast=CastType.LIST),
        pattern_override=r"^logging\s+host\s+(\S+)\s*$",
    )
    assert pattern.match.pattern == r"^logging\s+host\s+(\S+)\s*$"
    assert pattern.self_check() == []


# ---------------------------------------------------------------------------
# Nothing compiles without a human
# ---------------------------------------------------------------------------


def test_a_rejection_compiles_to_nothing() -> None:
    """ "Not security relevant" is a real decision, and not a mapping."""
    with pytest.raises(NotConfirmedError, match="rejected"):
        compile_pattern(
            example(field=None, outcome=TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT),
            CompileRequest(value_token=2),
        )


def test_a_decision_naming_no_administrator_compiles_to_nothing() -> None:
    """Trust originates in a person. A blank name is not a person."""
    with pytest.raises(NotConfirmedError, match="names no administrator"):
        compile_pattern(example(confirmed_by="   "), CompileRequest(value_token=2))


def test_a_field_outside_the_canonical_schema_is_refused() -> None:
    """An administrator maps syntax onto the schema; they do not extend it.

    Adding a canonical field requires a pattern verifiable against a real corpus
    file (DEVELOPER_GUIDE.md §3) — a different decision, made by different people, with a
    different kind of evidence behind it.
    """
    with pytest.raises(PatternCompileError, match="not a canonical security field"):
        compile_pattern(example(field="favourite_colour"), CompileRequest(value_token=2))


def test_a_pattern_that_captures_nothing_and_asserts_nothing_is_refused() -> None:
    with pytest.raises(PatternCompileError, match="neither"):
        compile_pattern(example(), CompileRequest(value_token=None, literal_value=None))


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_a_compiled_pattern_keeps_its_decision_and_audit_sequence() -> None:
    """Required by the P11 provenance rule: a mapping traces to a person.

    Without this a pack would say what it reads and be unable to say who decided
    that it should — and the audit chain's record of the confirmation would have
    nothing pointing at it.
    """
    pattern = compile_pattern(example(), CompileRequest(value_token=2, cast=CastType.LIST))

    assert pattern.source is PatternSource.ADMIN_TRAINED
    assert pattern.provenance is not None
    assert pattern.provenance.training_example_id == "trn-0001"
    assert pattern.provenance.audit_seq == 7
    assert pattern.provenance.suggestion_rank_accepted == 1


def test_a_compiled_pattern_retains_the_line_it_came_from() -> None:
    """The contract requires it, and re-validation depends on it."""
    pattern = compile_pattern(example(), CompileRequest(value_token=2, cast=CastType.LIST))
    assert pattern.examples == ("logging host 192.0.2.10",)


def test_a_compiled_pattern_carries_no_framework_or_remediation() -> None:
    """A confirmation teaches parsing. It does not assert compliance content.

    Framework identifiers need a benchmark edition somebody read; remediation
    commands need a vetted snippet. Neither is a thing an administrator creates
    by confirming what a line means, and a compiled pattern has nowhere to put
    one.
    """
    pattern = compile_pattern(example(), CompileRequest(value_token=2, cast=CastType.LIST))
    dumped = pattern.model_dump()

    assert "frameworks" not in dumped
    assert "remediation" not in dumped
    assert "default" not in dumped
    assert "capability" not in dumped


def test_a_corrected_outcome_records_no_accepted_rank() -> None:
    """CORRECTED means the administrator overrode every suggestion shown."""
    pattern = compile_pattern(
        example(outcome=TrainingOutcome.CORRECTED, suggestions=()),
        CompileRequest(value_token=2, cast=CastType.LIST),
    )
    assert pattern.provenance is not None
    assert pattern.provenance.suggestion_rank_accepted is None


def test_pattern_ids_do_not_collide_with_existing_ones() -> None:
    assert next_pattern_id("ntp_servers", ()) == "p-ntp-servers-admin-001"
    assert next_pattern_id("ntp_servers", ("p-ntp-servers-admin-001",)) == "p-ntp-servers-admin-002"


def test_a_generated_id_says_it_was_admin_trained() -> None:
    """Readable provenance: a person scanning a pack sees which lines were learned."""
    assert "-admin-" in next_pattern_id("ssh_version", ())
