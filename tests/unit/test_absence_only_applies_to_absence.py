"""Abstaining is not the same as being absent (P5 regression).

The absence table answers one question: *the directive is missing — what does
that mean on this platform?* It is only entitled to run when the directive really
is missing, which the parser signals with `NO_MATCH`.

Every other abstention reason means the directive **is** in the configuration and
something else went wrong. `CONFLICTING_EVIDENCE` is the dangerous one: two lines
disagree, so the control has been explicitly set — contradictorily. Running the
absence table over it does three wrong things at once:

  1. asserts the platform's documented default for a control the operator
     configured, which is a claim contradicted by the file itself;
  2. marks the field determinable, so a compliance rule can PASS on it;
  3. discards the citations that show the contradiction — the only thing that
     would let an operator see what could not be resolved.

This was a real defect in the first cut of `_resolve_absences`, caught in review
before commit. These tests exist so it cannot return.
"""

from __future__ import annotations

from typing import Any

import pytest

from api.models.config_tree import ConfigTree
from api.models.enums import (
    CastType,
    ConfidenceMethod,
    FieldState,
    MatchType,
    SourceType,
    SyntaxMode,
    UnknownReason,
)
from api.models.evidence import Evidence
from api.models.field import Field
from api.models.pack import CaptureSpec, MatchSpec, PatternDef, PatternScope, VendorPack
from api.models.parsing import ParseResult
from api.normalise.service import build_csm
from tests.fixtures.platform import sourced_capability, sourced_default

FIELD = "telnet_enabled"


def evidence(line: int, text: str) -> Evidence:
    return Evidence(
        file_id="f1",
        file_path="rtr.cfg",
        line_start=line,
        line_end=line,
        raw_line=text,
        source_type=SourceType.CLI,
    )


def pack_with_platform_knowledge() -> VendorPack:
    """A pack that WOULD resolve an absent field to a default, if asked."""
    return VendorPack(
        vendor="testvendor",
        os_family="testos",
        pack_version="1.0.0",
        patterns=(
            PatternDef(
                id="p-001",
                field=FIELD,
                scope=PatternScope(),
                match=MatchSpec(type=MatchType.REGEX, pattern="^transport input telnet$"),
                capture=CaptureSpec(value="true", cast=CastType.BOOL),
            ),
        ),
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(sourced_default(FIELD, False),),
    )


def result_with(field: Field[Any]) -> ParseResult:
    return ParseResult(
        file_id="f1",
        file_path="rtr.cfg",
        vendor="testvendor",
        os_family="testos",
        pack_version="1.0.0",
        tree=ConfigTree(
            file_id="f1",
            file_path="rtr.cfg",
            syntax_mode=SyntaxMode.INDENT,
            roots=(),
            nodes={},
            unplaced=(),
            source_line_count=0,
        ),
        fields={FIELD: field},
    )


def conflicted() -> Field[Any]:
    """What P4 produces when two lines disagree: UNKNOWN, both citations kept."""
    return Field[Any](
        value=None,
        state=FieldState.UNKNOWN,
        confidence=0.0,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
        unknown_reason=UnknownReason.CONFLICTING_EVIDENCE,
        evidence=(evidence(10, "transport input telnet"), evidence(22, "transport input ssh")),
    )


# ---------------------------------------------------------------------------
# The regression
# ---------------------------------------------------------------------------


def test_a_conflicted_field_does_not_get_the_platform_default() -> None:
    """The control IS configured. Asserting a default would contradict the file."""
    csm = build_csm(result_with(conflicted()), pack_with_platform_knowledge(), device_id="d1")
    field = csm.fields[FIELD]

    assert field.state is FieldState.UNKNOWN, (
        "a contradictory configuration was resolved to the platform default, "
        "asserting a value the file itself contradicts"
    )
    assert field.value is None
    assert field.state is not FieldState.ABSENT_DEFAULT


def test_a_conflicted_field_stays_undeterminable() -> None:
    """Rule 3 — a contradiction must not become something a rule can PASS on."""
    csm = build_csm(result_with(conflicted()), pack_with_platform_knowledge(), device_id="d1")

    assert not csm.fields[FIELD].is_determinable
    assert csm.determinable_fields() == {}


def test_a_conflicted_field_keeps_every_citation() -> None:
    """Rule 2 — the citations are the only way to see what could not be resolved."""
    csm = build_csm(result_with(conflicted()), pack_with_platform_knowledge(), device_id="d1")
    field = csm.fields[FIELD]

    assert len(field.evidence) == 2
    assert [e.line_start for e in field.evidence] == [10, 22]


def test_a_conflicted_field_keeps_its_reason() -> None:
    """'We could not read this' and 'this is absent' are different findings."""
    csm = build_csm(result_with(conflicted()), pack_with_platform_knowledge(), device_id="d1")

    assert csm.fields[FIELD].unknown_reason is UnknownReason.CONFLICTING_EVIDENCE


def test_a_conflicted_field_is_passed_through_untouched() -> None:
    """Frozen and by reference, so 'unchanged' is literal."""
    original = conflicted()
    csm = build_csm(result_with(original), pack_with_platform_knowledge(), device_id="d1")

    assert csm.fields[FIELD] is original


# ---------------------------------------------------------------------------
# ...while a genuinely absent field still resolves
# ---------------------------------------------------------------------------


def test_a_no_match_field_still_gets_the_absence_table() -> None:
    """The fix must not disable the feature it guards."""
    absent = Field[Any].unknown(
        UnknownReason.NO_MATCH,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
    )
    csm = build_csm(result_with(absent), pack_with_platform_knowledge(), device_id="d1")
    field = csm.fields[FIELD]

    assert field.state is FieldState.ABSENT_DEFAULT
    assert field.value is False
    assert field.confidence_method is ConfidenceMethod.PLATFORM_DEFAULT


@pytest.mark.parametrize(
    "reason",
    [
        UnknownReason.CONFLICTING_EVIDENCE,
        UnknownReason.LOW_CONFIDENCE,
        UnknownReason.UNCALIBRATED_CONFIDENCE,
        UnknownReason.UNPARSED_BLOCK,
        UnknownReason.NO_EVIDENCE,
        UnknownReason.CAPABILITY_UNKNOWN,
    ],
)
def test_only_no_match_reaches_the_absence_table(reason: UnknownReason) -> None:
    """Every other reason describes a directive that is present, not missing."""
    field = Field[Any].unknown(reason, confidence_method=ConfidenceMethod.DETERMINISTIC)
    csm = build_csm(result_with(field), pack_with_platform_knowledge(), device_id="d1")

    assert csm.fields[FIELD].unknown_reason is reason
    assert csm.fields[FIELD].state is FieldState.UNKNOWN
