"""The absence truth table — the substance of P5 (decisions D11, D13).

One test per row, each named for the row it pins. The table decides what a
*missing* directive means, which the Concept Report calls the single distinction
separating a usable audit from a misleading one.

    parse       capability        default          →  state
    ---------------------------------------------------------------------
    matched     —                 —                →  PRESENT      (untouched)
    no match    supported: false  —                →  ABSENT_UNSUPPORTED
    no match    supported: true   admissible       →  ABSENT_DEFAULT
    no match    supported: true   inadmissible     →  UNKNOWN / no_match
    no match    supported: true   none             →  UNKNOWN / no_match
    no match    undocumented      —                →  UNKNOWN / capability_unknown
    no pattern  —                 —                →  key absent (reads UNKNOWN)

Every platform fixture here is synthetic and names a fictional document. The
shipped packs contain no defaults, because no vendor documentation has been
sourced — see the ADR and CORPUS_PREREQUISITES.
"""

from __future__ import annotations

import pytest

from api.config import settings
from api.models.enums import (
    CastType,
    ConfidenceMethod,
    FieldState,
    MatchType,
    PackStatus,
    UnknownReason,
)
from api.models.pack import (
    CaptureSpec,
    MatchSpec,
    PatternDef,
    PatternScope,
    VendorPack,
)
from api.normalise.absence import is_platform_derived, resolve_absent_field
from tests.fixtures.platform import (
    asserted_capability,
    asserted_default,
    sourced_capability,
    sourced_default,
    undocumented_capability,
)

FIELD = "telnet_enabled"


def pack(**kw: object) -> VendorPack:
    base: dict[str, object] = {
        "vendor": "testvendor",
        "os_family": "testos",
        "pack_version": "1.0.0",
        "status": PackStatus.DRAFT,
        "patterns": (
            PatternDef(
                id="p-001",
                field=FIELD,
                scope=PatternScope(),
                match=MatchSpec(type=MatchType.REGEX, pattern="^transport input telnet$"),
                capture=CaptureSpec(value="true", cast=CastType.BOOL),
            ),
        ),
    }
    base.update(kw)
    return VendorPack(**base)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Row 2 — supported: false → ABSENT_UNSUPPORTED
# ---------------------------------------------------------------------------


def test_row_unsupported_platform_yields_absent_unsupported() -> None:
    """The platform cannot express this control, and something sourced says so."""
    field = resolve_absent_field(FIELD, pack(capabilities=(sourced_capability(FIELD, False),)))

    assert field.state is FieldState.ABSENT_UNSUPPORTED
    assert field.value is None, "an unsupported control has no value to report"
    assert field.confidence_method is ConfidenceMethod.PLATFORM_DEFAULT
    assert field.default_ref, "the citation must travel so a report can explain the gap"


# ---------------------------------------------------------------------------
# Row 3 — supported + admissible default → ABSENT_DEFAULT
# ---------------------------------------------------------------------------


def test_row_sourced_default_yields_absent_default() -> None:
    p = pack(
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(sourced_default(FIELD, False),),
    )
    field = resolve_absent_field(FIELD, p)

    assert field.state is FieldState.ABSENT_DEFAULT
    assert field.value is False
    assert field.confidence_method is ConfidenceMethod.PLATFORM_DEFAULT
    assert field.is_determinable


def test_absent_default_carries_no_evidence_but_does_carry_a_citation() -> None:
    """Rule 2 is satisfied by documentation, because there is no line to cite.

    The premise of an ABSENT_DEFAULT field is that the directive is missing, so
    demanding configuration evidence would make the state unconstructable. The
    contract requires `default_ref` in its place.
    """
    p = pack(
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(sourced_default(FIELD, False),),
    )
    field = resolve_absent_field(FIELD, p)

    assert field.evidence == ()
    assert field.default_ref is not None and field.default_ref.strip()


# ---------------------------------------------------------------------------
# Row 4 — supported + INADMISSIBLE default → UNKNOWN
# ---------------------------------------------------------------------------


def test_row_project_asserted_default_abstains() -> None:
    """D11's core guarantee: our own assertion is not evidence.

    The default is recorded in the pack and visible to a reviewer, but it cannot
    produce a determinable field — an unverified default must never become a
    PASS or a FAIL.
    """
    p = pack(
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(asserted_default(FIELD, False),),
    )
    field = resolve_absent_field(FIELD, p)

    assert field.state is FieldState.UNKNOWN
    assert field.value is None
    assert field.unknown_reason is UnknownReason.NO_MATCH
    assert not field.is_determinable


def test_project_asserted_capability_abstains_too() -> None:
    """A claim that a platform cannot express a control is equally load-bearing.

    `supported: false` resolves to ABSENT_UNSUPPORTED, which a rule may treat as
    NOT_APPLICABLE. Asserting it without a source would let an assumption become
    a skipped check, so the same admissibility rule applies.
    """
    field = resolve_absent_field(FIELD, pack(capabilities=(asserted_capability(FIELD, False),)))

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN


# ---------------------------------------------------------------------------
# Row 5 — supported, no default at all → UNKNOWN
# ---------------------------------------------------------------------------


def test_row_supported_but_no_default_abstains() -> None:
    """The platform can express it; nothing documents what happens when absent."""
    field = resolve_absent_field(FIELD, pack(capabilities=(sourced_capability(FIELD, True),)))

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.NO_MATCH


# ---------------------------------------------------------------------------
# Row 6 — undocumented capability → UNKNOWN / capability_unknown
# ---------------------------------------------------------------------------


def test_row_undocumented_capability_abstains() -> None:
    """The row that earns the phase.

    An undocumented capability must not become "unsupported". Reading it that way
    would turn every unasked question into ABSENT_UNSUPPORTED, which a rule may
    legitimately treat as not-applicable — so ignorance would silently pass.
    """
    field = resolve_absent_field(FIELD, pack(capabilities=(undocumented_capability(FIELD),)))

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
    assert field.state is not FieldState.ABSENT_UNSUPPORTED


def test_no_capability_entry_at_all_abstains_identically() -> None:
    """A missing entry is not more certain than an explicit refusal to claim."""
    field = resolve_absent_field(FIELD, pack())

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN


def test_a_default_cannot_rescue_an_undocumented_capability() -> None:
    """Order matters: capability is asked first.

    A pack documenting a default while saying nothing about whether the platform
    supports the control has not established enough to assert. Applying the
    default anyway would assume support that was never claimed.
    """
    field = resolve_absent_field(FIELD, pack(defaults=(sourced_default(FIELD, False),)))

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN


# ---------------------------------------------------------------------------
# D13 — the configured confidence, and the floor it must clear
# ---------------------------------------------------------------------------


def test_platform_default_confidence_is_the_configured_value() -> None:
    p = pack(
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(sourced_default(FIELD, False),),
    )
    field = resolve_absent_field(FIELD, p)

    assert field.confidence == 0.95
    assert field.confidence == settings.platform_default_confidence


def test_the_floor_is_a_separate_number_from_the_assigned_confidence() -> None:
    """D13 — 0.95 is what an accepted default is assigned; 0.90 is admissibility.

    They must not be equal. Setting the assigned value at the floor would put
    every default exactly on the boundary, leaving the floor untestable in the
    failing direction.
    """
    assert settings.platform_default_min_confidence == 0.90
    assert settings.platform_default_confidence == 0.95
    assert settings.platform_default_confidence > settings.platform_default_min_confidence


def test_platform_default_confidence_is_not_a_calibrated_probability() -> None:
    """R7 — this population is never pooled with similarity scores."""
    p = pack(
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(sourced_default(FIELD, False),),
    )
    field = resolve_absent_field(FIELD, p)

    assert not field.confidence_is_probability
    assert not field.is_model_derived


def test_a_pack_author_cannot_choose_the_confidence() -> None:
    """D13 — the number lives in configuration, not in YAML.

    `PlatformDefault` has no confidence field and forbids extras, so a pack
    cannot dial a weak claim up to look like a strong one.
    """
    from pydantic import ValidationError

    from api.models.pack import PlatformDefault
    from tests.fixtures.platform import sourced_provenance

    assert "confidence" not in PlatformDefault.model_fields

    with pytest.raises(ValidationError, match="[Ee]xtra"):
        PlatformDefault(
            field=FIELD,
            value=False,
            provenance=sourced_provenance(),
            confidence=0.99,  # type: ignore[call-arg]
        )


def test_confidence_below_the_floor_abstains(monkeypatch: pytest.MonkeyPatch) -> None:
    """The floor is real, and reachable in the failing direction.

    Only testable because the assigned value sits above it rather than on it.
    """
    monkeypatch.setattr(settings, "platform_default_confidence", 0.5)

    p = pack(
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(sourced_default(FIELD, False),),
    )
    field = resolve_absent_field(FIELD, p)

    assert field.state is FieldState.UNKNOWN
    assert field.unknown_reason is UnknownReason.LOW_CONFIDENCE


# ---------------------------------------------------------------------------
# Reporting: platform knowledge must be distinguishable from observation
# ---------------------------------------------------------------------------


def test_platform_derived_fields_are_distinguishable_from_observed_facts() -> None:
    """A report and an audit record must be able to tell these apart.

    "We observed telnet enabled on line 17" and "this platform documents telnet
    as off by default" are different kinds of claim, and only one cites the
    operator's own configuration.
    """
    p = pack(
        capabilities=(sourced_capability(FIELD, True),),
        defaults=(sourced_default(FIELD, False),),
    )
    from_default = resolve_absent_field(FIELD, p)

    assert is_platform_derived(from_default)
    assert from_default.confidence_method is ConfidenceMethod.PLATFORM_DEFAULT
    assert from_default.evidence == ()
    assert from_default.default_ref is not None
