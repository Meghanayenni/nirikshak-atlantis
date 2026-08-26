"""Field contract — Rules 2 and 3, and decision R7.

These are the tests that matter most in the whole suite. Every guarantee about
NIRIKSHAK not making unjustified claims reduces to something asserted here.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.models import (
    ConfidenceMethod,
    Evidence,
    Field,
    FieldState,
    SourceType,
    UnknownReason,
)

EV = Evidence(
    file_id="f1",
    file_path="rtr.cfg",
    line_start=412,
    line_end=412,
    raw_line="ip ssh version 2",
    source_type=SourceType.CLI,
)


# ---------------------------------------------------------------------------
# Rule 2 — evidence is mandatory, and confidence never substitutes for it
# ---------------------------------------------------------------------------


def test_present_without_evidence_is_unconstructable() -> None:
    with pytest.raises(ValidationError, match="requires at least one Evidence"):
        Field[int](
            value=2,
            state=FieldState.PRESENT,
            confidence=1.0,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )


@pytest.mark.parametrize("confidence", [0.86, 0.95, 0.99, 1.0])
def test_high_confidence_never_compensates_for_missing_evidence(confidence: float) -> None:
    """R7: confidence and evidence are strictly separate semantics.

    Every one of these confidences is above the abstention threshold, so nothing
    coerces the field to UNKNOWN. It must still be rejected, purely for lacking
    a citation.
    """
    with pytest.raises(ValidationError, match="does not substitute for a citation"):
        Field[int](
            value=2,
            state=FieldState.PRESENT,
            confidence=confidence,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )


def test_present_with_evidence_is_accepted() -> None:
    f = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=1.0,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
        evidence=(EV,),
    )
    assert f.value == 2
    assert f.is_determinable
    assert f.evidence_citations() == ["rtr.cfg:412"]


def test_present_requires_a_value() -> None:
    with pytest.raises(ValidationError, match="must carry a value"):
        Field[int](
            value=None,
            state=FieldState.PRESENT,
            confidence=1.0,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
            evidence=(EV,),
        )


# ---------------------------------------------------------------------------
# Rule 3 — low confidence abstains
# ---------------------------------------------------------------------------


def test_sub_threshold_confidence_is_coerced_to_unknown() -> None:
    f = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=0.40,
        confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY,
        evidence=(EV,),
    )
    assert f.state is FieldState.UNKNOWN
    assert f.unknown_reason is UnknownReason.LOW_CONFIDENCE
    assert f.value is None, "an abstaining field must not retain a guessed value"


@pytest.mark.parametrize("confidence", [0.0, 0.1, 0.5, 0.84])
def test_low_calibrated_similarity_never_becomes_a_claim(confidence: float) -> None:
    """Low calibrated similarity must be UNKNOWN, never PASS or FAIL input."""
    f = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=confidence,
        confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY,
        evidence=(EV,),
    )
    assert f.state is FieldState.UNKNOWN
    assert not f.is_determinable


def test_threshold_boundary_is_inclusive_above() -> None:
    """At exactly the threshold the field stands; below it, it abstains."""
    at = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=0.85,
        confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY,
        evidence=(EV,),
    )
    assert at.state is FieldState.PRESENT

    below = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=0.8499,
        confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY,
        evidence=(EV,),
    )
    assert below.state is FieldState.UNKNOWN


def test_unknown_requires_a_reason() -> None:
    with pytest.raises(ValidationError, match="must record why it abstained"):
        Field[int](
            value=None,
            state=FieldState.UNKNOWN,
            confidence=0.0,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        )


def test_unknown_may_not_carry_a_value() -> None:
    with pytest.raises(ValidationError, match="guess wearing an abstention label"):
        Field[int](
            value=2,
            state=FieldState.UNKNOWN,
            confidence=0.0,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
            unknown_reason=UnknownReason.NO_MATCH,
        )


def test_unknown_constructor_is_always_valid() -> None:
    f = Field[int].unknown(UnknownReason.CAPABILITY_UNKNOWN)
    assert f.state is FieldState.UNKNOWN
    assert not f.is_determinable


# ---------------------------------------------------------------------------
# R7 — confidence populations
# ---------------------------------------------------------------------------


def test_uncalibrated_similarity_cannot_assert_anything() -> None:
    """A raw score is not a confidence, whatever its magnitude."""
    f = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=0.99,
        confidence_method=ConfidenceMethod.UNCALIBRATED_SIMILARITY,
        evidence=(EV,),
        raw_score=0.99,
    )
    assert f.state is FieldState.UNKNOWN
    assert f.unknown_reason is UnknownReason.UNCALIBRATED_CONFIDENCE
    assert f.value is None
    assert f.raw_score == 0.99, "the score is retained for the training queue"


@pytest.mark.parametrize("confidence", [0.0, 0.5, 0.9, 1.0])
def test_uncalibrated_abstains_at_every_confidence(confidence: float) -> None:
    f = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=confidence,
        confidence_method=ConfidenceMethod.UNCALIBRATED_SIMILARITY,
        evidence=(EV,),
    )
    assert f.state is FieldState.UNKNOWN


@pytest.mark.parametrize(
    ("method", "is_probability", "is_model"),
    [
        (ConfidenceMethod.DETERMINISTIC, False, False),
        (ConfidenceMethod.ADMIN_CONFIRMED, False, False),
        (ConfidenceMethod.PLATFORM_DEFAULT, False, False),
        (ConfidenceMethod.CALIBRATED_SIMILARITY, True, True),
        (ConfidenceMethod.UNCALIBRATED_SIMILARITY, False, True),
    ],
)
def test_population_discriminator(
    method: ConfidenceMethod, is_probability: bool, is_model: bool
) -> None:
    """R7: only calibrated similarity may be read as a probability."""
    assert method.is_probability is is_probability
    assert method.is_model_derived is is_model


def test_deterministic_confidence_is_not_a_probability() -> None:
    """R7 explicitly: parser confidence must not be interpreted as ML output."""
    f = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=1.0,
        confidence_method=ConfidenceMethod.DETERMINISTIC,
        evidence=(EV,),
    )
    assert not f.confidence_is_probability
    assert not f.is_model_derived


def test_calibrated_similarity_is_a_probability() -> None:
    f = Field[int](
        value=2,
        state=FieldState.PRESENT,
        confidence=0.92,
        confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY,
        evidence=(EV,),
    )
    assert f.confidence_is_probability
    assert f.is_model_derived


# ---------------------------------------------------------------------------
# Absence states
# ---------------------------------------------------------------------------


def test_absent_default_requires_a_citation() -> None:
    with pytest.raises(ValidationError, match="requires default_ref"):
        Field[bool](
            value=False,
            state=FieldState.ABSENT_DEFAULT,
            confidence=1.0,
            confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        )


def test_absent_default_with_citation_needs_no_evidence() -> None:
    """Absence is justified by a documented default, not by a source line."""
    f = Field[bool](
        value=False,
        state=FieldState.ABSENT_DEFAULT,
        confidence=1.0,
        confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        default_ref="Cisco IOS 17.x Configuration Guide, Telnet disabled by default",
    )
    assert f.is_determinable
    assert f.evidence == ()


def test_absent_unsupported_carries_no_value() -> None:
    with pytest.raises(ValidationError, match="ABSENT_UNSUPPORTED"):
        Field[bool](
            value=True,
            state=FieldState.ABSENT_UNSUPPORTED,
            confidence=1.0,
            confidence_method=ConfidenceMethod.PLATFORM_DEFAULT,
        )


# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------


def test_confidence_is_bounded() -> None:
    for bad in (-0.1, 1.1):
        with pytest.raises(ValidationError):
            Field[int](
                value=None,
                state=FieldState.UNKNOWN,
                confidence=bad,
                confidence_method=ConfidenceMethod.DETERMINISTIC,
                unknown_reason=UnknownReason.NO_MATCH,
            )


def test_field_is_immutable() -> None:
    f = Field[int].unknown(UnknownReason.NO_MATCH)
    with pytest.raises(ValidationError):
        f.state = FieldState.PRESENT  # type: ignore[misc]
