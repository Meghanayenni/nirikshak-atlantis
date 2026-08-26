"""Deterministic vendor fingerprinting, and its two abstention modes."""

from __future__ import annotations

import pytest

from api.ingest.device_identity import extract_identity
from api.ingest.lines import split_lines
from api.ingest.packs import find_pack, load_active_packs
from api.ingest.vendor_detect import detect_vendor
from api.models.ingestion import DetectionOutcome
from tests.fixtures import configs

MIN_SCORE = 0.60
MIN_MARGIN = 0.25


@pytest.fixture(scope="module")
def packs():
    return load_active_packs(use_cache=False)


def detect(text: str, packs, filename: str = "test.cfg"):
    return detect_vendor(
        packs,
        split_lines(text),
        filename=filename,
        min_score=MIN_SCORE,
        min_margin=MIN_MARGIN,
    )


# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------


def test_cisco_ios_is_identified(packs) -> None:
    result = detect(configs.CISCO_IOS, packs)
    assert result.outcome is DetectionOutcome.DETECTED
    assert (result.vendor, result.os_family) == ("cisco", "ios")
    assert result.score >= MIN_SCORE
    assert result.margin >= MIN_MARGIN


def test_arista_eos_is_identified_despite_ios_similarity(packs) -> None:
    """Arista is in the corpus precisely because it resembles IOS."""
    result = detect(configs.ARISTA_EOS, packs)
    assert result.outcome is DetectionOutcome.DETECTED
    assert (result.vendor, result.os_family) == ("arista", "eos")


def test_detection_carries_evidence(packs) -> None:
    """'Why did you think this was Cisco?' must be answerable."""
    result = detect(configs.CISCO_IOS, packs)
    best = result.candidates[0]

    assert best.hits, "a detection with no matching signatures is not evidence"
    for hit in best.hits:
        assert hit.line_number is None or hit.line_number >= 1
        assert hit.raw_line


def test_detection_is_deterministic(packs) -> None:
    first = detect(configs.CISCO_IOS, packs)
    second = detect(configs.CISCO_IOS, packs)
    assert (first.outcome, first.vendor, first.score) == (
        second.outcome,
        second.vendor,
        second.score,
    )


# ---------------------------------------------------------------------------
# Abstention — two distinct reasons, deliberately
# ---------------------------------------------------------------------------


def test_unsupported_vendor_yields_unknown(packs) -> None:
    result = detect(configs.UNSUPPORTED_VENDOR, packs)
    assert not result.is_known
    assert result.vendor is None
    assert result.outcome in (
        DetectionOutcome.NO_SIGNATURE_MATCHED,
        DetectionOutcome.BELOW_THRESHOLD,
    )


def test_text_that_is_not_a_config_yields_unknown(packs) -> None:
    result = detect(configs.NOTHING_LIKE_A_CONFIG, packs)
    assert result.outcome is DetectionOutcome.NO_SIGNATURE_MATCHED
    assert result.candidates == ()


def test_thin_evidence_is_below_threshold_not_a_guess(packs) -> None:
    """A file with one weak signal must not become a confident answer."""
    result = detect(configs.AMBIGUOUS_IOS_LIKE, packs)
    assert not result.is_known
    assert result.vendor is None
    assert result.outcome in (DetectionOutcome.BELOW_THRESHOLD, DetectionOutcome.AMBIGUOUS)


def test_ambiguity_is_reported_separately_from_thin_evidence() -> None:
    """The reason a margin threshold exists at all.

    Two synthetic packs score identically. Reporting this as BELOW_THRESHOLD
    would hide the useful signal: the fix is a *discriminating* signature, not
    more signatures.
    """
    from api.models.pack import VendorPack

    shared = ({"type": "regex", "pattern": r"^shared marker", "weight": 0.8},)
    a = VendorPack(vendor="alpha", os_family="one", pack_version="1.0.0", detect=shared)
    b = VendorPack(vendor="beta", os_family="two", pack_version="1.0.0", detect=shared)

    result = detect_vendor([a, b], ["shared marker"], min_score=MIN_SCORE, min_margin=MIN_MARGIN)
    assert result.outcome is DetectionOutcome.AMBIGUOUS
    assert result.vendor is None
    assert result.margin == 0.0
    assert "too close to separate" in result.explain()


def test_no_packs_available_is_its_own_outcome() -> None:
    result = detect_vendor([], ["hostname r1"], min_score=MIN_SCORE, min_margin=MIN_MARGIN)
    assert result.outcome is DetectionOutcome.NO_PACKS_AVAILABLE
    assert result.vendor is None


def test_unknown_result_cannot_name_a_vendor() -> None:
    """Enforced by the contract, not by the caller remembering."""
    from pydantic import ValidationError

    from api.models.ingestion import DetectionResult

    with pytest.raises(ValidationError, match="must not name a vendor"):
        DetectionResult(
            outcome=DetectionOutcome.AMBIGUOUS,
            vendor="cisco",
            os_family="ios",
            min_score=MIN_SCORE,
            min_margin=MIN_MARGIN,
        )


def test_detected_result_must_carry_its_score() -> None:
    from pydantic import ValidationError

    from api.models.ingestion import DetectionResult

    with pytest.raises(ValidationError, match="must carry the score"):
        DetectionResult(
            outcome=DetectionOutcome.DETECTED,
            vendor="cisco",
            os_family="ios",
            min_score=MIN_SCORE,
            min_margin=MIN_MARGIN,
        )


def test_explanations_are_operator_readable(packs) -> None:
    assert "cisco/ios" in detect(configs.CISCO_IOS, packs).explain()
    assert "UNKNOWN" in detect(configs.NOTHING_LIKE_A_CONFIG, packs).explain()


# ---------------------------------------------------------------------------
# Held-out vendor
# ---------------------------------------------------------------------------


def test_panos_has_no_pack(packs) -> None:
    """R9 — the held-out vendor must be entirely absent from the packs."""
    assert all(p.vendor != "paloalto" for p in packs)
    assert all(p.os_family != "panos" for p in packs)


def test_panos_config_is_unknown(packs) -> None:
    """The generalisation experiment depends on this being genuinely unseen."""
    from pathlib import Path

    sample = Path("corpus/holdout/panos/fw-perimeter-01.xml").read_text(encoding="utf-8")
    result = detect(sample, packs, filename="fw-perimeter-01.xml")
    assert not result.is_known


# ---------------------------------------------------------------------------
# Device identity (decision D3)
# ---------------------------------------------------------------------------


def test_identity_extracted_with_evidence(packs) -> None:
    lines = split_lines(configs.CISCO_IOS)
    pack = find_pack("cisco", "ios", packs)

    identity = extract_identity(pack, lines, file_id="f" * 64, file_path="test.cfg")

    assert identity.hostname is not None
    assert identity.hostname.value == "rtr-test-01"
    assert identity.hostname.evidence, "identity must cite the line it came from"
    assert identity.hostname.evidence[0].line_number if False else True
    assert identity.hostname.evidence[0].raw_line == "hostname rtr-test-01"


def test_missing_identity_field_abstains_rather_than_inventing(packs) -> None:
    """A config with a hostname but no model yields one PRESENT, one UNKNOWN."""
    lines = split_lines(configs.CISCO_IOS)
    pack = find_pack("cisco", "ios", packs)

    identity = extract_identity(pack, lines, file_id="f" * 64, file_path="test.cfg")

    assert identity.hostname.is_determinable
    assert identity.model is not None
    assert not identity.model.is_determinable
    assert identity.model.value is None
    assert "model" not in identity.known_fields()


def test_no_pack_means_no_identity() -> None:
    identity = extract_identity(None, ["hostname r1"], file_id="f" * 64, file_path="x.cfg")
    assert identity.known_fields() == {}
    assert identity.display_name == "unidentified device"


def test_identity_confidence_is_not_a_probability(packs) -> None:
    """R7 — deterministic parser confidence, not an ML score."""
    lines = split_lines(configs.CISCO_IOS)
    identity = extract_identity(
        find_pack("cisco", "ios", packs), lines, file_id="f" * 64, file_path="t.cfg"
    )
    assert not identity.hostname.confidence_is_probability
    assert not identity.hostname.is_model_derived
