"""Calibration machinery, and the refusal to use it (P10, decision D42).

No calibrator is fitted and none ships. The population it would need — line-level
ground truth saying *this unknown line means `ssh_version`* — does not exist, and
decision D39 declined to author it for the purpose of making a metric computable.

So the tests here do two jobs. They check the arithmetic against **constructed**
score distributions, so the machinery is correct on the day real data arrives.
And they check the refusals, which are the part that ships: fitting below the
sample floor raises, and `active_calibrator()` returns `None`.

Every score below is invented for the test and is clearly a fixture. None of it
is evaluation ground truth, and nothing here reads the corpus.
"""

from __future__ import annotations

import pytest

from api.learn.calibration import (
    MIN_CALIBRATION_SAMPLES,
    MIN_POSITIVE_SAMPLES,
    ScoreOutcome,
    active_calibrator,
    expected_calibration_error,
    fit,
    reliability,
)
from api.learn.errors import CalibrationError
from api.models.enums import ConfidenceMethod


def synthetic(count: int, *, accuracy: float = 0.8) -> list[ScoreOutcome]:
    """A constructed, monotone score population. A TEST FIXTURE, not ground truth.

    Scores rise across the range and correctness rises with them, which is the
    shape a calibrator is supposed to find. Nothing about it is measured.
    """
    out: list[ScoreOutcome] = []
    for i in range(count):
        score = i / max(count - 1, 1)
        out.append(ScoreOutcome(score=score, was_correct=score >= (1.0 - accuracy)))
    return out


# ---------------------------------------------------------------------------
# What ships: the refusals
# ---------------------------------------------------------------------------


def test_no_calibrator_is_active() -> None:
    """D42. Expected to fail the day someone fits one without revisiting it."""
    assert active_calibrator() is None


def test_fitting_below_the_sample_floor_is_refused() -> None:
    """The guard that makes D42 enforceable rather than a note in a document.

    A curve fitted on a handful of points is a claim about how often the system
    is right, made from a sample too small to support one — the same failure as
    an unsourced platform default, wearing a probability.
    """
    with pytest.raises(CalibrationError, match="refusing to fit"):
        fit(synthetic(12), fitted_on="a dozen constructed points")


def test_the_refusal_names_the_floor_and_the_decision() -> None:
    """An error a reader can act on, not just a rejection."""
    with pytest.raises(CalibrationError) as caught:
        fit(synthetic(5), fitted_on="constructed")

    message = str(caught.value)
    assert str(MIN_CALIBRATION_SAMPLES) in message
    assert "D42" in message
    assert "abstains" in message


def test_a_population_that_is_almost_never_correct_is_refused() -> None:
    """A curve fitted on scores that were never right describes noise."""
    barely = [ScoreOutcome(score=i / 400, was_correct=i > 398) for i in range(400)]
    with pytest.raises(CalibrationError, match="below the floor"):
        fit(barely, fitted_on="constructed")


def test_the_floor_is_plainly_above_what_this_corpus_could_supply() -> None:
    """So the refusal is unambiguous rather than marginal.

    The development split holds roughly a dozen security-relevant unknown lines.
    A floor of 200 is not a statistical derivation and is not presented as one —
    it is set far enough above the available data that nobody has to argue.
    """
    assert MIN_CALIBRATION_SAMPLES >= 200
    assert MIN_POSITIVE_SAMPLES >= 20


# ---------------------------------------------------------------------------
# The machinery, on constructed distributions
# ---------------------------------------------------------------------------


def test_a_sufficient_population_fits() -> None:
    calibrator = fit(synthetic(400), fitted_on="constructed fixture, not ground truth")

    assert calibrator.sample_size == 400
    assert calibrator.method is ConfidenceMethod.CALIBRATED_SIMILARITY
    assert "not ground truth" in calibrator.fitted_on


def test_the_fitted_mapping_is_monotone() -> None:
    """Isotonic regression assumes only that higher similarity is not worse."""
    calibrator = fit(synthetic(400), fitted_on="constructed")
    probabilities = [calibrator.probability(i / 100) for i in range(101)]

    assert probabilities == sorted(probabilities)


def test_probabilities_stay_within_range() -> None:
    calibrator = fit(synthetic(400), fitted_on="constructed")
    for i in range(101):
        assert 0.0 <= calibrator.probability(i / 100) <= 1.0


def test_a_high_score_maps_higher_than_a_low_one() -> None:
    calibrator = fit(synthetic(400, accuracy=0.5), fitted_on="constructed")
    assert calibrator.probability(0.95) > calibrator.probability(0.05)


# ---------------------------------------------------------------------------
# Reliability, which is useful before a calibrator exists
# ---------------------------------------------------------------------------


def test_reliability_bins_report_their_own_population() -> None:
    diagram = reliability(synthetic(200))

    assert diagram
    assert all(b.count > 0 for b in diagram)
    assert sum(b.count for b in diagram) == 200


def test_an_empty_bin_is_dropped_rather_than_scored_zero() -> None:
    """A bucket nobody landed in is not a bucket the system got wrong."""
    clustered = [ScoreOutcome(score=0.95, was_correct=True) for _ in range(20)]
    diagram = reliability(clustered, bins=10)

    assert len(diagram) == 1
    assert diagram[0].count == 20


def test_reliability_of_nothing_is_nothing() -> None:
    assert reliability([]) == ()


def test_calibration_error_is_none_on_an_empty_population() -> None:
    """A perfect score over nothing is not a perfect score."""
    assert expected_calibration_error([]) is None


def test_a_perfectly_calibrated_population_has_near_zero_error() -> None:
    """Scores that match observed accuracy exactly."""
    population = [ScoreOutcome(score=0.5, was_correct=i % 2 == 0) for i in range(200)]
    error = expected_calibration_error(population)

    assert error is not None
    assert error == pytest.approx(0.0, abs=0.01)


def test_a_badly_calibrated_population_shows_a_large_gap() -> None:
    """Confident and wrong — the shape calibration exists to expose."""
    population = [ScoreOutcome(score=0.99, was_correct=False) for _ in range(100)]
    error = expected_calibration_error(population)

    assert error is not None
    assert error > 0.9


def test_a_score_outcome_records_a_human_judgement_only() -> None:
    """There is no constructor path deriving `was_correct` from the pipeline."""
    assert set(ScoreOutcome.__dataclass_fields__) == {"score", "was_correct"}
