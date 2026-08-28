"""Similarity-layer errors.

The two that matter say different things and must not be collapsed.

`ModelUnavailableError` means the environment cannot run the model. The
embedding stack is an optional extra with a download step pip cannot perform, so
this is an environment gap — the same shape as the GTK gap ADR 0006 records, and
answered the same way: probe, refuse, name what is missing.

`UncalibratedScoreError` means something tried to read a raw similarity score as
a confidence. That is not an environment problem; it is the R7 violation the
whole confidence-method split exists to prevent, and it must never be
recoverable.
"""

from __future__ import annotations


class LearnError(RuntimeError):
    """Base for every similarity-layer failure."""


class ModelUnavailableError(LearnError):
    """The embedding model cannot be used in this environment.

    Carries the specific missing pieces rather than a generic message, and
    **there is deliberately no fallback behind it.** A hash-based or
    bag-of-words stand-in would produce suggestions that look like model output
    and are not, which is worse than producing none: an administrator confirming
    a mapping is trusting the ranking that put it in front of them.
    """

    def __init__(
        self,
        *,
        package_installed: bool,
        weights_present: bool,
        airgap: bool,
        model_name: str,
        detail: str | None = None,
    ) -> None:
        self.package_installed = package_installed
        self.weights_present = weights_present
        self.airgap = airgap
        self.model_name = model_name

        parts = ["the embedding model is unavailable, so no suggestion can be produced."]
        if not package_installed:
            parts.append(
                "The sentence-transformers package is not installed; it belongs to the "
                "optional [ai] dependency group (make install-ai)."
            )
        if not weights_present:
            parts.append(
                f"The weights for {model_name!r} are not present in the local cache. "
                "They are downloaded once by a documented setup step and are never "
                "committed to this repository."
            )
        if airgap and not weights_present:
            parts.append(
                "NIRIKSHAK is running with airgap enabled, so it will not fetch them. "
                "Failing closed is the intended behaviour (Rule 6)."
            )
        if detail:
            parts.append(detail)
        parts.append("See docs/adr/0018-model-acquisition.md.")
        super().__init__(" ".join(parts))


class UncalibratedScoreError(LearnError):
    """A raw similarity score was about to be treated as a probability.

    R7: a similarity score and a calibrated confidence are different kinds of
    claim that happen to share a numeric range. This is raised where code tries
    to read the first as the second, so the mistake surfaces at the point it is
    made rather than three layers later in a report.
    """


class IndexBuildError(LearnError):
    """The labelled-example index could not be built.

    Includes a seed example that cannot be traced to a development file. An
    example of unknown provenance in the index is an unlabelled claim about what
    a line means, which is the thing the corpus separation rules exist to stop.
    """


class CalibrationError(LearnError):
    """A calibrator could not be fitted, or was asked to do something dishonest.

    Chiefly: fitting below the minimum sample size. A curve fitted on a dozen
    points is a confidence claim resting on a sample too small to support one —
    the same failure as an unsourced platform default, in probabilistic clothing.
    """
