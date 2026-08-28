"""Evaluation-harness errors.

`SealedSplitError` is the one that matters. The PAN-OS holdout exists to answer
one question at P10 — whether coverage generalises to a vendor nothing was ever
authored from — and that question can be asked exactly once. Reading those files
early spends the experiment, and no result obtained afterwards can restore it.

So the harness does not merely decline to read them. It raises, by name, from a
guard every corpus read passes through.
"""

from __future__ import annotations


class EvaluationError(RuntimeError):
    """Base for every evaluation-harness failure."""


class SealedSplitError(EvaluationError):
    """Something tried to read a split the harness may not open.

    Named for what was violated rather than for what failed, so a stack trace
    says `SealedSplitError: holdout` and the reader knows immediately that this
    is an experiment-integrity problem and not a missing file.
    """

    def __init__(self, path: str, split: str) -> None:
        self.path = path
        self.split = split
        super().__init__(
            f"refusing to read {path!r}: it belongs to the sealed {split!r} split. "
            "The held-out vendor is read once, by the generalisation experiment at "
            "P10, and reading it earlier destroys the measurement it exists for."
        )


class LabelLoadError(EvaluationError):
    """A label file exists but could not be read as ground truth.

    Covers invalid YAML, contract violations, a checksum that no longer matches
    the configuration, and a citation the file does not support. All of them mean
    the ground truth on disk does not describe the file it claims to.
    """


class LabelIntegrityError(EvaluationError):
    """A label loaded, but does not agree with the configuration it cites.

    Separate from `LabelLoadError` because it says something different: the YAML
    was well-formed and satisfied the contract, but the line it points at is not
    the line it quotes. That is the failure the citation requirement exists to
    catch, and it must never be recoverable — a label scoring against text the
    file does not contain would produce a number about nothing.
    """


class ScoringError(EvaluationError):
    """The harness was asked to score something it must not score."""
