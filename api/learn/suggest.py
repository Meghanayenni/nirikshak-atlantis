"""Producing up to three ranked candidates for an unknown line.

This is the module the whole Rule 1 argument points at, so it is worth being
precise about what it does and does not do.

**It proposes. It never decides.** Every `Suggestion` leaves here carrying
`ConfidenceMethod.UNCALIBRATED_SIMILARITY`, which the contract already treats as
forcing the field to UNKNOWN regardless of the number attached — a raw score may
be *recorded and shown*, and can never support a claim. Nothing downstream can
promote it: `normalise` may not import `learn`, so a suggestion has no path into
the canonical model, and `comply` may not import `learn`, so it has no path into
a verdict. Coverage grows one way only:

    administrator confirms -> pattern enters the pack -> re-parse -> DETERMINISTIC match

**It ships uncalibrated, deliberately** (decision D42). Marking these
`CALIBRATED_SIMILARITY` would require a calibrator fitted on labelled ground
truth that does not exist, and the contract refuses a calibrated method without a
calibrated value. The abstention that follows is not a limitation being worked
around; it is the correct answer until the data exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.learn.errors import UncalibratedScoreError
from api.learn.index import ExampleIndex, IndexEntry
from api.models.enums import ConfidenceMethod
from api.models.training import Suggestion

MAX_SUGGESTIONS = 3
"""Three, from the Concept Report and DEVELOPER_GUIDE.md §5.

Not a tuning parameter. A longer list stops being a judgement and becomes a
search result the administrator has to work through, and the training interface
is meant to be one decision at a time.
"""

MIN_SCORE = 0.0
"""No score floor is applied.

Deliberate: a floor would be a threshold doing the job of a calibrator, chosen
by whoever wrote this line rather than fitted to anything. Every candidate is
shown with its raw score and its ranking, and the administrator decides. When a
calibrator exists, `settings.confidence_threshold` becomes meaningful for this
population and gating belongs there — not here.
"""


@dataclass(frozen=True)
class RankedCandidate:
    """One retrieved example and its similarity to the query line."""

    entry: IndexEntry
    score: float


def cosine(a: list[float], b: list[float]) -> float:
    """Dot product of two unit vectors.

    The embedder normalises at source, so this is cosine similarity without a
    second pass. Written out rather than pulled from a library so the retrieval
    arithmetic is testable with the `[ai]` extra uninstalled.
    """
    if len(a) != len(b):
        raise ValueError(f"vector width mismatch: {len(a)} vs {len(b)}")
    return sum(x * y for x, y in zip(a, b, strict=True))


def rank_candidates(
    query: list[float],
    index_vectors: list[list[float]],
    index: ExampleIndex,
    *,
    limit: int = MAX_SUGGESTIONS,
) -> tuple[RankedCandidate, ...]:
    """The closest examples, best first.

    Ties break on the entry's field then its text, so an ambiguous ranking is
    still a stable one. A ranking that reordered between runs would make top-3
    accuracy unreproducible and a training queue that reshuffles under the
    administrator.
    """
    if len(index_vectors) != len(index.entries):
        raise ValueError(f"index has {len(index.entries)} entries but {len(index_vectors)} vectors")

    scored = [
        RankedCandidate(entry=entry, score=cosine(query, vector))
        for entry, vector in zip(index.entries, index_vectors, strict=True)
    ]
    scored.sort(key=lambda c: (-c.score, c.entry.field, c.entry.text))
    return tuple(scored[:limit])


def to_suggestions(candidates: tuple[RankedCandidate, ...]) -> tuple[Suggestion, ...]:
    """Turn ranked candidates into contract objects, one field each.

    Deduplicated by field: three examples of `ssh_version` are one suggestion,
    not three. The administrator is choosing a *field*, and offering the same
    answer three times would waste all three slots and hide the alternatives.
    """
    seen: set[str] = set()
    suggestions: list[Suggestion] = []

    for candidate in candidates:
        if candidate.entry.field in seen:
            continue
        seen.add(candidate.entry.field)
        suggestions.append(
            Suggestion(
                rank=len(suggestions) + 1,
                field=candidate.entry.field,
                raw_score=candidate.score,
                calibrated_confidence=None,
                confidence_method=ConfidenceMethod.UNCALIBRATED_SIMILARITY,
            )
        )
        if len(suggestions) == MAX_SUGGESTIONS:
            break

    return tuple(suggestions)


def suggest_for_vectors(
    query: list[float],
    index_vectors: list[list[float]],
    index: ExampleIndex,
) -> tuple[Suggestion, ...]:
    """The whole retrieval path, for one already-embedded line.

    Takes vectors rather than text so the ranking is testable without a model,
    which is what lets the arithmetic be exercised on a machine with no `[ai]`
    extra installed.
    """
    if index.is_empty:
        return ()
    return to_suggestions(rank_candidates(query, index_vectors, index))


def assert_never_confidence(suggestions: tuple[Suggestion, ...]) -> None:
    """Refuse to let a raw score be read as a probability (R7).

    Called at every boundary where suggestions leave this package. It raises
    rather than returning a flag, because a caller that could ignore the answer
    would eventually ignore it, and the point of the confidence-method split is
    that it cannot be waived.
    """
    for suggestion in suggestions:
        if suggestion.confidence_method is ConfidenceMethod.CALIBRATED_SIMILARITY:
            raise UncalibratedScoreError(
                f"suggestion for {suggestion.field!r} claims calibrated confidence, but no "
                "calibrator has been fitted. A similarity score is not a probability (R7)."
            )
        if suggestion.calibrated_confidence is not None:
            raise UncalibratedScoreError(
                f"suggestion for {suggestion.field!r} carries a calibrated confidence "
                "while marked uncalibrated; a raw score cannot become a probability by "
                "being stored in that slot."
            )


def suggestions_are_evidence(suggestions: tuple[Suggestion, ...]) -> bool:
    """Whether these may support a compliance claim. Always False.

    Present as a named function rather than an implicit rule so that a future
    caller asking the question gets an answer in one place, and so a test can
    assert the answer never changes without a calibrator and an administrator.
    """
    return False
