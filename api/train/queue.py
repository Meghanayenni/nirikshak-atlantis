"""The training queue: what an administrator is actually asked to decide.

Residue in, one decision at a time out. The clustering, ranking and index all
belong to `api/learn/`; what this module adds is the honesty layer between them
and a person.

**The central rule here is decision D50.** On a machine where the embedding model
is absent — which is every machine in this repository, because the `[ai]` extra
is deliberately uninstalled (ADR 0018) — the queue must still work, and it must
say *why* there are no suggestions. It must never return an empty list of
suggestions, because an empty list is indistinguishable from "the model ran and
found nothing similar", and those are opposite statements. One means *we could
not look*; the other means *we looked and the index is unlike this line*. An
administrator who cannot tell them apart is being asked to confirm a mapping
while being misled about what informed the question.

This is the same failure DEVELOPER_GUIDE.md §14 names — *"a mode that silently returns
empty output is indistinguishable from a clean result"* — applied to the one
screen where a mistake becomes permanent.

So a `QueueEntry` never carries a bare tuple of suggestions. It carries a
`SuggestionOutcome` with an explicit state, and the state is what the interface
renders. Confirming with no suggestion at all remains perfectly valid: the
administrator is the authority and always was, and a confirmation made without a
ranking is the `CORRECTED` path the contract has modelled since P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from api.learn.cluster import LineCluster, cluster_unknown_lines
from api.learn.embedding import ModelAvailability, availability, embed
from api.learn.errors import ModelUnavailableError
from api.learn.index import ExampleIndex
from api.learn.suggest import assert_never_confidence, suggest_for_vectors
from api.models.csm import UnknownLine
from api.models.training import Suggestion
from api.train.errors import QueueError


class SuggestionState(StrEnum):
    """Why this cluster has the suggestions it has — or has none.

    Rendered by the interface as a distinct state, never collapsed into an empty
    list (D50).
    """

    RANKED = "ranked"
    """The model ran and the index was searched. Suggestions are present."""

    MODEL_UNAVAILABLE = "model_unavailable"
    """No embedding could be produced here. Nothing was searched, nothing was
    ranked, and nothing about this line has been assessed."""

    INDEX_EMPTY = "index_empty"
    """The model is available but there is nothing to compare against. Distinct
    from MODEL_UNAVAILABLE because the remedy is different: one needs an
    installed model, the other needs confirmations."""

    NOT_CONFIRMABLE = "not_confirmable"
    """The cluster's shape is too generic to be one decision (`is_confirmable`).
    Shown so the queue is complete, never offered as a single confirmation."""


@dataclass(frozen=True)
class SuggestionOutcome:
    """Suggestions, and the reason there are or are not any.

    `reason` is always populated for a non-RANKED state. A state without a reason
    would push the interface back into inventing an explanation, which is how
    "the model found nothing" gets printed above a queue the model never saw.
    """

    state: SuggestionState
    suggestions: tuple[Suggestion, ...] = ()
    reason: str = ""
    model: ModelAvailability | None = None

    def __post_init__(self) -> None:
        if self.state is not SuggestionState.RANKED and not self.reason:
            raise QueueError(f"suggestion state {self.state} must carry a reason (D50)")
        if self.state is not SuggestionState.RANKED and self.suggestions:
            raise QueueError(
                f"suggestion state {self.state} carries {len(self.suggestions)} "
                "suggestions; a non-ranked outcome has none by definition"
            )

    @property
    def is_ranked(self) -> bool:
        return self.state is SuggestionState.RANKED


@dataclass(frozen=True)
class QueueEntry:
    """One cluster as an administrator sees it."""

    cluster: LineCluster
    outcome: SuggestionOutcome

    @property
    def cluster_id(self) -> str:
        return self.cluster.cluster_id

    @property
    def exemplar_text(self) -> str:
        """The scrubbed line shown to the person. Never the raw line."""
        return self.cluster.exemplar.raw_line_scrubbed


@dataclass(frozen=True)
class TrainingQueue:
    """Every unknown shape, ranked by how much confirming it would buy.

    `index_description` is `ExampleIndex.describe()` — "11 labelled examples
    across 8 fields and 1 vendor(s)". ADR 0017 requires that sentence to appear
    on the training screen: an administrator judging a ranking deserves to know
    it was drawn from eleven examples of one vendor, not from a corpus.
    """

    entries: tuple[QueueEntry, ...] = ()
    index_description: str = ""
    model: ModelAvailability | None = None
    scrubbed: bool = True

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def confirmable(self) -> tuple[QueueEntry, ...]:
        return tuple(e for e in self.entries if e.cluster.is_confirmable)

    def find(self, cluster_id: str) -> QueueEntry | None:
        return next((e for e in self.entries if e.cluster_id == cluster_id), None)

    def describe(self) -> str:
        """One line for the report and the training screen."""
        if not self.entries:
            return "The training queue is empty; every line was recognised by a pack."
        state = "with ranked suggestions"
        if self.model is not None and not self.model.available:
            state = "with no suggestions — " + self.model.summary
        return (
            f"{self.size} unknown shapes ({len(self.confirmable)} confirmable) {state}. "
            f"{self.index_description}"
        )


def _model_unavailable_outcome(state: ModelAvailability) -> SuggestionOutcome:
    """The honest empty state, carrying what is missing and how to fix it."""
    return SuggestionOutcome(
        state=SuggestionState.MODEL_UNAVAILABLE,
        suggestions=(),
        reason=(
            state.summary + " No line was embedded and no candidate was ranked, so nothing here "
            "has been assessed by a model. A mapping may still be confirmed — the "
            "administrator is the authority, not the ranking (see ADR 0018)."
        ),
        model=state,
    )


def build_queue(
    unknown_lines: tuple[UnknownLine, ...],
    index: ExampleIndex,
    *,
    airgap: bool = False,
    model_state: ModelAvailability | None = None,
) -> TrainingQueue:
    """Cluster the residue and attach suggestions, or state why there are none.

    The model is probed once for the whole queue rather than per cluster: the
    answer cannot change mid-build, and asking repeatedly would let one queue
    report two different states about the same machine.
    """
    clusters = cluster_unknown_lines(unknown_lines)
    state = model_state if model_state is not None else availability(airgap=airgap)

    entries: list[QueueEntry] = []
    index_vectors: list[list[float]] | None = None

    for cluster in clusters:
        if not cluster.is_confirmable:
            entries.append(
                QueueEntry(
                    cluster=cluster,
                    outcome=SuggestionOutcome(
                        state=SuggestionState.NOT_CONFIRMABLE,
                        reason=(
                            f"the shape {cluster.signature!r} carries no command "
                            "vocabulary, so one confirmation over it would cover "
                            "lines that have nothing in common"
                        ),
                        model=state,
                    ),
                )
            )
            continue

        if not state.available:
            entries.append(QueueEntry(cluster=cluster, outcome=_model_unavailable_outcome(state)))
            continue

        if index.is_empty:
            entries.append(
                QueueEntry(
                    cluster=cluster,
                    outcome=SuggestionOutcome(
                        state=SuggestionState.INDEX_EMPTY,
                        reason=(
                            "the labelled-example index is empty, so there is nothing "
                            "to rank this line against. It fills as administrators "
                            "confirm mappings."
                        ),
                        model=state,
                    ),
                )
            )
            continue

        if index_vectors is None:
            index_vectors = _embed_index(index, airgap=airgap)
            if index_vectors is None:
                entries.append(
                    QueueEntry(cluster=cluster, outcome=_model_unavailable_outcome(state))
                )
                continue

        try:
            query = embed([cluster.exemplar.raw_line_scrubbed], airgap=airgap)[0]
        except ModelUnavailableError:
            entries.append(QueueEntry(cluster=cluster, outcome=_model_unavailable_outcome(state)))
            continue

        suggestions = suggest_for_vectors(
            query,
            index_vectors,
            index,
            block_paths=[member.block_path for member in cluster.members],
        )
        assert_never_confidence(suggestions)

        if not suggestions:
            entries.append(
                QueueEntry(
                    cluster=cluster,
                    outcome=SuggestionOutcome(
                        state=SuggestionState.INDEX_EMPTY,
                        reason=("the index was searched and yielded no candidate for this shape"),
                        model=state,
                    ),
                )
            )
            continue

        entries.append(
            QueueEntry(
                cluster=cluster,
                outcome=SuggestionOutcome(
                    state=SuggestionState.RANKED,
                    suggestions=suggestions,
                    model=state,
                ),
            )
        )

    return TrainingQueue(
        entries=tuple(entries),
        index_description=index.describe(),
        model=state,
    )


def _embed_index(index: ExampleIndex, *, airgap: bool) -> list[list[float]] | None:
    """Vectors for the index, or None when the model turns out to be absent."""
    try:
        return embed(index.texts(), airgap=airgap)
    except ModelUnavailableError:
        return None


__all__ = [
    "QueueEntry",
    "SuggestionOutcome",
    "SuggestionState",
    "TrainingQueue",
    "build_queue",
]
