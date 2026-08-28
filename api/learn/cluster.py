"""Grouping unknown lines by token-shape signature.

The Concept Report describes the loop as *"unknown lines are clustered and
ranked by frequency, presented with top-3 AI suggestions"*. This is the
clustering and the ranking; the suggestions are `suggest.py` and the presenting
is P11.

**Clustering is deterministic string grouping, not a model.** Two lines belong
together when their signatures are identical — nothing is inferred, nothing is
approximate, and the grouping can be checked by eye. That matters because the
cluster is the unit an administrator confirms: one decision applied to every
line in it. A fuzzy cluster would mean a confirmation silently covering lines
the person never saw.

Ranking is by frequency, then by first appearance. A shape occurring on forty
devices is worth an administrator's attention before one occurring on a single
device, and the tie-break keeps the order stable between runs.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dc_field

from api.learn.signature import is_generic, signature
from api.models.csm import UnknownLine


@dataclass(frozen=True)
class LineCluster:
    """A set of unknown lines sharing one command shape."""

    cluster_id: str
    signature: str
    members: tuple[UnknownLine, ...]
    generic: bool = False

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def file_count(self) -> int:
        """How many distinct configurations this shape appears in.

        The number that makes a cluster worth confirming: one shape across
        thirty devices is one decision worth thirty.
        """
        return len({m.file_id for m in self.members})

    @property
    def exemplar(self) -> UnknownLine:
        """The line shown to the administrator.

        The first member in file and line order, so the same cluster always
        presents the same line and a person returning to the queue sees what
        they saw before.
        """
        return self.members[0]

    @property
    def is_confirmable(self) -> bool:
        """Whether this cluster may be offered for confirmation at all.

        A generic shape carries no command vocabulary, so a single confirmation
        over it would cover lines that have nothing in common. Such clusters stay
        visible in the queue and are never presented as one decision.
        """
        return not self.generic


def cluster_id_for(sig: str) -> str:
    """A stable identifier for a signature.

    Derived from the signature text, so the same shape gets the same id across
    runs, machines and fleets — which is what lets a confirmation recorded on one
    audit apply to the same shape on the next.
    """
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]


@dataclass
class _Accumulator:
    signature: str
    members: list[UnknownLine] = dc_field(default_factory=list)


def cluster_unknown_lines(lines: Iterable[UnknownLine]) -> tuple[LineCluster, ...]:
    """Group unknown lines by shape, ranked by how much attention each deserves.

    Lines whose signature is empty are dropped: a blank line has no shape, and
    it should not have reached the queue in the first place.
    """
    buckets: dict[str, _Accumulator] = {}

    for line in lines:
        sig = line.normalised_line or signature(line.raw_line_scrubbed)
        if not sig:
            continue
        buckets.setdefault(sig, _Accumulator(signature=sig)).members.append(line)

    clusters = [
        LineCluster(
            cluster_id=cluster_id_for(sig),
            signature=sig,
            members=tuple(sorted(acc.members, key=lambda m: (m.file_id, m.line_number))),
            generic=is_generic(sig),
        )
        for sig, acc in buckets.items()
    ]

    # Frequency first, then breadth across files, then the signature itself so
    # the order is total and identical between runs.
    clusters.sort(key=lambda c: (-c.size, -c.file_count, c.signature))
    return tuple(clusters)


def confirmable(clusters: Iterable[LineCluster]) -> tuple[LineCluster, ...]:
    """Only the clusters that may be offered as a single decision."""
    return tuple(c for c in clusters if c.is_confirmable)
