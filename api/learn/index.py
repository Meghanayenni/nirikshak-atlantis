"""The labelled-example index the similarity layer searches.

Every entry is a `(line, canonical field)` pair somebody can point at. There are
two legitimate sources and no third:

  **SEED** — a pattern example already declared in a development-split vendor
  pack. These are labelled by construction: the pack says which field the
  pattern populates, and `test_every_pack_example_comes_from_the_development_split`
  has required since P4 that the example appear verbatim in a `dev` file.

  **ADMIN** — an administrator's confirmation, recorded as a `TrainingExample`.
  Added at P11 by `admin_entries_from_examples`. Unlike a seed, an admin entry
  is *not* required to appear in a development configuration: it came from a
  real device this deployment ingested, which is the point. Its provenance is
  the recorded decision — a named person, an outcome and an audit sequence —
  which is a stronger claim than a corpus citation, not a weaker one.

**Nothing else may enter** (decision D38). No example is invented, no line is
harvested from an evaluation file, and no entry is derived from the parser's own
output. A seed whose text cannot be found in a development configuration is
refused at build time rather than quietly indexed.

The index is deliberately small and honest about it: 11 pairs across 8 fields,
all from one vendor. That is what the packs contain, and inventing more to make
retrieval look better is the exact failure every phase of this project has
refused.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from api.learn.errors import IndexBuildError
from api.learn.signature import signature
from api.models.enums import ExampleSource
from api.models.pack import VendorPack
from api.models.training import TrainingExample

DEV_SPLIT = "dev"
"""The only split an index entry may be traced to.

Seeding from an evaluation file would put the answers inside the thing being
measured; seeding from the holdout would spend an experiment that can only be
run once.
"""


@dataclass(frozen=True)
class IndexEntry:
    """One labelled example, with the provenance that makes it admissible."""

    text: str
    field: str
    vendor: str
    os_family: str
    source: ExampleSource
    origin: str
    """Where the label came from — a pack pattern id, or a training example id."""

    signature: str = ""

    @property
    def is_seed(self) -> bool:
        return self.source is ExampleSource.SEED


@dataclass(frozen=True)
class ExampleIndex:
    """Every admissible labelled example, and what can be asked of it.

    Frozen, and built only by `build_index`. There is no `add` method: an entry
    enters by being a pack example or a recorded administrator confirmation, and
    by no other route.
    """

    entries: tuple[IndexEntry, ...]

    @property
    def is_empty(self) -> bool:
        return not self.entries

    @property
    def fields(self) -> frozenset[str]:
        return frozenset(e.field for e in self.entries)

    @property
    def vendors(self) -> frozenset[str]:
        return frozenset(e.vendor for e in self.entries)

    def texts(self) -> list[str]:
        return [e.text for e in self.entries]

    def describe(self) -> str:
        """A one-line honesty statement for the report and the training screen."""
        if self.is_empty:
            return "The labelled-example index is empty; no suggestion can be ranked."
        return (
            f"{len(self.entries)} labelled examples across {len(self.fields)} fields "
            f"and {len(self.vendors)} vendor(s)."
        )


def seed_entries_from_packs(packs: list[VendorPack]) -> tuple[IndexEntry, ...]:
    """Turn declared pattern examples into index entries.

    Only `patterns` are used, not `identity`. An identity pattern maps to a
    hostname or an OS version, which are not canonical security fields, and
    indexing them would let the layer propose `hostname` as the meaning of a
    security directive.
    """
    entries: list[IndexEntry] = []
    for pack in packs:
        for pattern in pack.patterns:
            for example in pattern.examples:
                text = example.strip()
                if not text:
                    continue
                entries.append(
                    IndexEntry(
                        text=text,
                        field=pattern.field,
                        vendor=pack.vendor,
                        os_family=pack.os_family,
                        source=ExampleSource.SEED,
                        origin=f"{pack.pack_id}:{pattern.id}",
                        signature=signature(text),
                    )
                )
    return tuple(entries)


def admin_entries_from_examples(examples: Iterable[TrainingExample]) -> tuple[IndexEntry, ...]:
    """Confirmed mappings as index entries (P11).

    A rejection is skipped. "This line is not security relevant" is a real
    decision worth keeping in `training_example`, and it is not a labelled
    example of anything — indexing it would let the layer propose a field for a
    line a human explicitly said had none.

    `raw_line_scrubbed` is what enters the index, never a raw line. The contract
    stores it post-redaction precisely because this text reaches an embedding
    model (Rule 6).
    """
    entries: list[IndexEntry] = []
    for example in examples:
        if example.field is None:
            continue
        text = example.raw_line_scrubbed.strip()
        if not text:
            continue
        entries.append(
            IndexEntry(
                text=text,
                field=example.field,
                vendor=example.vendor,
                os_family=example.os_family,
                source=ExampleSource.ADMIN,
                origin=example.example_id,
                signature=signature(text),
            )
        )
    return tuple(entries)


def verify_provenance(entries: tuple[IndexEntry, ...], development_lines: set[str]) -> list[str]:
    """Entries that cannot be traced to a development configuration.

    The corpus is supplied by the caller rather than read here. `api/learn/` must
    not depend on a `corpus/` directory: it does not exist in a deployment, and
    production code that reads development data is a fault waiting for the first
    install that lacks it.

    The guarantee itself is not weakened. Every entry originates in a pack
    pattern example, and `test_every_pack_example_comes_from_the_development_split`
    has required since P4 that each such example appear verbatim in a `dev` file.
    This function re-checks it against a corpus a test supplies.
    """
    return [
        f"{entry.origin}: {entry.text!r} appears in no development configuration"
        for entry in entries
        if entry.is_seed and entry.text not in development_lines
    ]


def build_index(
    packs: list[VendorPack],
    *,
    development_lines: set[str] | None = None,
    confirmations: Iterable[TrainingExample] = (),
) -> ExampleIndex:
    """The seed index, in a stable order.

    `development_lines` is optional. A caller with the corpus to hand passes it
    and provenance is re-checked; a deployment has no `corpus/` directory and
    does not, relying instead on the P4 test that guards pack examples at their
    source.

    An entry that cannot be traced raises rather than being dropped: a silently
    smaller index would change every retrieval metric with nothing in the output
    saying why.
    """
    entries = seed_entries_from_packs(packs) + admin_entries_from_examples(confirmations)

    if development_lines is not None:
        problems = verify_provenance(entries, development_lines)
        if problems:
            raise IndexBuildError(
                "seed examples must be traceable to a development configuration:\n"
                + "\n".join(f"  {p}" for p in problems)
            )

    ordered = tuple(sorted(entries, key=lambda e: (e.field, e.vendor, e.text, e.origin)))
    return ExampleIndex(entries=ordered)
