"""Reading the corpus manifest, and refusing to read what must stay sealed.

Every corpus read in the harness passes through `read_configuration`, and that
function checks the split before it opens anything. The holdout is therefore
unreadable by construction rather than by discipline: there is no path through
this module that returns the bytes of a sealed file.

This module imports `api.models` and nothing else from the project. It has no
route to a parser, a normaliser or a compliance engine, which is what lets the
label loader depend on it without acquiring one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import yaml

from eval.errors import EvaluationError, SealedSplitError

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_ROOT = REPO_ROOT / "corpus"
MANIFEST_PATH = CORPUS_ROOT / "MANIFEST.yaml"

SEALED_SPLITS = frozenset({"holdout"})
"""Splits the evaluation harness may never open.

`holdout` only. It is a frozenset rather than a string so the guard reads the
same when a second held-out population is added, and so nothing can append to it
at runtime.
"""

SCOREABLE_SPLIT = "eval"
"""The only split that may be scored.

`dev` is excluded even though it holds configurations the parser handles best.
Scoring the files patterns were authored from measures memorisation, and a
harness that reports it as accuracy is worse than no harness.
"""


@dataclass(frozen=True)
class CorpusEntry:
    """One manifest entry, as the harness needs it."""

    path: str
    split: str
    vendor: str
    os_family: str
    source_type: str
    is_real_world_data: bool
    labelled: bool
    sha256: str

    @property
    def is_sealed(self) -> bool:
        return self.split in SEALED_SPLITS

    @property
    def is_scoreable(self) -> bool:
        return self.split == SCOREABLE_SPLIT


def load_manifest(path: Path = MANIFEST_PATH) -> tuple[CorpusEntry, ...]:
    """Every entry, in a stable order.

    Sorted by path so two runs over an unchanged corpus produce the same report.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries = [
        CorpusEntry(
            path=e["path"],
            split=e["split"],
            vendor=e["vendor"],
            os_family=e["os_family"],
            source_type=e["source_type"],
            is_real_world_data=e["is_real_world_data"],
            labelled=e.get("labelled", False),
            sha256=e["sha256"],
        )
        for e in raw["files"]
    ]
    return tuple(sorted(entries, key=lambda e: e.path))


def held_out_vendor(path: Path = MANIFEST_PATH) -> str:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return str(raw["held_out_vendor"])


def find_entry(corpus_path: str, entries: tuple[CorpusEntry, ...] | None = None) -> CorpusEntry:
    """The manifest entry for one corpus-relative path, or an error.

    A label naming a file the manifest does not list is refused here. An
    unlisted file could otherwise enter a metric without provenance, a
    checksum, or a declared split.
    """
    for entry in entries if entries is not None else load_manifest():
        if entry.path == corpus_path:
            return entry
    raise EvaluationError(
        f"{corpus_path!r} is not in the corpus manifest. Every scored file must be "
        "listed with its provenance and checksum."
    )


def guard_split(entry: CorpusEntry) -> None:
    """Raise if this entry belongs to a sealed split. Call before any read."""
    if entry.is_sealed:
        raise SealedSplitError(entry.path, entry.split)


def read_configuration(entry: CorpusEntry) -> str:
    """The raw text of one corpus configuration.

    The seal is checked **before** the file is opened, so a sealed path is never
    read into memory even briefly. `errors="replace"` matches what the ingestion
    layer does, so the harness scores the same text the pipeline would see.
    """
    guard_split(entry)
    return (CORPUS_ROOT / entry.path).read_text(encoding="utf-8", errors="replace")


def read_bytes(entry: CorpusEntry) -> bytes:
    """The raw bytes, for checksum verification. Also sealed."""
    guard_split(entry)
    return (CORPUS_ROOT / entry.path).read_bytes()


def sha256_of(entry: CorpusEntry) -> str:
    """The file's content hash, computed rather than trusted.

    Sealed files are refused here too. A hash is a small amount of information
    about a file's contents, and the holdout must yield none until P10.
    """
    return hashlib.sha256(read_bytes(entry)).hexdigest()


def scoreable_entries(entries: tuple[CorpusEntry, ...] | None = None) -> tuple[CorpusEntry, ...]:
    """Only the evaluation split. Never dev, never holdout."""
    return tuple(e for e in (entries if entries is not None else load_manifest()) if e.is_scoreable)


def corpus_is_synthetic(entries: tuple[CorpusEntry, ...] | None = None) -> bool:
    """Whether every scoreable file is synthetic.

    Read rather than assumed, because the honesty caveat in the report is
    generated from it: the day a real sanitised configuration is added, the
    wording must change on its own rather than by someone remembering to.
    """
    checked = entries if entries is not None else load_manifest()
    return all(e.source_type == "synthetic" and not e.is_real_world_data for e in checked)
