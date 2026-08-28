"""Loading ground truth, and verifying it against the configuration it cites.

**This module has no import path to the pipeline.** It may reach `api.models`
and `eval.corpus`, and nothing else from the project — no parser, no normaliser,
no compliance engine. That is what makes the rule from ADR 0010 structural:

    A label is authored from the configuration, never from parser output.

A loader that could reach the parser could, one refactor later, fill in a
missing label from it. This one cannot, and an architecture test says so.

## What is verified, and why each check exists

**The checksum**, because a configuration edited after labelling would be scored
against ground truth describing a file that no longer exists — silently, and in
the flattering direction as often as not.

**Every citation**, because a label pointing at line 12 and quoting text that is
not on line 12 has drifted from the file, and a metric computed from it is a
number about nothing. This is the same discipline Rule 2 imposes on findings,
applied to the labels that score them.

**The split**, because ground truth beside the files patterns are authored from
is an invitation to author patterns from the ground truth.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from api.models.label import FileLabels
from eval.corpus import CORPUS_ROOT, CorpusEntry, find_entry, read_configuration, sha256_of
from eval.errors import LabelIntegrityError, LabelLoadError

LABELS_ROOT = CORPUS_ROOT / "labels"


def label_files(root: Path = LABELS_ROOT) -> list[Path]:
    """Every label file, in a stable order."""
    if not root.is_dir():
        return []
    return sorted(root.glob("*.yaml"))


def load_label_file(path: Path) -> FileLabels:
    """One label file, contract-checked. Not yet verified against its configuration."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise LabelLoadError(f"{path.name}: invalid YAML - {exc}") from exc

    if not isinstance(raw, dict):
        raise LabelLoadError(f"{path.name}: expected a mapping at the top level")

    try:
        return FileLabels(**raw)
    except Exception as exc:
        raise LabelLoadError(f"{path.name}: {exc}") from exc


def verify_against_configuration(labels: FileLabels, entry: CorpusEntry) -> None:
    """Check the labels describe the file they claim to. Raises, or returns None.

    Deliberately not a boolean. A caller that could ignore the result would
    eventually ignore it, and the whole value of a citation is that it cannot be
    quietly wrong.
    """
    actual = sha256_of(entry)
    if actual != labels.file_sha256:
        raise LabelIntegrityError(
            f"{labels.corpus_path}: labelled against {labels.file_sha256[:12]} but the "
            f"file now hashes to {actual[:12]}. The configuration changed after it was "
            "labelled, so the ground truth describes a file that no longer exists."
        )

    lines = read_configuration(entry).splitlines()

    for label in labels.fields:
        if not label.cites_a_line:
            continue

        assert label.evidence_line is not None  # narrowed by cites_a_line
        if label.evidence_line > len(lines):
            raise LabelIntegrityError(
                f"{labels.corpus_path}: label for {label.field!r} cites line "
                f"{label.evidence_line}, but the file has {len(lines)} lines."
            )

        found = lines[label.evidence_line - 1]
        if found != label.evidence_text:
            raise LabelIntegrityError(
                f"{labels.corpus_path}: label for {label.field!r} cites line "
                f"{label.evidence_line} as {label.evidence_text!r}, but that line "
                f"reads {found!r}. The citation has drifted from the file."
            )


def load_labels(root: Path = LABELS_ROOT) -> tuple[FileLabels, ...]:
    """Every label, contract-checked and verified against its configuration.

    Ordered by corpus path so a report is diffable between runs.
    """
    loaded: list[FileLabels] = []
    for path in label_files(root):
        labels = load_label_file(path)
        entry = find_entry(labels.corpus_path)

        if entry.split != labels.corpus_path and entry.split != labels.split:
            raise LabelLoadError(
                f"{path.name}: declares split {labels.split!r} but the manifest says "
                f"{entry.split!r}"
            )

        verify_against_configuration(labels, entry)
        loaded.append(labels)

    return tuple(sorted(loaded, key=lambda labels: labels.corpus_path))


def labels_by_path(root: Path = LABELS_ROOT) -> dict[str, FileLabels]:
    return {labels.corpus_path: labels for labels in load_labels(root)}
