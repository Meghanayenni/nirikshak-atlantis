"""Boundaries around the evaluation harness (P9).

An evaluation is worth exactly its separation guarantees. Three properties carry
those, in descending order of how much they matter:

    1. Ground truth cannot be produced by the thing it scores. The label loader
       has no import path to a parser, a normaliser or a compliance engine.
    2. The held-out vendor cannot be read. Not by the harness, not by a test,
       not by a report.
    3. Only the evaluation split is scored. Scoring development files measures
       memorisation.

The first is the one that would be easiest to lose in a refactor and hardest to
notice afterwards, because a self-scored harness produces beautiful numbers.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL = REPO_ROOT / "eval"
CORPUS = REPO_ROOT / "corpus"
LABELS = CORPUS / "labels"

PIPELINE_PACKAGES = [
    "api.parse",
    "api.normalise",
    "api.comply",
    "api.ingest",
    "api.analyse",
    "api.learn",
    "api.train",
    "api.prioritise",
]
"""Packages the label side must not reach, directly or transitively.

`api.learn` was added at P10 (GAP-1). It was absent from this list until then
only because the package was empty, and the omission was harmless exactly as
long as that stayed true. It is the most important entry now: a label loader
that can reach the similarity layer is a label that could be *suggested by the
model it scores*, which is the circularity decision D31 exists to prevent — and
a subtler one than reaching the parser, because a suggestion looks like a
judgement rather than like output.

`api.train` joined at P11 for the same argument one step further on. The
similarity layer only proposes; the confirmation loop *records what was
believed* and compiles it into a pack. A label loader that could reach it would
be ground truth able to see — or to become — the mapping it is scoring, and
correlated error between the two would be invisible in every metric the harness
prints.

`api.prioritise` joined at P12. It is the weakest of the three claims and is
listed anyway: a label that could reach the ordering layer would be ground truth
aware of how important the thing it describes was judged to be.
"""

# Modules that must never reach the pipeline. These are what produce ground
# truth, so a route from here to a parser is a route from parser output into a
# label.
LABEL_SIDE = ["corpus.py", "labels.py", "metrics.py", "errors.py"]

# Modules that legitimately run the pipeline in order to compare against it.
SCORING_SIDE = ["score.py", "report.py", "run.py"]

HOLDOUT_TOKENS = ["holdout", "panos", "paloalto"]
"""Used for the label-file scan, where any mention at all is wrong."""


def _sources(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def _code_only(path: Path) -> str:
    """Source with comments and docstrings removed.

    The harness explains the holdout rule at length, and prose about the sealed
    split is not a read of it. Stripping documentation is what lets the grep
    below be strict without being wrong.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    docstrings = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    pieces: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                pieces.append(node.value)
        elif isinstance(node, ast.Name):
            pieces.append(node.id)
        elif isinstance(node, ast.Attribute):
            pieces.append(node.attr)
    return "\n".join(pieces)


def test_the_eval_package_is_populated() -> None:
    modules = [p for p in _sources(EVAL) if p.name != "__init__.py"]
    assert len(modules) >= 6, f"expected the harness modules, found {len(modules)}"


# ---------------------------------------------------------------------------
# A label cannot be produced by the thing it scores
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", LABEL_SIDE)
@pytest.mark.parametrize("forbidden", PIPELINE_PACKAGES)
def test_the_label_side_cannot_reach_the_pipeline(module: str, forbidden: str) -> None:
    """The rule from ADR 0010, made structural.

    A loader that could reach the parser could, one refactor later, fill a
    missing label in from it. This one cannot.
    """
    path = EVAL / module
    if not path.is_file():  # pragma: no cover - every module is expected to exist
        pytest.skip(f"{module} not present")

    offending = [
        imported
        for imported in _imports(path)
        if imported == forbidden or imported.startswith(f"{forbidden}.")
    ]
    assert offending == [], f"eval/{module} imports {offending}"


def test_the_label_side_imports_only_contracts_and_itself() -> None:
    """A whitelist, so a layer written later is forbidden too."""
    violations: list[str] = []
    for module in LABEL_SIDE:
        path = EVAL / module
        if not path.is_file():
            continue
        for imported in _imports(path):
            if not imported.startswith(("api.", "eval.")):
                continue
            top = ".".join(imported.split(".")[:2])
            if top not in {
                "api.models",
                "eval.corpus",
                "eval.errors",
                "eval.labels",
                "eval.metrics",
            }:
                violations.append(f"eval/{module} imports {imported}")
    assert violations == [], "\n".join(violations)


def test_only_the_loader_knows_where_labels_live() -> None:
    """One module resolves the label directory, and it is read-only.

    Confining `LABELS_ROOT` to the loader is what makes the next assertion
    total: if no other module can name the directory, no other module can write
    into it either.
    """
    knows = [
        path.name for path in _sources(EVAL) if "LABELS_ROOT" in path.read_text(encoding="utf-8")
    ]
    assert knows == ["labels.py"], f"the label directory is resolved in {knows}"


def test_the_label_loader_never_writes() -> None:
    """Ground truth is authored by a person and committed, never generated.

    A loader that could write into `corpus/labels/` could regenerate a label
    from the pipeline's own output — the circularity this phase is built to
    avoid. Asserted against the loader's syntax tree rather than a text search,
    so a write introduced under any name is caught.
    """
    tree = ast.parse((EVAL / "labels.py").read_text(encoding="utf-8"))
    writes = {"write_text", "write_bytes", "mkdir", "unlink", "dump", "safe_dump", "touch"}

    offenders = [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in writes
    ]
    assert offenders == [], f"eval/labels.py performs writes: {offenders}"


def test_the_label_contract_has_nowhere_to_put_a_prediction() -> None:
    """Rule 3 of the phase, enforced by the shape of the type.

    There is no `predicted_value`, no `confidence`, no parsed `state`. A
    pipeline result cannot be written into a label even by a caller trying to.
    """
    from api.models.label import FieldLabel, FileLabels

    forbidden = {
        "predicted_value",
        "parser_value",
        "confidence",
        "confidence_method",
        "system_value",
        "actual_value",
        "state",
    }
    assert not (forbidden & set(FieldLabel.model_fields))
    assert not (forbidden & set(FileLabels.model_fields))


# ---------------------------------------------------------------------------
# The holdout stays sealed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fragment", ["holdout/", "corpus/holdout", "panos", "paloalto"])
def test_no_harness_code_builds_a_path_into_the_holdout(fragment: str) -> None:
    """The distinction that matters is naming versus reaching.

    `SEALED_SPLITS = frozenset({"holdout"})` names the split — that *is* the
    guard, and forbidding it would forbid the protection. The report names it
    too, to say it was not read. What must never appear is a path fragment that
    could locate those files: a directory separator after the split name, or the
    held-out vendor at all.

    Docstrings and comments are stripped first, so the modules can explain the
    rule at length while the executable text stays free of a route to it.
    """
    offenders = [
        f"{path.name} builds {fragment!r}"
        for path in _sources(EVAL)
        if fragment in _code_only(path).lower()
    ]
    assert offenders == [], "\n".join(offenders)


def test_the_seal_is_a_frozen_set_the_guard_actually_reads() -> None:
    from eval.corpus import SEALED_SPLITS

    assert isinstance(SEALED_SPLITS, frozenset)
    assert "holdout" in SEALED_SPLITS


def test_reading_a_sealed_entry_raises_by_name() -> None:
    """A stack trace must say what was violated, not just that a call failed."""
    from eval.corpus import load_manifest, read_bytes, read_configuration, sha256_of
    from eval.errors import SealedSplitError

    sealed = [e for e in load_manifest() if e.is_sealed]
    assert sealed, "the manifest declares no sealed entry"

    for entry in sealed:
        for reader in (read_configuration, read_bytes, sha256_of):
            with pytest.raises(SealedSplitError):
                reader(entry)


def test_the_holdout_is_never_labelled() -> None:
    """Labelling requires reading, and nothing may read the held-out vendor."""
    from eval.corpus import load_manifest

    offenders = [e.path for e in load_manifest() if e.is_sealed and e.labelled]
    assert offenders == [], f"a sealed file is marked labelled: {offenders}"


def test_no_label_file_names_a_holdout_path() -> None:
    for path in sorted(LABELS.glob("*.yaml")):
        text = path.read_text(encoding="utf-8").lower()
        for token in HOLDOUT_TOKENS:
            assert token not in text, f"{path.name} names {token!r}"


# ---------------------------------------------------------------------------
# Only the evaluation split is scored
# ---------------------------------------------------------------------------


def test_only_evaluation_files_are_scoreable() -> None:
    from eval.corpus import load_manifest, scoreable_entries

    assert {e.split for e in scoreable_entries()} == {"eval"}
    assert {e.split for e in load_manifest()} == {"dev", "eval", "holdout"}


def test_scoring_a_development_file_is_refused() -> None:
    """Scoring what patterns were authored from measures memorisation."""
    from eval.corpus import load_manifest
    from eval.errors import ScoringError
    from eval.labels import load_labels
    from eval.score import score_file

    dev = next(e for e in load_manifest() if e.split == "dev")
    any_labels = load_labels()[0]

    with pytest.raises(ScoringError, match="dev"):
        score_file(dev, any_labels)


def test_a_label_outside_the_evaluation_split_is_refused_by_the_contract() -> None:
    from pydantic import ValidationError

    from api.models.label import Determinability, FieldLabel, FileLabels, LabelProvenance

    provenance = LabelProvenance(
        labelled_by="tester",
        labelled_at="2026-01-01T00:00:00Z",
        authored_from="corpus/x.cfg",
    )
    field = FieldLabel(
        field="ssh_version",
        determinability=Determinability.NOT_DETERMINABLE,
        rationale="constructed",
    )

    with pytest.raises(ValidationError, match="split"):
        FileLabels(
            corpus_path="cisco/dev/rtr-core-01.cfg",
            split="dev",
            vendor="cisco",
            os_family="ios",
            file_sha256="0" * 64,
            provenance=provenance,
            fields=(field,),
        )


# ---------------------------------------------------------------------------
# The harness does not improve its own score
# ---------------------------------------------------------------------------


def test_the_harness_touches_no_pack_rule_or_snippet() -> None:
    """A harness that edits what it measures is not a harness."""
    offenders: list[str] = []
    for path in _sources(EVAL):
        source = path.read_text(encoding="utf-8")
        for directory in ("packs/", "rules/", "snippets/"):
            if directory in source:
                offenders.append(f"{path.name} references {directory}")
    assert offenders == [], "\n".join(offenders)


def test_metrics_module_performs_no_io() -> None:
    """Arithmetic over outcomes, so every metric is testable without a corpus."""
    source = (EVAL / "metrics.py").read_text(encoding="utf-8")
    for pattern in ("open(", "read_text", "Path(", "yaml", "sqlite3"):
        assert pattern not in source, f"metrics.py performs I/O via {pattern!r}"
