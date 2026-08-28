"""Architecture tests for the confirmation loop (P11).

`api/train/` is the one package permitted to compose the advisory branch with
storage. That makes it the most dangerous package in the repository, so it is
also the most constrained: it may join `learn`, `db`, `audit`, `ingest.packs`,
`parse` and `models`, and it may reach nothing that decides anything.

The guards here are the P10 learn guards continued one step further on. Three
matter most:

  * a compiled pattern always names the human decision it came from;
  * only scrubbed text reaches this layer;
  * nothing here can build a path into the PAN-OS holdout.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
API = REPO_ROOT / "api"
TRAIN = API / "train"
CORPUS = REPO_ROOT / "corpus"


def _sources(package: Path) -> list[Path]:
    return sorted(package.rglob("*.py")) if package.is_dir() else []


def _module_names() -> list[str]:
    return [p.name for p in _sources(TRAIN)]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def _strings(path: Path, *, skip_docs: bool = True) -> list[str]:
    """Every string literal, optionally excluding docstrings.

    Documentation is allowed to explain why the holdout must not be read; code
    is not allowed to name a path into it. Separating the two is what lets the
    guard be strict without forbidding the explanation.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    documentation = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if skip_docs and id(node) in documentation:
                continue
            out.append(node.value)
    return out


def test_the_train_package_is_populated() -> None:
    """Vacuous guards are worse than none: they read as enforcement."""
    assert _module_names(), "api/train/ is empty; these guards would pass vacuously"


# ---------------------------------------------------------------------------
# Rule 1 and Rule 4 — what the loop may never reach
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("forbidden", ["api.comply", "api.remediate", "api.report", "api.analyse"])
def test_train_does_not_reach_deciding_layers(forbidden: str) -> None:
    """A confirmation is a mapping, never a verdict and never a command."""
    offenders = [
        f"{path.relative_to(REPO_ROOT)} imports {module}"
        for path in _sources(TRAIN)
        for module in _imports(path)
        if module == forbidden or module.startswith(f"{forbidden}.")
    ]
    assert offenders == [], "\n".join(offenders)


def test_train_reaches_no_verdict_or_command_symbol() -> None:
    """Belt and braces: names, not only import paths.

    An import guard is defeated by a late import inside a function. Checking for
    the symbols themselves catches the shape of the mistake rather than one
    spelling of it.
    """
    banned = ("Verdict", "evaluate_device", "RemediationSnippet", "resolve_remediation")
    offenders: list[str] = []
    for path in _sources(TRAIN):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        documentation = {
            id(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in banned:
                offenders.append(f"{path.name} references {node.id}")
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in documentation
                and any(b in node.value for b in banned)
            ):
                offenders.append(f"{path.name} names {node.value!r}")
    assert offenders == [], "\n".join(offenders)


def test_train_has_no_network_capability() -> None:
    """Rule 6 — offline first. Nothing in the loop talks to anything."""
    banned = {"socket", "http", "urllib", "urllib.request", "requests", "httpx", "ftplib"}
    offenders: list[str] = []
    for path in _sources(TRAIN):
        for module in _imports(path):
            root = module.split(".")[0]
            if root in banned or module in banned:
                offenders.append(f"{path.name} imports {module}")
    assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# Rule 6 / D12 — only scrubbed text reaches this layer
# ---------------------------------------------------------------------------


def test_train_never_touches_a_raw_line() -> None:
    """`ConfigNode.raw_line` is the unredacted text an operator wrote.

    The training queue reaches a person and an embedding model, so it carries the
    scrubbed form only (decision D12). The raw line stays reachable through
    evidence, where a report quotes it — and nowhere near here.
    """
    offenders: list[str] = []
    for path in _sources(TRAIN):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "raw_line":
                offenders.append(f"{path.name} reads .raw_line")
    assert offenders == [], "only scrubbed text may enter the training loop (D12):\n" + "\n".join(
        offenders
    )


def test_the_persisted_queue_stores_only_scrubbed_text() -> None:
    """The migration must not offer a column a raw line could be written to."""
    sql = (REPO_ROOT / "api" / "db" / "migrations" / "operational" / "0003_training.sql").read_text(
        encoding="utf-8"
    )

    assert "text_scrubbed" in sql
    assert "raw_line_scrubbed" in sql
    # A column literally named for the unredacted line would be an invitation.
    assert "raw_line " not in sql.replace("raw_line_scrubbed", "")


# ---------------------------------------------------------------------------
# The holdout stays sealed (extends the P10 guard to api/train/)
# ---------------------------------------------------------------------------


def test_no_train_code_builds_a_path_into_the_holdout() -> None:
    """Naming the rule is fine; reaching the files is not.

    The identical guard `api/learn/` has carried since P10, extended to the layer
    that now writes packs. A confirmation loop able to construct a holdout path
    could seed the index — or a pack — from the files the generalisation
    experiment depends on never having been read.
    """
    for fragment in ("holdout/", "corpus/holdout", "panos", "paloalto"):
        offenders = [
            f"{path.name} builds {fragment!r}"
            for path in _sources(TRAIN)
            for text in _strings(path)
            if fragment in text.lower()
        ]
        assert offenders == [], "\n".join(offenders)


def test_train_reads_no_corpus_directory() -> None:
    """Decision D43, extended.

    `api/learn/` was caught at P10 reading `corpus/*/dev/` at runtime, and the
    fix was to take the corpus as an argument. Production code that depends on a
    development data directory breaks on the first install that lacks one — and
    `api/train/` runs in exactly those installs.

    Path-shaped references only. An error message that *explains* why a claim
    needs a real corpus file is documentation reaching a person at the moment
    they need it, and forbidding the word itself would delete the explanation
    while changing nothing about what the code is able to open.
    """
    offenders = [
        f"{path.name} names {text!r}"
        for path in _sources(TRAIN)
        for text in _strings(path)
        if "corpus/" in text.lower() or "corpus\\" in text.lower()
    ]
    assert offenders == [], "\n".join(offenders)


def _corpus_lines(splits: set[str]) -> set[str]:
    """Lines from the named splits. `holdout` is refused, never read."""
    assert "holdout" not in splits, "this helper must never open a held-out file"
    manifest = yaml.safe_load((CORPUS / "MANIFEST.yaml").read_text(encoding="utf-8"))
    lines: set[str] = set()
    for entry in manifest["files"]:
        if entry["split"] not in splits:
            continue
        text = (CORPUS / entry["path"]).read_text(encoding="utf-8")
        lines |= {line.strip() for line in text.split("\n") if line.strip()}
    return lines


def test_no_trained_pack_quotes_an_evaluation_or_holdout_line() -> None:
    """A compiled pack may not carry an answer from a file being scored.

    Same shape as the P10 index guard, applied to the packs P11 writes. A pack
    example that appears in an evaluation file and in no development file would
    mean the thing being measured had been taught the answer.

    The holdout is skipped without being opened: nothing in the index or in any
    pack could have come from a file no code has ever read, and reading it here
    to prove that would be the very thing the guard exists to prevent.
    """
    trained = REPO_ROOT / "packs" / "trained"
    pack_files = [p for p in trained.rglob("*.yaml") if p.name != "activation.yaml"]
    if not pack_files:
        pytest.skip("no trained pack on disk; the guard applies when one exists")

    protected = _corpus_lines({"eval"})
    development = _corpus_lines({"dev"})

    offenders: list[str] = []
    for path in pack_files:
        pack = yaml.safe_load(path.read_text(encoding="utf-8"))
        for pattern in pack.get("patterns") or []:
            for example in pattern.get("examples") or []:
                text = example.strip()
                if text in protected and text not in development:
                    offenders.append(f"{path.name}:{pattern['id']} quotes {text!r}")
    assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# Provenance — a pattern always names the person it came from
# ---------------------------------------------------------------------------


def test_a_suggestion_alone_cannot_become_a_pattern() -> None:
    """The learning loop's whole safety argument, asserted on a signature.

    `compile_pattern` takes a `TrainingExample`. There is deliberately no overload
    accepting a `Suggestion`, because the difference between the two is the
    difference between what a model proposed and what a human decided.
    """
    import inspect

    from api.train.compile import compile_pattern

    signature = inspect.signature(compile_pattern)
    annotation = signature.parameters["example"].annotation
    assert "TrainingExample" in str(annotation)
    assert "Suggestion" not in str(signature)


def test_compiled_patterns_are_marked_admin_trained() -> None:
    """A generated pattern must never be indistinguishable from a shipped one."""
    source = (TRAIN / "compile.py").read_text(encoding="utf-8")
    assert "PatternSource.ADMIN_TRAINED" in source
    assert "PatternProvenance(" in source
    assert "training_example_id=" in source
    assert "audit_seq=" in source
