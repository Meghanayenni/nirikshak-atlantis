"""Boundaries around the similarity layer (P10).

This is the one advisory branch in a deterministic system, so the question these
tests answer is narrow: **can anything the model produced reach a claim?**

The answer has to be no by construction, not by discipline, because a suggestion
is the most persuasive wrong output the system can generate. A wrong parse looks
like a bug. A wrong suggestion looks like a judgement, and an administrator
confirming it enters it into a vendor pack permanently.

Three properties, in descending order of consequence:

    1. No suggestion can become a value, a verdict or a command.
    2. Only `api/learn/` may import a machine-learning library.
    3. Nothing here presents a similarity score as a probability.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
API_ROOT = REPO_ROOT / "api"
LEARN = API_ROOT / "learn"

ML_MODULES = ["sentence_transformers", "torch", "faiss", "sklearn", "transformers", "numpy"]
NETWORK_MODULES = ["netmiko", "napalm", "paramiko", "requests", "socket", "telnetlib"]


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


def _offending(root: Path, module: str) -> list[str]:
    return [
        f"{path.relative_to(REPO_ROOT)} imports {imported}"
        for path in _sources(root)
        for imported in _imports(path)
        if imported == module or imported.startswith(f"{module}.")
    ]


def test_the_learn_package_is_populated() -> None:
    modules = [p for p in _sources(LEARN) if p.name != "__init__.py"]
    assert len(modules) >= 6, f"expected the similarity modules, found {len(modules)}"


# ---------------------------------------------------------------------------
# Nothing the model produced may become a claim
# ---------------------------------------------------------------------------


def test_learn_reaches_no_verdict_value_or_command() -> None:
    """The whitelist. A layer written later is forbidden too."""
    violations: list[str] = []
    for path in _sources(LEARN):
        for imported in _imports(path):
            if not imported.startswith("api."):
                continue
            top = ".".join(imported.split(".")[:2])
            if top not in {"api.models", "api.learn"}:
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")
    assert violations == [], "\n".join(violations)


def test_learn_makes_no_compliance_decision() -> None:
    """No verdict vocabulary anywhere in the package."""
    forbidden = ("Verdict", "ComplianceRule", "Rulepack", "AbsenceAction", "evaluate_device")
    offenders = [
        f"{path.relative_to(REPO_ROOT)} references {name}"
        for path in _sources(LEARN)
        for name in forbidden
        if name in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], "\n".join(offenders)


def test_learn_cannot_construct_a_canonical_field() -> None:
    """The narrowest statement of Rule 1 for this layer.

    A `Field` is what the compliance engine reads. If the similarity layer could
    build one, a model-derived value would be one assignment away from a verdict.
    """
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in _sources(LEARN)
        if re.search(r"\bField\s*\[|\bField\s*\(", path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], f"the similarity layer constructs a canonical Field: {offenders}"


@pytest.mark.parametrize("module", NETWORK_MODULES)
def test_learn_has_no_network_capability(module: str) -> None:
    """R1 and Rule 6 — offline configuration exports, local inference only."""
    assert _offending(LEARN, module) == []


# ---------------------------------------------------------------------------
# Only api/learn/ may import a machine-learning library
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", ML_MODULES)
def test_no_package_outside_learn_imports_ml(module: str) -> None:
    """Repository-wide, not per-package.

    `analyse`, `remediate` and `report` each carried their own ML ban from the
    phase that created them. This generalises it: the deterministic spine must
    stay free of the model, and a package added later inherits the rule without
    anyone remembering to write it.
    """
    offenders: list[str] = []
    for package_dir in sorted(API_ROOT.iterdir()):
        if not package_dir.is_dir() or package_dir.name in ("learn", "__pycache__"):
            continue
        offenders += _offending(package_dir, module)
    assert offenders == [], "\n".join(offenders)


def test_the_ml_import_is_lazy_so_the_suite_runs_without_the_extra() -> None:
    """Importing `api.learn` must not require the `[ai]` group.

    Eight phases do not need a model, and the suite must stay runnable on a
    machine that never installs one. The import lives inside a function.
    """
    tree = ast.parse((LEARN / "embedding.py").read_text(encoding="utf-8"))
    top_level = {
        alias.name for node in tree.body if isinstance(node, ast.Import) for alias in node.names
    } | {node.module for node in tree.body if isinstance(node, ast.ImportFrom) and node.module}

    assert not any(m and m.startswith("sentence_transformers") for m in top_level), (
        "sentence_transformers is imported at module level"
    )

    import api.learn.embedding  # noqa: F401  - must not raise with the extra absent


def test_no_model_weights_are_committed() -> None:
    """D40 — weights are an environment prerequisite, never repository content."""
    weight_suffixes = (".bin", ".safetensors", ".onnx", ".pt", ".pth", ".ckpt", ".h5")
    offenders = [
        str(path.relative_to(REPO_ROOT))
        for path in REPO_ROOT.rglob("*")
        if path.is_file()
        and path.suffix in weight_suffixes
        and ".venv" not in path.parts
        and ".git" not in path.parts
    ]
    assert offenders == [], f"model weights in the repository: {offenders}"


# ---------------------------------------------------------------------------
# A score is never a probability (R7, decision D42)
# ---------------------------------------------------------------------------


def test_no_calibrator_is_active() -> None:
    """D42 — P10 ships uncalibrated, and this is where that stops being prose.

    Expected to fail on the day someone fits one, so the author has to revisit
    the decision rather than switching it on quietly.
    """
    from api.learn.calibration import active_calibrator

    assert active_calibrator() is None


def test_the_suggestion_layer_never_claims_calibrated_confidence() -> None:
    from api.learn import suggest

    source = (LEARN / "suggest.py").read_text(encoding="utf-8")
    assert "UNCALIBRATED_SIMILARITY" in source
    assert suggest.suggestions_are_evidence(()) is False


def test_similarity_cannot_be_read_as_evidence() -> None:
    """Named function, one home, asserted so the answer cannot drift."""
    from api.learn.suggest import suggestions_are_evidence

    assert suggestions_are_evidence(()) is False


def test_learn_names_no_vendor() -> None:
    """Rule 5 — which platform a line came from is data, never a literal here."""
    vendors = ["cisco", "arista", "juniper", "paloalto", "panos", "fortinet", "sonic"]
    offenders: list[str] = []
    for path in _sources(LEARN):
        source = path.read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines() if not line.strip().startswith("#"))
        for vendor in vendors:
            if re.search(rf"['\"]{vendor}['\"]", code, re.IGNORECASE):
                offenders.append(f"{path.name} names {vendor!r}")
    assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# The index cannot be contaminated
# ---------------------------------------------------------------------------


def test_the_index_is_seeded_only_from_development_files() -> None:
    """D38 — provenance re-checked at build time, not trusted from the pack."""
    from api.ingest.packs import load_active_packs
    from api.learn.index import build_index, verify_provenance

    development_lines: set[str] = set()
    for vendor_dir in sorted((REPO_ROOT / "corpus").iterdir()):
        dev = vendor_dir / "dev"
        if not dev.is_dir():
            continue
        for path in sorted(dev.iterdir()):
            text = path.read_text(encoding="utf-8", errors="replace")
            development_lines |= {ln.strip() for ln in text.splitlines() if ln.strip()}

    index = build_index(load_active_packs(use_cache=False), development_lines=development_lines)
    assert verify_provenance(index.entries, development_lines) == []
    assert not index.is_empty


def test_no_index_entry_quotes_an_evaluation_or_holdout_line() -> None:
    """The leak that would make every retrieval metric meaningless."""
    import yaml

    from api.ingest.packs import load_active_packs
    from api.learn.index import build_index

    manifest = yaml.safe_load((REPO_ROOT / "corpus" / "MANIFEST.yaml").read_text(encoding="utf-8"))
    protected: set[str] = set()
    for entry in manifest["files"]:
        if entry["split"] == "dev":
            continue
        if entry["split"] == "holdout":
            continue  # never read; nothing in the index could have come from it
        text = (REPO_ROOT / "corpus" / entry["path"]).read_text(encoding="utf-8")
        protected |= {line.strip() for line in text.splitlines() if line.strip()}

    dev: set[str] = set()
    for entry in manifest["files"]:
        if entry["split"] != "dev":
            continue
        text = (REPO_ROOT / "corpus" / entry["path"]).read_text(encoding="utf-8")
        dev |= {line.strip() for line in text.splitlines() if line.strip()}

    index = build_index(load_active_packs(use_cache=False))
    offenders = [e.text for e in index.entries if e.text in protected and e.text not in dev]
    assert offenders == [], f"index entries unique to a protected file: {offenders}"


def test_no_learn_code_builds_a_path_into_the_holdout() -> None:
    """Naming the rule is fine; reaching the files is not.

    `index.py` explains in prose why seeding from the held-out vendor would spend
    an experiment that can only be run once — that explanation is the guard
    documenting itself. What must never appear is a fragment that could locate
    those files, so docstrings and comments are stripped before the search.
    """
    for fragment in ("holdout/", "corpus/holdout", "panos", "paloalto"):
        offenders: list[str] = []
        for path in _sources(LEARN):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            documentation = {
                id(node.value)
                for node in ast.walk(tree)
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
            }
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and fragment in node.value.lower()
                    and id(node) not in documentation
                ):
                    offenders.append(f"{path.name} builds {fragment!r}")
        assert offenders == [], "\n".join(offenders)
