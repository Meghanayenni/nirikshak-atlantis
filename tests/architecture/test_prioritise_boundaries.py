"""Architecture tests for the Prioritise stage (P12).

Prioritisation sits between the engine that decides and the report that renders,
and it is the layer most likely to acquire a shortcut: ranking is easy to fake,
and a fake ranking is indistinguishable from a real one at a glance.

So the guards here are less about imports than about *claims*. The important
ones assert that this layer cannot produce a score it did not establish, cannot
reach a verdict, and cannot fall back to sorting by severity.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
API = REPO_ROOT / "api"
PRIORITISE = API / "prioritise"


def _sources(package: Path) -> list[Path]:
    return sorted(package.rglob("*.py")) if package.is_dir() else []


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


def _code_strings(path: Path) -> list[str]:
    """String literals excluding docstrings — prose may explain, code may not act."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docs = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
    }
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docs
    ]


def test_the_prioritise_package_is_populated() -> None:
    assert _sources(PRIORITISE), "api/prioritise/ is empty; these guards would pass vacuously"


# ---------------------------------------------------------------------------
# What it may not reach
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "forbidden",
    [
        "api.comply",
        "api.parse",
        "api.normalise",
        "api.learn",
        "api.train",
        "api.remediate",
        "api.report",
        "api.ingest",
        "api.db",
        "api.audit",
    ],
)
def test_prioritise_reaches_no_other_layer(forbidden: str) -> None:
    """It may import `api.models` and itself. Nothing else.

    A whitelist in effect, so a layer written after P12 is forbidden too without
    anybody remembering to add it.
    """
    offenders = [
        f"{path.relative_to(REPO_ROOT)} imports {module}"
        for path in _sources(PRIORITISE)
        for module in _imports(path)
        if module == forbidden or module.startswith(f"{forbidden}.")
    ]
    assert offenders == [], "\n".join(offenders)


def test_prioritise_uses_no_machine_learning() -> None:
    """The Concept Report: peer analysis "requires no model".

    Not a preference. A baseline is counting, and a counting routine that
    acquired an embedding would stop being explainable — which is the property
    the feature is sold on.
    """
    banned = {"sentence_transformers", "torch", "faiss", "numpy", "sklearn", "scipy"}
    offenders = [
        f"{path.name} imports {module}"
        for path in _sources(PRIORITISE)
        for module in _imports(path)
        if module.split(".")[0] in banned
    ]
    assert offenders == [], "\n".join(offenders)


def test_prioritise_has_no_network_capability() -> None:
    banned = {"socket", "http", "urllib", "requests", "httpx", "ftplib"}
    offenders = [
        f"{path.name} imports {module}"
        for path in _sources(PRIORITISE)
        for module in _imports(path)
        if module.split(".")[0] in banned
    ]
    assert offenders == [], "\n".join(offenders)


def test_prioritise_produces_no_verdict() -> None:
    """A rank is not a judgement.

    An outlier is an observation about a fleet and an exposure score is a
    property of a control's reachability. Neither says whether the device passes,
    and this layer has no name for one — the same separation decision D22 drew
    between ACL observations and compliance findings.
    """
    banned = ("Verdict", "evaluate_device", "PASS", "FAIL")
    offenders: list[str] = []
    for path in _sources(PRIORITISE):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in banned:
                offenders.append(f"{path.name} references {node.id}")
        for text in _code_strings(path):
            if any(b in text for b in ("Verdict", "evaluate_device")):
                offenders.append(f"{path.name} names {text!r}")
    assert offenders == [], "\n".join(offenders)


def test_prioritise_names_no_vendor() -> None:
    """Exposure reasoning is vendor-neutral, like everything downstream of the pack."""
    vendors = ["cisco", "arista", "juniper", "paloalto", "panos", "fortinet", "ios", "junos"]
    offenders = [
        f"{path.name} names {v!r}"
        for path in _sources(PRIORITISE)
        for text in _code_strings(path)
        for v in vendors
        if v in text.lower()
    ]
    assert offenders == [], "\n".join(offenders)


def test_no_prioritise_code_builds_a_path_into_the_holdout() -> None:
    """The guard `learn` has carried since P10 and `train` since P11."""
    for fragment in ("holdout/", "corpus/holdout", "panos", "paloalto"):
        offenders = [
            f"{path.name} builds {fragment!r}"
            for path in _sources(PRIORITISE)
            for text in _code_strings(path)
            if fragment in text.lower()
        ]
        assert offenders == [], "\n".join(offenders)


def test_prioritise_reads_no_corpus_directory() -> None:
    """Decision D43's rule, extended again: production code owns no dev data."""
    offenders = [
        f"{path.name} names {text!r}"
        for path in _sources(PRIORITISE)
        for text in _code_strings(path)
        if "corpus/" in text.lower() or "corpus\\" in text.lower()
    ]
    assert offenders == [], "\n".join(offenders)


def test_prioritise_never_reads_a_raw_line() -> None:
    """Ranking has no reason to touch configuration text."""
    offenders: list[str] = []
    for path in _sources(PRIORITISE):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in {"raw_line", "text"}:
                offenders.append(f"{path.name} reads .{node.attr}")
    assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# The claim guards — the ones that carry the weight
# ---------------------------------------------------------------------------


def test_severity_alone_cannot_produce_a_score() -> None:
    """DEVELOPER_GUIDE.md §7 — "Severity alone must not determine remediation order."

    Asserted structurally rather than by reading the code: a severity weight is
    only ever multiplied by a reachability term, and reachability can only be
    computed from interfaces. With no interfaces there is no product, so there is
    no score however severe the finding.
    """
    from api.models.enums import Severity
    from api.prioritise.exposure import SEVERITY_WEIGHT, management_exposure

    assert management_exposure(()) == 0.0
    for severity in Severity:
        assert SEVERITY_WEIGHT[severity] * management_exposure(()) == 0.0


def test_an_undetermined_exposure_cannot_carry_a_score() -> None:
    """The invariant that stops "we could not tell" becoming a sortable number."""
    from api.prioritise.errors import ExposureError
    from api.prioritise.exposure import ExposureAssessment, ExposureDeterminacy

    with pytest.raises(ExposureError, match="no number"):
        ExposureAssessment(determinacy=ExposureDeterminacy.NO_ACL_DATA, score=0.9, reason="x")


def test_a_determined_exposure_must_carry_a_score() -> None:
    from api.prioritise.errors import ExposureError
    from api.prioritise.exposure import ExposureAssessment, ExposureDeterminacy

    with pytest.raises(ExposureError, match="carries no score"):
        ExposureAssessment(determinacy=ExposureDeterminacy.DETERMINED)


def test_every_undetermined_state_must_name_what_was_missing() -> None:
    """ "Undetermined" alone sends an operator hunting for a bug."""
    from api.prioritise.errors import ExposureError
    from api.prioritise.exposure import ExposureAssessment, ExposureDeterminacy

    with pytest.raises(ExposureError, match="must name what was missing"):
        ExposureAssessment(determinacy=ExposureDeterminacy.NO_INTERFACE_DATA)


def test_unknown_is_not_counted_as_absent() -> None:
    """The peer-baseline equivalent of DEF-2, guarded at the definition.

    "Forty-seven have logging and three do not" is only true if those three were
    read. A field that abstained is not a field that is missing, and counting it
    as one manufactures drift out of our own parsing gaps.
    """
    from api.models.enums import FieldState
    from api.prioritise.baseline import DETERMINABLE_STATES

    assert FieldState.UNKNOWN not in DETERMINABLE_STATES
    assert FieldState.PRESENT in DETERMINABLE_STATES
