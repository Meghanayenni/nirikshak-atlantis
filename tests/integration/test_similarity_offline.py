"""The similarity layer against the real corpus, with no model installed (P10).

Two things are checked here that a unit test cannot.

**The seed index is real.** It is built from the shipped vendor packs, and every
entry's provenance is re-verified against the development configurations —
11 pairs, 8 fields, one vendor. That number is small and the test asserts it, so
the day it grows somebody has to look at where the growth came from.

**Nothing breaks with the `[ai]` extra absent.** The model is not installed on
this machine and is not required to be. Clustering, indexing and ranking all
work; only embedding raises, and it raises a typed error that names what is
missing rather than failing somewhere inside a library.

The PAN-OS holdout is never read. The similarity layer has no code path that
could reach it, and the index is built from `dev` only.
"""

from __future__ import annotations

import hashlib
import pathlib

import pytest

from api.ingest.packs import find_pack, load_active_packs
from api.learn.cluster import cluster_unknown_lines, confirmable
from api.learn.embedding import MODEL_NAME, availability, embed, require_model
from api.learn.errors import ModelUnavailableError
from api.learn.index import build_index, verify_provenance
from api.learn.suggest import suggest_for_vectors, suggestions_are_evidence
from api.models.enums import ConfidenceMethod, ExampleSource
from api.normalise.service import build_csm
from api.parse.service import parse_configuration

OS_FAMILY = {"cisco": "ios", "arista": "eos", "juniper": "junos"}
CORPUS = pathlib.Path("corpus")


@pytest.fixture(scope="module")
def development_lines() -> set[str]:
    """Every line of every development configuration.

    Supplied by the test rather than read inside `api/learn/`: production code
    must not depend on a `corpus/` directory that no deployment has.
    """
    lines: set[str] = set()
    for vendor_dir in sorted(CORPUS.iterdir()):
        dev = vendor_dir / "dev"
        if not dev.is_dir():
            continue
        for path in sorted(dev.iterdir()):
            text = path.read_text(encoding="utf-8", errors="replace")
            lines |= {line.strip() for line in text.splitlines() if line.strip()}
    return lines


@pytest.fixture(scope="module")
def index(development_lines: set[str]):
    return build_index(load_active_packs(use_cache=False), development_lines=development_lines)


def unknown_lines_for(relative: str):
    """Parse one corpus file and return its unknown-line queue.

    Only ever called with `dev` or `eval` paths. The holdout has no pack, and
    `find_pack` would return `None` for it.
    """
    path = CORPUS / relative
    vendor = relative.split("/")[0]
    pack = find_pack(vendor, OS_FAMILY[vendor], load_active_packs(use_cache=False))
    text = path.read_text(encoding="utf-8")
    file_id = hashlib.sha256(text.encode("utf-8")).hexdigest()
    parsed = parse_configuration(text, pack, file_id=file_id, file_path=relative)
    return build_csm(parsed, pack, device_id=file_id).residue


# ---------------------------------------------------------------------------
# The seed index
# ---------------------------------------------------------------------------


def test_the_index_is_built_from_development_packs(index) -> None:
    """D38 — small, and stated. 19 pairs across 9 fields at P17.

    Was 11 pairs over 8 fields from one pack. The NX-OS pack added the rest,
    so the index now spans two *platforms* — still one vendor, and still far
    too small to support any claim about retrieval.
    """
    assert len(index.entries) == 19
    assert len(index.fields) == 9
    assert index.vendors == {"cisco"}


def test_every_entry_traces_to_a_development_configuration(index, development_lines) -> None:
    """Re-verified against the corpus, not trusted from the pack declaration."""
    assert verify_provenance(index.entries, development_lines) == []


def test_every_entry_is_a_seed_with_a_named_origin(index) -> None:
    origins = {entry.origin.split(":")[0] for entry in index.entries}
    assert origins == {"cisco/ios", "cisco/nxos"}

    for entry in index.entries:
        assert entry.source is ExampleSource.SEED
        assert ":p-" in entry.origin, "an entry must name the pattern it came from"


def test_the_index_describes_its_own_size_honestly(index) -> None:
    """The sentence the report and the training screen print."""
    described = index.describe()
    assert "19 labelled examples" in described
    assert "9 fields" in described
    assert "1 vendor" in described


def test_no_identity_pattern_leaks_into_the_index(index) -> None:
    """Hostname and OS version are not canonical security fields.

    Indexing them would let the layer propose `hostname` as the meaning of a
    security directive.
    """
    assert "hostname" not in index.fields
    assert "os_version" not in index.fields
    assert "model" not in index.fields


# ---------------------------------------------------------------------------
# Clustering the real queue
# ---------------------------------------------------------------------------


def test_the_arista_queue_no_longer_carries_comment_noise() -> None:
    """DEF-9 — 23 of 57 residue lines were `!` before the 1.0.1 pack.

    The queue is what an administrator reads one line at a time at P11, and
    comment noise there is how careless confirmations happen.
    """
    lines = unknown_lines_for("arista/dev/sw-leaf-01.cfg")
    assert lines
    assert all(not line.raw_line_scrubbed.strip().startswith("!") for line in lines)


def test_repeated_shapes_collapse_into_one_decision() -> None:
    """The point of clustering: one confirmation covering many devices."""
    lines = list(unknown_lines_for("cisco/dev/rtr-core-01.cfg"))
    lines += list(unknown_lines_for("cisco/dev/sw-access-02.cfg"))

    clusters = cluster_unknown_lines(lines)
    assert clusters
    assert len(clusters) < len(lines), "clustering collapsed nothing"
    assert all(c.size >= 1 for c in clusters)


def test_clusters_are_ordered_by_attention_deserved() -> None:
    lines = list(unknown_lines_for("juniper/dev/srx-edge-01.conf"))
    clusters = cluster_unknown_lines(lines)
    sizes = [c.size for c in clusters]
    assert sizes == sorted(sizes, reverse=True)


def test_confirmable_clusters_exclude_generic_shapes() -> None:
    lines = list(unknown_lines_for("cisco/dev/rtr-core-01.cfg"))
    clusters = cluster_unknown_lines(lines)
    assert all(c.is_confirmable for c in confirmable(clusters))


def test_clustering_needs_no_model() -> None:
    """It is deterministic string grouping, and must work with the extra absent.

    Asserted by doing the work and checking the result, not by asking whether a
    model happens to be installed — the point is that the answer is the same
    either way.
    """
    clusters = cluster_unknown_lines(unknown_lines_for("arista/eval/sw-leaf-07.cfg"))

    assert clusters
    assert all(c.signature for c in clusters)
    assert cluster_unknown_lines(unknown_lines_for("arista/eval/sw-leaf-07.cfg")) == clusters


# ---------------------------------------------------------------------------
# The model is an environment prerequisite (decision D40)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(availability().available, reason="the [ai] extra is installed here")
def test_embedding_raises_a_typed_error_when_the_model_is_absent() -> None:
    with pytest.raises(ModelUnavailableError):
        embed(["ip ssh version 2"])

    with pytest.raises(ModelUnavailableError):
        require_model()


@pytest.mark.skipif(availability().available, reason="the [ai] extra is installed here")
def test_the_refusal_names_what_is_missing_and_where_to_read_about_it() -> None:
    with pytest.raises(ModelUnavailableError) as caught:
        embed(["ip ssh version 2"])

    message = str(caught.value)
    assert "sentence-transformers" in message
    assert MODEL_NAME in message
    assert "never committed to this repository" in message
    assert "docs/adr/0018-model-acquisition.md" in message


@pytest.mark.skipif(availability().available, reason="the [ai] extra is installed here")
def test_airgap_is_named_in_the_refusal_when_it_would_block_a_fetch() -> None:
    """Rule 6 — failing closed is the intended behaviour, and it says so."""
    with pytest.raises(ModelUnavailableError) as caught:
        embed(["ip ssh version 2"], airgap=True)

    assert "airgap" in str(caught.value)
    assert "Failing closed is the intended behaviour" in str(caught.value)


def test_the_probe_answers_without_installing_or_downloading_anything() -> None:
    state = availability()
    assert isinstance(state.available, bool)
    assert state.available == (state.package_installed and state.weights_present)


def test_importing_the_layer_does_not_require_the_extra() -> None:
    """Eight phases do not need a model; the suite must run without one."""
    import api.learn.cluster  # noqa: F401
    import api.learn.embedding  # noqa: F401
    import api.learn.index  # noqa: F401
    import api.learn.suggest  # noqa: F401


# ---------------------------------------------------------------------------
# The gate holds over real data
# ---------------------------------------------------------------------------


def test_retrieval_over_the_real_index_stays_uncalibrated(index) -> None:
    """Constructed vectors against the real index, so no model is needed.

    The point is not the ranking — it is that whatever comes back is still
    uncalibrated and therefore still forces the field to UNKNOWN.
    """
    width = 8
    query = [1.0] + [0.0] * (width - 1)
    vectors = [[1.0] + [0.0] * (width - 1) for _ in index.entries]

    suggestions = suggest_for_vectors(query, vectors, index)

    assert suggestions
    assert len(suggestions) <= 3
    for suggestion in suggestions:
        assert suggestion.confidence_method is ConfidenceMethod.UNCALIBRATED_SIMILARITY
        assert suggestion.calibrated_confidence is None
        assert not suggestion.confidence_method.is_probability
    assert suggestions_are_evidence(suggestions) is False


def test_no_suggestion_can_reach_a_canonical_field() -> None:
    """A suggestion names a field; it never carries a value for one.

    Together with the forbidden edge `normalise -> learn`, this is why the P9
    wrong-confident rate cannot move at P10.
    """
    from api.models.training import Suggestion

    assert "value" not in Suggestion.model_fields


# ---------------------------------------------------------------------------
# The model, where it is present
# ---------------------------------------------------------------------------
#
# Every test above covers the REFUSAL and skips where the model is installed.
# On a machine with the [ai] extra and the weights present, that left `embed` —
# the entry point to the entire similarity layer — asserted by nothing. The same
# shape as the PDF finding in ADR 0041: a capability that works, and a suite
# that would stay green if it stopped.


@pytest.mark.skipif(
    not availability().available, reason="the embedding model is absent in this environment"
)
def test_embedding_produces_vectors_when_the_model_is_present() -> None:
    """The positive path. Deliberately asserts shape, not values.

    An embedding is not reproducible across versions of the model and pinning
    numbers here would make a legitimate upgrade look like a regression. What
    must hold is that the layer runs: one vector per line, a fixed width, and
    finite numbers rather than NaNs a distance calculation would silently
    propagate.
    """
    import math

    lines = ["ip ssh version 2", "transport input telnet", "no ip http server"]
    vectors = embed(lines)

    assert len(vectors) == len(lines)
    widths = {len(v) for v in vectors}
    assert len(widths) == 1, f"ragged embedding widths: {widths}"
    assert widths.pop() > 0

    for vector in vectors:
        assert all(math.isfinite(component) for component in vector)


@pytest.mark.skipif(
    not availability().available, reason="the embedding model is absent in this environment"
)
def test_embedding_is_deterministic_for_one_line() -> None:
    """Two calls, one answer.

    A retrieval layer that returned different neighbours for the same line on
    consecutive runs would make the training queue unreproducible, and an
    administrator would be confirming against a ranking nobody could recreate.
    """
    first = embed(["ip ssh version 2"])
    second = embed(["ip ssh version 2"])

    assert first == second


@pytest.mark.skipif(
    not availability().available, reason="the embedding model is absent in this environment"
)
def test_a_real_embedding_still_cannot_reach_a_verdict(index) -> None:
    """The gate that matters, exercised with real vectors rather than constructed ones.

    `test_retrieval_over_the_real_index_stays_uncalibrated` makes this claim
    with hand-built vectors, which proves the arithmetic. This proves it on the
    path a deployment actually takes: a real model, real embeddings, real
    neighbours — and still UNCALIBRATED_SIMILARITY, still not evidence.
    """
    query = embed(["ip ssh version 2"])[0]
    vectors = embed([entry.text for entry in index.entries])

    suggestions = suggest_for_vectors(query, vectors, index)

    assert suggestions
    for suggestion in suggestions:
        assert suggestion.confidence_method is ConfidenceMethod.UNCALIBRATED_SIMILARITY
        assert suggestion.calibrated_confidence is None
    assert suggestions_are_evidence(suggestions) is False
