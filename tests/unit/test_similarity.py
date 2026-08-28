"""The similarity layer's arithmetic and its gate (P10).

Everything here runs with the `[ai]` extra **uninstalled**. Signatures,
clustering and ranking are exercised against constructed vectors and constructed
unknown lines; no model is loaded and no corpus is read. That is deliberate — a
retrieval layer tested only through a model is tested only where the model
happens to be installed.

The tests that matter most are the ones about the gate.
`test_a_perfect_score_is_still_not_a_confidence` is the whole safety argument
for this phase in one assertion: a similarity of 1.0 produces a suggestion that
still forces the field to UNKNOWN.
"""

from __future__ import annotations

import pytest

from api.learn.cluster import cluster_id_for, cluster_unknown_lines, confirmable
from api.learn.errors import UncalibratedScoreError
from api.learn.index import ExampleIndex, IndexEntry
from api.learn.signature import is_generic, signature, token_shape
from api.learn.suggest import (
    MAX_SUGGESTIONS,
    RankedCandidate,
    assert_never_confidence,
    cosine,
    rank_candidates,
    suggest_for_vectors,
    suggestions_are_evidence,
    to_suggestions,
)
from api.models.csm import UnknownLine
from api.models.enums import ConfidenceMethod, ExampleSource


def line(text: str, *, number: int = 1, file_id: str = "f1") -> UnknownLine:
    return UnknownLine(
        line_number=number,
        raw_line_scrubbed=text,
        normalised_line="",
        file_id=file_id,
    )


def entry(field: str, text: str, vendor: str = "fixture-vendor") -> IndexEntry:
    return IndexEntry(
        text=text,
        field=field,
        vendor=vendor,
        os_family="fixture-os",
        source=ExampleSource.SEED,
        origin="constructed-fixture",
        signature=signature(text),
    )


# ---------------------------------------------------------------------------
# Signatures — readable, and stable
# ---------------------------------------------------------------------------


def test_values_become_typed_placeholders() -> None:
    assert signature("ntp server 192.0.2.20") == "ntp server <IP>"
    assert signature("exec-timeout 10 0") == "exec-timeout <N> <N>"
    assert signature("version 17.9") == "version <VER>"


def test_the_same_command_with_different_values_shares_a_signature() -> None:
    """The property clustering rests on."""
    assert signature("ntp server 192.0.2.20") == signature("ntp server 198.51.100.9")
    assert signature("exec-timeout 10 0") == signature("exec-timeout 30 0")


def test_different_commands_do_not_share_a_signature() -> None:
    assert signature("ntp server 192.0.2.20") != signature("logging host 192.0.2.20")


def test_a_version_token_is_not_mistaken_for_an_interface() -> None:
    """`v2` satisfies the interface shape, and reads as a mistake if labelled one.

    Not a clustering error — both groupings are identical — but the signature is
    shown to an administrator beside the line, and `protocol-version <IF>` looks
    like a broken tool.
    """
    assert signature("set system services ssh protocol-version v2").endswith("<VER>")
    assert token_shape("v2") == "<VER>"
    assert token_shape("ge-0/0/2") == "<IF>"


def test_indentation_and_spacing_do_not_change_a_signature() -> None:
    """Indentation is structure, already carried by `block_path`."""
    assert signature("  transport input ssh") == signature("transport input ssh")
    assert signature("transport   input  ssh") == signature("transport input ssh")


def test_a_signature_of_only_placeholders_is_generic() -> None:
    """Such a shape describes a fragment, not a command."""
    assert is_generic(signature("192.0.2.1 255.255.255.0"))
    assert not is_generic(signature("ntp server 192.0.2.20"))


def test_an_empty_line_has_no_signature() -> None:
    assert signature("") == ""
    assert signature("   ") == ""


def test_a_very_long_line_is_truncated_rather_than_unreadable() -> None:
    sig = signature(" ".join(["token"] * 60))
    assert sig.endswith("...")
    assert len(sig.split()) <= 25


# ---------------------------------------------------------------------------
# Clustering — deterministic grouping
# ---------------------------------------------------------------------------


def test_lines_with_one_shape_form_one_cluster() -> None:
    clusters = cluster_unknown_lines(
        [
            line("ntp server 192.0.2.20", number=1),
            line("ntp server 192.0.2.21", number=2),
            line("logging host 192.0.2.10", number=3),
        ]
    )
    assert len(clusters) == 2
    assert clusters[0].size == 2
    assert clusters[0].signature == "ntp server <IP>"


def test_clusters_rank_by_how_much_attention_they_deserve() -> None:
    """A shape on many devices before a shape on one."""
    clusters = cluster_unknown_lines(
        [line("ntp server 192.0.2.20", number=1, file_id=f"f{i}") for i in range(5)]
        + [line("banner motd ^C", number=2)]
    )
    assert clusters[0].signature == "ntp server <IP>"
    assert clusters[0].size == 5
    assert clusters[0].file_count == 5


def test_clustering_is_deterministic() -> None:
    """A queue that reshuffles under the administrator is unusable."""
    lines = [line(f"ntp server 192.0.2.{i}", number=i) for i in range(1, 6)]
    assert cluster_unknown_lines(lines) == cluster_unknown_lines(list(reversed(lines)))


def test_a_cluster_id_is_stable_across_runs_and_machines() -> None:
    """What lets a confirmation recorded once apply to the same shape later."""
    assert cluster_id_for("ntp server <IP>") == cluster_id_for("ntp server <IP>")
    assert cluster_id_for("ntp server <IP>") != cluster_id_for("logging host <IP>")


def test_the_exemplar_is_stable() -> None:
    clusters = cluster_unknown_lines(
        [line("ntp server 192.0.2.9", number=9), line("ntp server 192.0.2.1", number=1)]
    )
    assert clusters[0].exemplar.line_number == 1


def test_a_generic_cluster_is_never_offered_as_one_decision() -> None:
    """One confirmation over it would cover lines with nothing in common."""
    clusters = cluster_unknown_lines(
        [line("192.0.2.1 255.255.255.0"), line("ntp server 192.0.2.1")]
    )
    generic = [c for c in clusters if c.generic]

    assert generic, "this fixture should produce a generic shape"
    assert all(not c.is_confirmable for c in generic)
    assert all(c.signature != generic[0].signature for c in confirmable(clusters))


def test_blank_lines_never_reach_a_cluster() -> None:
    assert cluster_unknown_lines([line("   ", number=1)]) == ()


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------


def test_cosine_of_identical_unit_vectors_is_one() -> None:
    assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_mismatched_vector_widths_raise() -> None:
    """A silent truncation would compare vectors from two different models."""
    with pytest.raises(ValueError, match="width mismatch"):
        cosine([1.0, 0.0], [1.0, 0.0, 0.0])


def test_the_closest_example_ranks_first() -> None:
    index = ExampleIndex(
        entries=(
            entry("ssh_version", "ip ssh version 2"),
            entry("ntp_servers", "ntp server 192.0.2.99"),
        )
    )
    ranked = rank_candidates([1.0, 0.0], [[1.0, 0.0], [0.0, 1.0]], index)

    assert ranked[0].entry.field == "ssh_version"
    assert ranked[0].score == pytest.approx(1.0)


def test_ranking_is_stable_when_scores_tie() -> None:
    """An ambiguous ranking must still be a reproducible one."""
    index = ExampleIndex(entries=(entry("zzz_field", "z"), entry("aaa_field", "a")))
    ranked = rank_candidates([1.0, 0.0], [[1.0, 0.0], [1.0, 0.0]], index)

    assert [c.entry.field for c in ranked] == ["aaa_field", "zzz_field"]


def test_at_most_three_suggestions_are_produced() -> None:
    index = ExampleIndex(entries=tuple(entry(f"field_{i}", f"line {i}") for i in range(10)))
    vectors = [[1.0, 0.0]] * 10
    assert len(suggest_for_vectors([1.0, 0.0], vectors, index)) == MAX_SUGGESTIONS


def test_one_field_never_occupies_two_slots() -> None:
    """Three examples of one field is one answer, not three.

    Offering it repeatedly would waste every slot and hide the alternatives the
    administrator needs to choose between.
    """
    index = ExampleIndex(
        entries=(
            entry("ntp_servers", "ntp server 192.0.2.20"),
            entry("ntp_servers", "ntp server 192.0.2.21"),
            entry("ssh_version", "ip ssh version 2"),
        )
    )
    suggestions = suggest_for_vectors([1.0, 0.0], [[1.0, 0.0], [1.0, 0.0], [0.9, 0.1]], index)

    assert [s.field for s in suggestions] == ["ntp_servers", "ssh_version"]
    assert [s.rank for s in suggestions] == [1, 2]


def test_an_empty_index_suggests_nothing() -> None:
    """Not a zero-score guess. Nothing."""
    assert suggest_for_vectors([1.0, 0.0], [], ExampleIndex(entries=())) == ()


def test_a_vector_count_mismatch_raises() -> None:
    index = ExampleIndex(entries=(entry("ssh_version", "ip ssh version 2"),))
    with pytest.raises(ValueError, match="entries but"):
        rank_candidates([1.0, 0.0], [[1.0, 0.0], [0.0, 1.0]], index)


# ---------------------------------------------------------------------------
# The gate — R7 and decision D42
# ---------------------------------------------------------------------------


def test_every_suggestion_leaves_uncalibrated() -> None:
    index = ExampleIndex(entries=(entry("ssh_version", "ip ssh version 2"),))
    suggestions = suggest_for_vectors([1.0, 0.0], [[1.0, 0.0]], index)

    assert suggestions
    for suggestion in suggestions:
        assert suggestion.confidence_method is ConfidenceMethod.UNCALIBRATED_SIMILARITY
        assert suggestion.calibrated_confidence is None
        assert not suggestion.confidence_method.is_probability


def test_a_perfect_score_is_still_not_a_confidence() -> None:
    """The safety argument for this phase, in one assertion.

    A similarity of exactly 1.0 — an identical line already in the index —
    produces a suggestion that is still uncalibrated, and a field carrying that
    method abstains regardless of the number.
    """
    index = ExampleIndex(entries=(entry("ssh_version", "ip ssh version 2"),))
    suggestion = suggest_for_vectors([1.0, 0.0], [[1.0, 0.0]], index)[0]

    assert suggestion.raw_score == pytest.approx(1.0)
    assert suggestion.calibrated_confidence is None
    assert not suggestion.confidence_method.is_probability


def test_the_contract_refuses_a_calibrated_claim_without_a_value() -> None:
    """Asserted through the contract, not through this layer's discretion."""
    from pydantic import ValidationError

    from api.models.training import Suggestion

    with pytest.raises(ValidationError, match="calibrated confidence but carries none"):
        Suggestion(
            rank=1,
            field="ssh_version",
            raw_score=0.99,
            confidence_method=ConfidenceMethod.CALIBRATED_SIMILARITY,
        )


def test_the_contract_refuses_a_score_smuggled_into_the_confidence_slot() -> None:
    from pydantic import ValidationError

    from api.models.training import Suggestion

    with pytest.raises(ValidationError, match="cannot become a probability"):
        Suggestion(
            rank=1,
            field="ssh_version",
            raw_score=0.99,
            calibrated_confidence=0.99,
            confidence_method=ConfidenceMethod.UNCALIBRATED_SIMILARITY,
        )


def test_the_guard_raises_on_a_calibrated_suggestion() -> None:
    """`assert_never_confidence` is called wherever suggestions leave the package."""
    from api.models.training import Suggestion

    honest = Suggestion(rank=1, field="ssh_version", raw_score=0.9)
    assert_never_confidence((honest,))  # does not raise

    smuggled = honest.model_copy(
        update={"confidence_method": ConfidenceMethod.CALIBRATED_SIMILARITY}
    )
    with pytest.raises(UncalibratedScoreError, match="not a probability"):
        assert_never_confidence((smuggled,))


def test_suggestions_are_never_evidence() -> None:
    index = ExampleIndex(entries=(entry("ssh_version", "ip ssh version 2"),))
    suggestions = suggest_for_vectors([1.0, 0.0], [[1.0, 0.0]], index)

    assert suggestions_are_evidence(suggestions) is False
    assert suggestions_are_evidence(()) is False


def test_a_suggestion_carries_no_value_only_a_field() -> None:
    """It proposes what a line *means*, never what the device is configured to.

    A suggestion that carried a value would be one assignment from a canonical
    field, and one more from a verdict.
    """
    from api.models.training import Suggestion

    assert "value" not in Suggestion.model_fields
    assert "expected_value" not in Suggestion.model_fields
    assert set(Suggestion.model_fields) == {
        "rank",
        "field",
        "raw_score",
        "calibrated_confidence",
        "confidence_method",
    }


def test_to_suggestions_on_nothing_yields_nothing() -> None:
    assert to_suggestions(()) == ()


def test_a_ranked_candidate_keeps_its_provenance() -> None:
    """So the training screen can show which example produced the suggestion."""
    candidate = RankedCandidate(entry=entry("ssh_version", "ip ssh version 2"), score=0.8)
    assert candidate.entry.origin == "constructed-fixture"
    assert candidate.entry.source is ExampleSource.SEED
