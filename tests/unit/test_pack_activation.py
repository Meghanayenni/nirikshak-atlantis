"""Pack ordering, selection and the activation lifecycle (P11).

Three defects and two decisions meet here:

  **DEF-11** — versions were ordered by string comparison, so `1.0.10` sorted
  below `1.0.9`. Harmless while packs were hand-written and few; P11 mints them
  programmatically and reaches `.10` in an afternoon.

  **DEF-12** — `packs/trained/` was never loaded, so a compiled pack would have
  been silently invisible.

  **D46** — two ACTIVE packs for one platform is an error, never a race resolved
  by sort order.

  **D51** — DRAFT -> VALIDATED -> ACTIVE, with rollback, and no reviewed file
  ever mutated.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from api.ingest.pack_activation import ActivationRecord
from api.ingest.packs import (
    PACKS_ROOT,
    DuplicateActivePackError,
    PackLoadError,
    active_packs,
    discover_packs,
    load_pack,
    semver_key,
)
from api.models.enums import CastType, MatchType, PackStatus, PatternSource, TrainingOutcome
from api.models.pack import CaptureSpec, MatchSpec, PatternDef, VendorPack
from api.models.training import TrainingExample
from api.train.activation import (
    activate,
    bump_patch,
    draft_with_pattern,
    rollback,
    validate,
    write_pack,
)
from api.train.compile import CompileRequest, compile_pattern
from api.train.errors import ActivationError

# ---------------------------------------------------------------------------
# DEF-11 — version ordering
# ---------------------------------------------------------------------------


def test_1_0_9_sorts_below_1_0_10() -> None:
    """String comparison gets this backwards, and P11 reaches `.10` quickly."""
    assert semver_key("1.0.9") < semver_key("1.0.10")
    assert "1.0.9" > "1.0.10"  # the defect, preserved as the reason this exists


def test_1_2_0_sorts_below_1_10_0() -> None:
    assert semver_key("1.2.0") < semver_key("1.10.0")
    assert "1.2.0" > "1.10.0"  # likewise


def test_packs_are_ordered_newest_first_within_a_platform() -> None:
    found = [p for p in discover_packs(PACKS_ROOT) if p.pack_id == "arista/eos"]
    assert [p.pack_version for p in found] == ["1.0.1", "1.0.0"]


def test_a_double_digit_patch_orders_correctly(tmp_path: Path) -> None:
    """The case the defect actually breaks, exercised end to end on disk."""
    for version in ("1.0.9", "1.0.10"):
        _write_minimal_pack(tmp_path, version, status=PackStatus.DEPRECATED)

    found = discover_packs(tmp_path)
    assert [p.pack_version for p in found] == ["1.0.10", "1.0.9"]


def test_bump_patch_crosses_the_ten_boundary() -> None:
    assert bump_patch("1.0.9") == "1.0.10"
    assert bump_patch("1.0.10") == "1.0.11"


# ---------------------------------------------------------------------------
# D46 — competing ACTIVE packs
# ---------------------------------------------------------------------------


def _write_minimal_pack(
    root: Path,
    version: str,
    *,
    status: PackStatus = PackStatus.ACTIVE,
    vendor: str = "acme",
    os_family: str = "os",
) -> Path:
    pack = VendorPack(
        vendor=vendor,
        os_family=os_family,
        pack_version=version,
        status=PackStatus.DRAFT,
        detect=(),
        patterns=(),
    )
    written = pack.model_copy(update={"status": status})
    return write_pack(written, root)


def test_two_active_packs_for_one_platform_are_refused(tmp_path: Path) -> None:
    """Never resolved by ordering.

    Silently selecting the higher-sorting version would mean the fleet is parsed
    by a pack nobody chose, and the operator's evidence would cite a
    `pack_version` they never activated.
    """
    _write_minimal_pack(tmp_path, "1.0.0")
    _write_minimal_pack(tmp_path, "1.1.0")

    with pytest.raises(DuplicateActivePackError, match="two ACTIVE packs"):
        active_packs(tmp_path)


def test_the_shipped_repository_has_exactly_one_active_pack_per_platform() -> None:
    """A regression guard on the data, not only on the code."""
    ids = [p.pack_id for p in active_packs()]
    assert len(ids) == len(set(ids)), f"duplicate active platforms: {ids}"


# ---------------------------------------------------------------------------
# D45 — the trained root is loaded, and kept separate
# ---------------------------------------------------------------------------


def test_a_trained_pack_is_discovered(tmp_path: Path) -> None:
    """DEF-12 — `packs/trained/` was defined and read by nothing."""
    _write_minimal_pack(tmp_path, "2.0.0", status=PackStatus.DEPRECATED)
    assert [p.pack_version for p in discover_packs(tmp_path)] == ["2.0.0"]


def test_the_activation_record_is_not_mistaken_for_a_pack(tmp_path: Path) -> None:
    ActivationRecord(active={"acme/os": "1.0.0"}).save(tmp_path)
    _write_minimal_pack(tmp_path, "1.0.0", status=PackStatus.DEPRECATED)

    found = discover_packs(tmp_path)
    assert len(found) == 1
    assert found[0].pack_version == "1.0.0"


# ---------------------------------------------------------------------------
# D51 — the lifecycle
# ---------------------------------------------------------------------------


def _confirmed(line: str = "logging host 192.0.2.10") -> TrainingExample:
    return TrainingExample(
        example_id="trn-lifecycle",
        vendor="arista",
        os_family="eos",
        raw_line_scrubbed=line,
        field="logging_hosts",
        outcome=TrainingOutcome.CORRECTED,
        confirmed_by="alice",
        audit_seq=3,
    )


def _arista_base() -> VendorPack:
    return load_pack(PACKS_ROOT / "arista_eos" / "1.0.1.yaml")


def test_a_draft_is_a_patch_bump_of_its_parent() -> None:
    base = _arista_base()
    pattern = compile_pattern(_confirmed(), CompileRequest(value_token=2, cast=CastType.LIST))
    draft = draft_with_pattern(base, pattern)

    assert draft.pack_version == "1.0.2"
    assert draft.parent_version == "1.0.1"
    assert draft.status is PackStatus.DRAFT


def test_a_draft_carries_the_whole_parent_forward() -> None:
    """A pack is a description of a platform, not a diff.

    Losing the parent's `comment_prefixes` while gaining a pattern would
    reintroduce DEF-9 — every `!` line back in the training queue — on the very
    next parse.
    """
    base = _arista_base()
    pattern = compile_pattern(_confirmed(), CompileRequest(value_token=2, cast=CastType.LIST))
    draft = draft_with_pattern(base, pattern)

    assert draft.comment_prefixes == base.comment_prefixes == ("!",)
    assert draft.detect == base.detect
    assert draft.identity == base.identity
    assert draft.literal_blocks == base.literal_blocks
    assert len(draft.patterns) == len(base.patterns) + 1


def test_an_unvalidated_pack_cannot_be_activated(tmp_path: Path) -> None:
    """The two-step lifecycle only means something if step two checks step one."""
    base = _arista_base()
    pattern = compile_pattern(_confirmed(), CompileRequest(value_token=2, cast=CastType.LIST))
    draft = draft_with_pattern(base, pattern)

    with pytest.raises(ActivationError, match="only a VALIDATED pack"):
        activate(draft, trained_root=tmp_path)


def test_validation_refuses_a_pattern_that_fails_its_own_example() -> None:
    """`self_check()` is the gate `data-contracts.md` §6 names."""
    broken = PatternDef(
        id="p-broken-001",
        field="ssh_version",
        match=MatchSpec(type=MatchType.REGEX, pattern=r"^ip\s+ssh\s+version\s+(\S+)$"),
        capture=CaptureSpec(value="$1", cast=CastType.INT),
        source=PatternSource.ADMIN_TRAINED,
        examples=("telnet is not ssh",),
    )
    pack = _arista_base().model_copy(update={"patterns": (broken,), "status": PackStatus.DRAFT})

    with pytest.raises(ActivationError, match="fail their own examples"):
        validate(pack)


def test_activation_writes_a_verifiable_pack_and_records_the_choice(tmp_path: Path) -> None:
    base = _arista_base()
    pattern = compile_pattern(_confirmed(), CompileRequest(value_token=2, cast=CastType.LIST))
    draft = validate(draft_with_pattern(base, pattern))

    result = activate(draft, trained_root=tmp_path)

    assert result.version == "1.0.2"
    assert result.previous_version == "1.0.1"
    assert result.checksum.startswith("sha256:")

    written = load_pack(Path(result.path))
    assert written.status is PackStatus.ACTIVE
    assert written.checksum == result.checksum

    record = ActivationRecord.load(tmp_path)
    assert record.version_for("arista/eos") == "1.0.2"


def test_activation_never_edits_a_reviewed_builtin_pack(tmp_path: Path) -> None:
    """The reason the activation record exists at all.

    A deployment that rewrote `packs/builtin/*.yaml` would leave the repository
    dirty, invalidate those packs' checksums, and destroy the one clean answer to
    "what did we ship".
    """
    before = {p: p.read_bytes() for p in PACKS_ROOT.rglob("*.yaml")}

    pattern = compile_pattern(_confirmed(), CompileRequest(value_token=2, cast=CastType.LIST))
    activate(validate(draft_with_pattern(_arista_base(), pattern)), trained_root=tmp_path)

    after = {p: p.read_bytes() for p in PACKS_ROOT.rglob("*.yaml")}
    assert before == after


def test_the_activation_record_supersedes_a_shipped_status(tmp_path: Path) -> None:
    """One platform, one pack in force, with nothing edited to achieve it."""
    _write_minimal_pack(tmp_path, "1.0.0", status=PackStatus.ACTIVE)
    _write_minimal_pack(tmp_path, "1.0.1", status=PackStatus.DEPRECATED)
    ActivationRecord(active={"acme/os": "1.0.1"}).save(tmp_path)

    selected = active_packs(tmp_path)
    assert [p.pack_version for p in selected] == ["1.0.1"]


def test_an_activation_record_naming_a_missing_version_refuses(tmp_path: Path) -> None:
    """Falling back to another version would parse the fleet with a pack the
    operator did not choose — the same failure D46 refuses, arriving by a
    different route."""
    _write_minimal_pack(tmp_path, "1.0.0", status=PackStatus.ACTIVE)
    ActivationRecord(active={"acme/os": "9.9.9"}).save(tmp_path)

    with pytest.raises(PackLoadError, match="no such pack version"):
        active_packs(tmp_path)


def test_rollback_restores_the_previous_version_exactly(tmp_path: Path) -> None:
    """Exact because nothing was ever modified — the payoff of not mutating."""
    pattern = compile_pattern(_confirmed(), CompileRequest(value_token=2, cast=CastType.LIST))
    activate(validate(draft_with_pattern(_arista_base(), pattern)), trained_root=tmp_path)

    result = rollback("arista/eos", "1.0.1", trained_root=tmp_path)

    assert result.version == "1.0.1"
    assert result.previous_version == "1.0.2"
    assert ActivationRecord.load(tmp_path).version_for("arista/eos") == "1.0.1"


def test_rollback_to_a_version_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ActivationError, match="no such pack version"):
        rollback("arista/eos", "7.7.7", trained_root=tmp_path)


def test_a_written_pack_is_readable_yaml_with_its_provenance_intact(tmp_path: Path) -> None:
    """An administrator must be able to open the file and check it."""
    pattern = compile_pattern(_confirmed(), CompileRequest(value_token=2, cast=CastType.LIST))
    path = write_pack(validate(draft_with_pattern(_arista_base(), pattern)), tmp_path)

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    compiled = [p for p in raw["patterns"] if p["source"] == "admin_trained"]

    assert len(compiled) == 1
    assert compiled[0]["provenance"]["training_example_id"] == "trn-lifecycle"
    assert compiled[0]["provenance"]["audit_seq"] == 3
    assert compiled[0]["examples"] == ["logging host 192.0.2.10"]
    assert b"\r\n" not in path.read_bytes()
