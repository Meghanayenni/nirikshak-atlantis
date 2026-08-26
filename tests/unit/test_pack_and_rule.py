"""Vendor pack and compliance rule contracts — Rules 4, 5 and decision R16."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.models import (
    AbsenceAction,
    AbsencePolicy,
    AppliesTo,
    CaptureSpec,
    CastType,
    CheckSpec,
    ComplianceRule,
    Condition,
    ConditionOp,
    Framework,
    FrameworkRef,
    MappingProvenance,
    MatchSpec,
    MatchType,
    PackStatus,
    PatternDef,
    PatternSource,
    PlatformCapability,
    PlatformDefault,
    Severity,
    VendorPack,
)

# ---------------------------------------------------------------------------
# Patterns — boring by design (DEVELOPER_GUIDE.md §4)
# ---------------------------------------------------------------------------


def pattern(**kw: object) -> PatternDef:
    base: dict[str, object] = {
        "id": "p-ssh-001",
        "field": "ssh_version",
        "match": MatchSpec(type=MatchType.REGEX, pattern=r"^ip\ ssh\ version\ (\S+)"),
        "capture": CaptureSpec(value="$1", cast=CastType.INT),
        "examples": ("ip ssh version 2",),
    }
    base.update(kw)
    return PatternDef(**base)  # type: ignore[arg-type]


def test_regex_must_be_anchored() -> None:
    """Generated patterns are anchored with ^ — predictable, not clever."""
    with pytest.raises(ValidationError, match="not anchored"):
        MatchSpec(type=MatchType.REGEX, pattern=r"ip ssh version (\S+)")


def test_invalid_regex_is_rejected_at_load() -> None:
    with pytest.raises(ValidationError, match="invalid regex"):
        MatchSpec(type=MatchType.REGEX, pattern=r"^ip ssh version (\S+")


def test_textfsm_match_must_name_its_template() -> None:
    with pytest.raises(ValidationError, match="must name its template"):
        MatchSpec(type=MatchType.TEXTFSM, pattern="show_version")


def test_pattern_self_check_passes_on_good_examples() -> None:
    assert pattern().self_check() == []


def test_pattern_self_check_catches_non_matching_example() -> None:
    failures = pattern(examples=("set ssh proto-version 2",)).self_check()
    assert failures and "does not match" in failures[0]


def test_pattern_self_check_catches_negative_example_that_matches() -> None:
    failures = pattern(negative_examples=("ip ssh version 1",)).self_check()
    assert failures and "must not" in failures[0]


def test_admin_trained_pattern_must_retain_its_example() -> None:
    with pytest.raises(ValidationError, match="must retain the confirmed example"):
        pattern(source=PatternSource.ADMIN_TRAINED, examples=())


def test_example_cannot_be_both_positive_and_negative() -> None:
    with pytest.raises(ValidationError, match="both a positive"):
        pattern(negative_examples=("ip ssh version 2",))


# ---------------------------------------------------------------------------
# Vendor pack
# ---------------------------------------------------------------------------


def pack(**kw: object) -> VendorPack:
    base: dict[str, object] = {
        "vendor": "cisco",
        "os_family": "ios",
        "pack_version": "1.0.0",
        "patterns": (pattern(),),
    }
    base.update(kw)
    return VendorPack(**base)  # type: ignore[arg-type]


def test_pack_version_must_be_semver() -> None:
    with pytest.raises(ValidationError):
        pack(pack_version="1.0")


def test_duplicate_pattern_ids_are_rejected() -> None:
    with pytest.raises(ValidationError, match="duplicate pattern ids"):
        pack(patterns=(pattern(), pattern()))


def test_active_pack_must_carry_a_checksum() -> None:
    """Activation is audit-logged and must be verifiable."""
    with pytest.raises(ValidationError, match="must carry its checksum"):
        pack(status=PackStatus.ACTIVE)


def test_active_pack_with_checksum_is_valid() -> None:
    p = pack(status=PackStatus.ACTIVE, checksum="sha256:" + "a" * 64)
    assert p.status is PackStatus.ACTIVE


def test_pack_cannot_be_its_own_parent() -> None:
    with pytest.raises(ValidationError, match="its own parent"):
        pack(parent_version="1.0.0")


def test_pack_validate_patterns_reports_failures() -> None:
    bad = pack(patterns=(pattern(id="p-bad", examples=("nope",)),))
    assert "p-bad" in bad.validate_patterns()
    assert pack().validate_patterns() == {}


def test_capability_unknown_means_abstain() -> None:
    """`supported is None` is undocumented, which must produce abstention."""
    p = pack(capabilities=(PlatformCapability(field="min_password_length"),))
    assert p.supports("min_password_length") is None
    assert p.supports("never_declared") is None


def test_capability_claim_requires_a_citation() -> None:
    """A guess wearing a citation field is worse than abstaining."""
    with pytest.raises(ValidationError, match="without a citation"):
        PlatformCapability(field="ssh_version", supported=True)


def test_platform_default_requires_a_citation() -> None:
    with pytest.raises(ValidationError):
        PlatformDefault(field="telnet_enabled", value=False, citation="")


def test_pack_lookup_helpers() -> None:
    p = pack(
        defaults=(
            PlatformDefault(field="telnet_enabled", value=False, citation="IOS 17.x config guide"),
        )
    )
    assert p.pack_id == "cisco/ios"
    assert len(p.patterns_for("ssh_version")) == 1
    assert p.patterns_for("nonexistent") == ()
    assert p.default_for("telnet_enabled") is not None


# ---------------------------------------------------------------------------
# Compliance rules
# ---------------------------------------------------------------------------


def rule(**kw: object) -> ComplianceRule:
    base: dict[str, object] = {
        "rule_id": "NRK-SSH-001",
        "title": "SSH protocol version 2 only",
        "severity": Severity.HIGH,
        "rationale": "SSHv1 has structural cryptographic weaknesses.",
        "check": CheckSpec(
            field="ssh_version", condition=Condition(op=ConditionOp.EQUALS, value=2)
        ),
        "frameworks": (
            FrameworkRef(framework=Framework.CIS, control_id="1.5.2"),
            FrameworkRef(framework=Framework.NIST, control_id="AC-17(2)"),
            FrameworkRef(framework=Framework.STIG, control_id="NET1645"),
            FrameworkRef(framework=Framework.ISO, control_id="A.8.20"),
        ),
    }
    base.update(kw)
    return ComplianceRule(**base)  # type: ignore[arg-type]


def test_one_check_maps_to_all_four_frameworks() -> None:
    """A single ingestion must produce evidence for CIS, NIST, STIG and ISO."""
    r = rule()
    assert r.frameworks_covered == {Framework.CIS, Framework.NIST, Framework.STIG, Framework.ISO}
    assert r.framework_ids(Framework.NIST) == ("AC-17(2)",)


def test_duplicate_framework_mapping_is_rejected() -> None:
    with pytest.raises(ValidationError, match="twice"):
        rule(
            frameworks=(
                FrameworkRef(framework=Framework.CIS, control_id="1.5.2"),
                FrameworkRef(framework=Framework.CIS, control_id="1.5.2"),
            )
        )


def test_mappings_default_to_project_asserted() -> None:
    """R16 — claiming less, verifiably, beats claiming more."""
    r = rule()
    assert all(f.mapping_provenance is MappingProvenance.PROJECT_ASSERTED for f in r.frameworks)
    assert not r.has_official_mapping


# --- R16 content policy, enforced structurally -----------------------------


def test_rule_rejects_verbatim_text_fields() -> None:
    """extra='forbid' makes the content policy structural, not a convention."""
    for bad_field in ("control_text", "benchmark_text", "standard_text", "annex_text"):
        with pytest.raises(ValidationError):
            rule(**{bad_field: "some framework prose"})


def test_rationale_is_required() -> None:
    with pytest.raises(ValidationError):
        rule(rationale="")


def test_rationale_length_is_capped() -> None:
    with pytest.raises(ValidationError):
        rule(rationale="x" * 1201)


# --- conditions ------------------------------------------------------------


def test_valueless_operators_take_no_value() -> None:
    with pytest.raises(ValidationError, match="takes no value"):
        Condition(op=ConditionOp.IS_TRUE, value=True)
    assert Condition(op=ConditionOp.IS_TRUE).value is None


def test_comparison_operators_require_a_value() -> None:
    with pytest.raises(ValidationError, match="requires a value"):
        Condition(op=ConditionOp.EQUALS)


def test_membership_operators_require_a_collection() -> None:
    with pytest.raises(ValidationError, match="requires a collection"):
        Condition(op=ConditionOp.IN, value=2)
    assert Condition(op=ConditionOp.IN, value=[2, 3]).value == [2, 3]


# --- absence policy --------------------------------------------------------


def test_unknown_capability_abstains_by_default() -> None:
    """The safe default: if we do not know the platform supports it, abstain."""
    p = AbsencePolicy()
    assert p.on_capability_unknown is AbsenceAction.UNKNOWN
    assert p.on_absent_default is AbsenceAction.EVALUATE
    assert p.on_absent_unsupported is AbsenceAction.NOT_APPLICABLE


def test_applies_to_selector() -> None:
    assert AppliesTo().matches("cisco", "ios")
    assert AppliesTo(vendor=("cisco",)).matches("cisco", "ios")
    assert not AppliesTo(vendor=("juniper",)).matches("cisco", "ios")
    assert not AppliesTo(vendor=("cisco",)).matches(None, "ios")
