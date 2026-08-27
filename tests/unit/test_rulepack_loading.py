"""Loading and validating rulepacks (decisions D15, D16, D17, D18).

A malformed rulepack must not enter evaluation. The failure it prevents is
specific: a rule that loads but can never produce a verdict abstains on every
device forever, which is indistinguishable in a report from a control the vendor
packs cannot read. One is an authoring mistake; the other is a coverage gap, and
they route to different people.
"""

from __future__ import annotations

import pytest

from api.comply.errors import RulepackLoadError, RulepackValidationError
from api.comply.rulepacks import (
    discover_rules,
    load_rule,
    load_rulepack,
    validate_rulepack,
)
from api.models.enums import ConditionOp, PackStatus, Severity
from api.models.rule import CheckSpec, ComplianceRule, Condition, Rulepack

GOOD_RULE = (
    "rule_id: NRK-X-001\n"
    "title: A check\n"
    "severity: high\n"
    "rationale: Because it matters.\n"
    "check:\n"
    "  field: ssh_version\n"
    "  condition: { op: equals, value: 2 }\n"
)


# ---------------------------------------------------------------------------
# D15 — one home
# ---------------------------------------------------------------------------


def test_rules_live_only_in_canonical() -> None:
    """The empty per-framework directories are gone (D15)."""
    from api.comply.rulepacks import REPO_ROOT

    rules_root = REPO_ROOT / "rules"

    assert (rules_root / "canonical").is_dir()
    for gone in ("cis", "nist", "stig", "iso"):
        assert not (rules_root / gone).exists(), (
            f"rules/{gone}/ is back — a second place to define a rule is a "
            "second place for it to be wrong"
        )


def test_the_shipped_rulepack_loads() -> None:
    pack = load_rulepack()

    assert pack.rulepack_id == "canonical"
    assert pack.status is PackStatus.ACTIVE
    assert len(pack.rules) >= 7


def test_discovery_is_ordered() -> None:
    """Deterministic evaluation starts here: same rules, same order, every run."""
    first = [r.rule_id for r in discover_rules()]
    second = [r.rule_id for r in discover_rules()]

    assert first == second == sorted(first)


# ---------------------------------------------------------------------------
# D16 — no framework mappings ship
# ---------------------------------------------------------------------------


def test_no_framework_mappings_are_claimed() -> None:
    """D16 — zero CIS / NIST / STIG / ISO control IDs ship at P6.

    Writing a control identifier without having read the benchmark would be
    inventing it, and a mapping that cannot be produced on request is a claim of
    coverage the project cannot stand behind.

    **This test is expected to be deleted** by the change that adds the first
    sourced mapping. It fails loudly at that point so the author has to confront
    the sourcing requirement rather than adding identifiers quietly.
    """
    pack = load_rulepack()

    offenders = [
        f"{r.rule_id} claims {ref.framework.value}:{ref.control_id}"
        for r in pack.rules
        for ref in r.frameworks
    ]

    assert offenders == [], "\n".join(offenders)
    assert pack.frameworks_covered == frozenset()


def test_every_rule_carries_its_own_rationale() -> None:
    """R16 — our own words, and enough of them to explain the check."""
    pack = load_rulepack()

    for rule in pack.rules:
        assert rule.rationale.strip()
        assert len(rule.rationale) <= 1200
        assert rule.title.strip()


def test_no_rule_references_a_snippet_that_does_not_exist() -> None:
    """Remediation is P8; the vetted snippet library is empty."""
    pack = load_rulepack()

    assert all(r.remediation_ref is None for r in pack.rules)


# ---------------------------------------------------------------------------
# D17 — the rulepack is versioned
# ---------------------------------------------------------------------------


def test_the_rulepack_carries_a_version() -> None:
    """`FindingProvenance.rulepack_version` had no source before P6."""
    assert load_rulepack().version == "1.0.0"


def test_duplicate_rule_ids_are_rejected() -> None:
    from pydantic import ValidationError

    rule = ComplianceRule(
        rule_id="NRK-DUP-001",
        title="t",
        severity=Severity.LOW,
        rationale="r",
        check=CheckSpec(field="f", condition=Condition(op=ConditionOp.IS_TRUE)),
    )
    with pytest.raises(ValidationError, match="duplicate rule ids"):
        Rulepack(rulepack_id="x", version="1.0.0", rules=(rule, rule))


def test_the_rulepack_has_no_checksum_field() -> None:
    """D17 — deliberately not copied from VendorPack.

    Pack checksums are declared and never verified against file bytes; that was
    found at P4 and deferred to P11. Replicating an unverified integrity
    mechanism into a second contract would double the problem, not solve it.
    """
    assert "checksum" not in Rulepack.model_fields


# ---------------------------------------------------------------------------
# D18 — malformed rules are rejected, not silently tolerated
# ---------------------------------------------------------------------------


def test_invalid_yaml_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("rule_id: [unclosed\n", encoding="utf-8")

    with pytest.raises(RulepackLoadError, match="invalid YAML"):
        load_rule(path)


def test_a_non_mapping_file_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a list\n", encoding="utf-8")

    with pytest.raises(RulepackLoadError, match="expected a mapping"):
        load_rule(path)


def test_a_contract_violation_names_the_file(tmp_path) -> None:
    path = tmp_path / "missing-rationale.yaml"
    path.write_text(GOOD_RULE.replace("rationale: Because it matters.\n", ""), encoding="utf-8")

    with pytest.raises(RulepackLoadError, match="missing-rationale.yaml"):
        load_rule(path)


def test_a_framework_prose_field_is_rejected(tmp_path) -> None:
    """R16 — `extra="forbid"` makes the content policy structural."""
    path = tmp_path / "prose.yaml"
    path.write_text(GOOD_RULE + 'control_text: "verbatim benchmark wording"\n', encoding="utf-8")

    with pytest.raises(RulepackLoadError, match="[Ee]xtra"):
        load_rule(path)


def test_an_unevaluatable_rule_fails_self_check(tmp_path) -> None:
    """`lte: "600"` — a quoted number can never be compared with anything."""
    path = tmp_path / "broken.yaml"
    path.write_text(
        GOOD_RULE.replace("{ op: equals, value: 2 }", "{ op: lte, value: '600' }"),
        encoding="utf-8",
    )

    with pytest.raises(RulepackValidationError, match="abstain on every device"):
        load_rulepack(tmp_path)


def test_an_invalid_rulepack_cannot_enter_evaluation(tmp_path) -> None:
    """The whole point of validating at load rather than at runtime."""
    path = tmp_path / "broken.yaml"
    path.write_text(
        GOOD_RULE.replace("{ op: equals, value: 2 }", "{ op: lte, value: '600' }"),
        encoding="utf-8",
    )

    with pytest.raises(RulepackValidationError):
        load_rulepack(tmp_path)

    # And the failure names the rule, so it can be fixed without bisecting.
    pack = load_rulepack(tmp_path, validate=False)
    assert "NRK-X-001" in validate_rulepack(pack)


def test_the_shipped_rulepack_self_checks_clean() -> None:
    assert validate_rulepack(load_rulepack()) == {}


def test_a_missing_directory_yields_no_rules(tmp_path) -> None:
    assert discover_rules(tmp_path / "nothing-here") == []
