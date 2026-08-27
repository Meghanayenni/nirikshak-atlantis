"""Loading rulepacks from disk.

Rules are data (Rule 5). Adding a check is a YAML file, not a code release —
which is the same clause vendor packs answer, applied to the other half of the
system.

**One home for rule logic** (decision D15). Everything lives in
`rules/canonical/`, and each rule cross-maps itself through its own `frameworks`
list. The empty `cis/`, `nist/`, `stig/` and `iso/` directories that existed from
P0 have been removed: a second place where a rule could be defined is a second
place where it could be wrong, and the contract was already designed for the
inline form.

**Nothing loads without self-check** (decision D18). `load_rulepack` validates
before returning, so a rule whose condition could never evaluate is refused at
load rather than abstaining silently on every device forever.
"""

from __future__ import annotations

import functools
from pathlib import Path

import yaml

from api.comply.conditions import self_check
from api.comply.errors import RulepackLoadError, RulepackValidationError
from api.models.enums import PackStatus
from api.models.rule import ComplianceRule, Rulepack

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_ROOT = REPO_ROOT / "rules" / "canonical"

CANONICAL_RULEPACK_ID = "canonical"
CANONICAL_RULEPACK_VERSION = "1.0.0"


def load_rule(path: Path) -> ComplianceRule:
    """One rule file. Contract violations surface with the filename attached."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RulepackLoadError(f"{path.name}: invalid YAML — {exc}") from exc
    if not isinstance(raw, dict):
        raise RulepackLoadError(f"{path.name}: expected a mapping at the top level")
    try:
        return ComplianceRule(**raw)
    except Exception as exc:
        raise RulepackLoadError(f"{path.name}: {exc}") from exc


def discover_rules(root: Path = RULES_ROOT) -> list[ComplianceRule]:
    """Every rule under `root`, in a stable order.

    Sorted by path so evaluation is deterministic: the same rules in the same
    order produce the same findings in the same order, which is what makes a
    report diffable between runs.
    """
    if not root.is_dir():
        return []
    return [load_rule(path) for path in sorted(root.rglob("*.yaml"))]


def validate_rulepack(pack: Rulepack) -> dict[str, list[str]]:
    """Rules whose conditions could never produce a verdict. Empty means clean."""
    failures = {rule.rule_id: self_check(rule.check.condition) for rule in pack.rules}
    return {rule_id: msgs for rule_id, msgs in failures.items() if msgs}


def load_rulepack(root: Path = RULES_ROOT, *, validate: bool = True) -> Rulepack:
    """The canonical rulepack, self-checked before it can be evaluated.

    `validate=False` exists for tests that deliberately construct a broken pack
    to prove the check bites. Nothing in the evaluation path uses it.
    """
    pack = Rulepack(
        rulepack_id=CANONICAL_RULEPACK_ID,
        version=CANONICAL_RULEPACK_VERSION,
        status=PackStatus.ACTIVE,
        created_by="team-atlantis",
        rules=tuple(discover_rules(root)),
    )
    if validate:
        failures = validate_rulepack(pack)
        if failures:
            raise RulepackValidationError(failures)
    return pack


@functools.lru_cache(maxsize=1)
def _cached() -> Rulepack:
    return load_rulepack()


def load_active_rulepack(*, use_cache: bool = True) -> Rulepack:
    """Cached because an audit reads it once per device across a fleet."""
    return _cached() if use_cache else load_rulepack()


def clear_rulepack_cache() -> None:
    _cached.cache_clear()
