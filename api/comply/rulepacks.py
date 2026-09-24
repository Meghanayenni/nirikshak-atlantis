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

**Nothing loads unless it is the rulepack its version names** (ADR 0056).
`rules/rulepack.yaml` declares the version and a checksum over every rule file
and every framework index — the indexes decide which identifiers a finding
carries and on which platforms, so they are part of what a version means. The
loader recomputes it and refuses a mismatch, the way the pack loader refuses a
pack whose bytes do not match its declaration (D47).

The convention, stated once, here:

    sha256 over, for each file in sorted order of its path relative to
    `rules/` — `canonical/*.yaml`, then `frameworks/*.index.yaml` — the path
    in POSIX form, a NUL, the file's bytes with CRLF normalised to LF, a NUL.
"""

from __future__ import annotations

import functools
import hashlib
from pathlib import Path

import yaml

from api.comply.conditions import self_check
from api.comply.errors import RulepackIntegrityError, RulepackLoadError, RulepackValidationError
from api.models.enums import PackStatus
from api.models.rule import ComplianceRule, Rulepack

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_BASE = REPO_ROOT / "rules"
RULES_ROOT = RULES_BASE / "canonical"
MANIFEST_PATH = RULES_BASE / "rulepack.yaml"

CANONICAL_RULEPACK_ID = "canonical"

UNVERIFIED_VERSION = "0.0.0"
"""What a rulepack built with `manifest=None` calls itself. Never a shipped version."""


def rulepack_checksum(base: Path = RULES_BASE) -> str:
    """The digest a manifest must declare for the rules under `base`."""
    files = sorted(
        [*base.glob("canonical/*.yaml"), *base.glob("frameworks/*.index.yaml")],
        key=lambda path: path.relative_to(base).as_posix(),
    )
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(base).as_posix().encode("utf-8") + b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n") + b"\0")
    return "sha256:" + digest.hexdigest()


def read_manifest(path: Path = MANIFEST_PATH) -> dict:
    """The declared identity: `rulepack_id`, `version`, `checksum`, `history`."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RulepackIntegrityError(f"{path.name}: cannot be read — {exc}") from exc
    if not isinstance(raw, dict) or not {"rulepack_id", "version", "checksum"} <= set(raw):
        raise RulepackIntegrityError(f"{path.name} must declare rulepack_id, version and checksum")
    return raw


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
    failures = {
        rule.rule_id: [
            problem for condition in rule.check.conditions for problem in self_check(condition)
        ]
        for rule in pack.rules
    }
    return {rule_id: msgs for rule_id, msgs in failures.items() if msgs}


def load_rulepack(
    root: Path = RULES_ROOT,
    *,
    validate: bool = True,
    manifest: Path | None = MANIFEST_PATH,
) -> Rulepack:
    """The canonical rulepack, verified and self-checked before it can be evaluated.

    `validate=False` exists for tests that deliberately construct a broken pack
    to prove the check bites. `manifest=None` exists for tests that build rules
    in a scratch directory; such a pack is version `0.0.0` with no checksum, so
    it cannot be mistaken for a shipped one. Nothing in the evaluation path
    passes either.
    """
    version, checksum = UNVERIFIED_VERSION, None
    if manifest is not None:
        declared = read_manifest(manifest)
        computed = rulepack_checksum(root.parent)
        if declared["checksum"] != computed:
            raise RulepackIntegrityError(
                f"the rules under {root.parent.name}/ do not match rulepack "
                f"{declared['version']}: {manifest.name} declares "
                f"{declared['checksum']}, the files digest to {computed}. Either the "
                "rules were edited without minting a version, or the manifest was. "
                "Mint a new version and move the old one into `history` (ADR 0056)."
            )
        version, checksum = str(declared["version"]), computed

    pack = Rulepack(
        rulepack_id=CANONICAL_RULEPACK_ID,
        version=version,
        checksum=checksum,
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
