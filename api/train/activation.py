"""The pack lifecycle: DRAFT -> VALIDATED -> ACTIVE, and back again.

Decision D51. Compiling a pattern and *trusting* it are two different acts, and
P11 keeps them two different calls. The gap between them is where DEVELOPER_GUIDE.md §4's
"show it to the administrator, allow editing before activation" lives, and where
P13 will eventually render the generated regex for review. Collapsing the two
into one convenient call would foreclose that, and would mean a pattern entered a
vendor pack in the same breath as it was proposed.

**Reviewed data is never mutated at runtime.** `packs/builtin/` holds packs a
person wrote and a reviewer read; a deployment that edited those files would make
`git status` dirty, invalidate their checksums, and destroy the one clean answer
to "what did we ship". So activation never touches them. Instead the trained root
carries an *activation record* — `activation.yaml` — which names the version this
deployment has chosen for each platform:

    a pack file's `status:` is what it SHIPPED as
    the activation record is what this deployment has since decided

Exactly one of the two answers is authoritative per platform, and the record wins
where it has an opinion. That keeps decision D46's "one ACTIVE pack per platform"
true without a second copy of any pack and without editing a reviewed file.

**Rollback is the same mechanism run backwards** (`PACK_ROLLED_BACK`). Pointing
the record at the previous version restores the previous parse behaviour exactly,
because the previous pack file was never modified — which is the practical payoff
of refusing to mutate anything.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from api.ingest.pack_activation import ACTIVATION_RECORD, ActivationRecord
from api.ingest.pack_checksum import compute, verify_bytes
from api.ingest.packs import PACKS_ROOT, TRAINED_ROOT, load_pack, semver_key
from api.models.enums import PackStatus
from api.models.pack import PatternDef, VendorPack
from api.train.errors import ActivationError

PLACEHOLDER_CHECKSUM = "sha256:" + "0" * 64
"""Stand-in written while serialising, then replaced by the real digest.

Safe because the digest convention excludes the `checksum:` line from what it
hashes, so the placeholder cannot influence the value that replaces it.
"""


def bump_patch(version: str) -> str:
    """The next patch version. One confirmation is a patch, not a feature.

    A confirmed mapping adds a pattern and changes nothing that already existed,
    which is exactly what a patch bump means. Minor and major bumps stay reserved
    for changes a person makes deliberately to a builtin pack.
    """
    parts = list(semver_key(version))
    while len(parts) < 3:
        parts.append(0)
    parts[2] += 1
    return ".".join(str(p) for p in parts[:3])


# ---------------------------------------------------------------------------
# Drafting
# ---------------------------------------------------------------------------


def draft_with_pattern(base: VendorPack, pattern: PatternDef) -> VendorPack:
    """A new DRAFT version of `base`, one pattern richer.

    The whole parent pack is carried forward — detect signatures, identity,
    literal blocks, comment prefixes, defaults, capabilities — because a pack is
    a complete description of a platform, not a diff. Losing the parent's
    `comment_prefixes` while gaining a pattern would reintroduce DEF-9 on the
    very next parse.
    """
    if any(p.id == pattern.id for p in base.patterns):
        raise ActivationError(
            f"pattern id {pattern.id!r} already exists in {base.pack_id} {base.pack_version}"
        )

    return base.model_copy(
        update={
            "pack_version": bump_patch(base.pack_version),
            "parent_version": base.pack_version,
            "status": PackStatus.DRAFT,
            "checksum": None,
            "created_at": datetime.now(UTC),
            "patterns": (*base.patterns, pattern),
        }
    )


def validate(pack: VendorPack) -> VendorPack:
    """Run every pattern against its own examples, then mark the pack VALIDATED.

    `data-contracts.md` §6 names this as "the validation the P11 workflow gates
    activation on". It is a real gate: a pattern that does not match the line it
    was compiled from cannot reach ACTIVE through this function.
    """
    failures = pack.validate_patterns()
    if failures:
        raise ActivationError(
            f"{pack.pack_id} {pack.pack_version} cannot be validated; "
            f"patterns fail their own examples: {failures}"
        )
    return pack.model_copy(update={"status": PackStatus.VALIDATED})


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _serialise(pack: VendorPack, checksum: str) -> bytes:
    """One pack as YAML bytes, LF-terminated, with a stated checksum.

    `exclude_none` keeps the file readable: a generated pack full of explicit
    nulls is harder for an administrator to check than one that simply omits what
    it does not say.
    """
    payload = pack.model_dump(mode="json", exclude_none=True)
    payload["checksum"] = checksum

    header = (
        "# NIRIKSHAK vendor pack — GENERATED AT RUNTIME (P11).\n"
        "#\n"
        f"# Compiled from administrator confirmations by api/train/, parent version\n"
        f"# {pack.parent_version}. Every admin-trained pattern below retains the\n"
        "# training example id and audit sequence it came from, so any mapping here\n"
        "# can be traced to the person who confirmed it and the moment they did.\n"
        "#\n"
        "# This file is deployment state, not repository content. It is not reviewed\n"
        "# before it is loaded, which is why its checksum is verified on every load\n"
        "# (see api/ingest/pack_checksum.py).\n\n"
    )
    body = yaml.safe_dump(payload, sort_keys=True, allow_unicode=True, default_flow_style=False)
    return (header + body).encode("utf-8").replace(b"\r\n", b"\n")


def pack_path(pack: VendorPack, root: Path | None = None) -> Path:
    root = root if root is not None else TRAINED_ROOT
    return root / f"{pack.vendor}_{pack.os_family}" / f"{pack.pack_version}.yaml"


def write_pack(pack: VendorPack, root: Path | None = None) -> Path:
    """Serialise a pack and stamp it with its own digest.

    Two passes: serialise with a placeholder, compute the digest over the bytes
    with the `checksum:` line excluded, then serialise again with the real value.
    The second pass produces the same digest because the excluded line is the only
    thing that changed — which is the property that makes the convention usable
    for generated files at all.
    """
    root = root if root is not None else TRAINED_ROOT
    provisional = _serialise(pack, PLACEHOLDER_CHECKSUM)
    digest = compute(provisional)
    final = _serialise(pack, digest)

    if compute(final) != digest:  # pragma: no cover - the convention guarantees it
        raise ActivationError(
            "stamping changed the pack's digest; the checksum convention is not a "
            "fixed point for this file and the pack must not be written"
        )

    path = pack_path(pack, root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(final)

    result = verify_bytes(final, path=path.name)
    if not result.verified:  # pragma: no cover - as above
        raise ActivationError(
            f"refusing to leave an unverifiable pack on disk: {result.describe()}"
        )
    return path


# ---------------------------------------------------------------------------
# Activation and rollback
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ActivationResult:
    """What changed, for the audit payload and for the caller to report."""

    pack_id: str
    version: str
    previous_version: str | None
    path: str
    checksum: str
    pattern_ids: tuple[str, ...]


def activate(
    pack: VendorPack,
    *,
    trained_root: Path | None = None,
    builtin_root: Path | None = None,
) -> ActivationResult:
    """Write a VALIDATED pack as ACTIVE and point the activation record at it.

    Refuses a pack that has not been validated. The two-step lifecycle only means
    anything if the second step checks that the first one happened.
    """
    if pack.status is not PackStatus.VALIDATED:
        raise ActivationError(
            f"{pack.pack_id} {pack.pack_version} is {pack.status}; only a VALIDATED "
            "pack may be activated. Validation is the gate, not a formality."
        )

    trained_root = trained_root if trained_root is not None else TRAINED_ROOT
    builtin_root = builtin_root if builtin_root is not None else PACKS_ROOT
    record = ActivationRecord.load(trained_root)
    previous = record.version_for(pack.pack_id) or _shipped_active_version(
        pack.pack_id, builtin_root, trained_root
    )

    activated = pack.model_copy(update={"status": PackStatus.ACTIVE, "checksum": None})
    path = write_pack(activated, trained_root)

    # Reload from disk so the object the caller sees is the object a fresh
    # process would load, checksum included, rather than one held in memory.
    written = load_pack(path)
    record.with_active(pack.pack_id, written.pack_version).save(trained_root)

    return ActivationResult(
        pack_id=written.pack_id,
        version=written.pack_version,
        previous_version=previous,
        path=str(path),
        checksum=written.checksum or "",
        pattern_ids=tuple(p.id for p in written.patterns),
    )


def rollback(
    pack_id: str,
    to_version: str,
    *,
    trained_root: Path | None = None,
    builtin_root: Path | None = None,
) -> ActivationResult:
    """Point the activation record back at an earlier version.

    Restores the earlier parse behaviour exactly, because no pack file was ever
    modified. The version must already exist on disk: rollback selects between
    packs that were written, it does not reconstruct one.
    """
    trained_root = trained_root if trained_root is not None else TRAINED_ROOT
    builtin_root = builtin_root if builtin_root is not None else PACKS_ROOT
    record = ActivationRecord.load(trained_root)
    previous = record.version_for(pack_id) or _shipped_active_version(
        pack_id, builtin_root, trained_root
    )

    target = find_version(pack_id, to_version, builtin_root, trained_root)
    if target is None:
        raise ActivationError(
            f"cannot roll {pack_id} back to {to_version}: no such pack version exists "
            "on disk. Rollback selects an existing version; it does not rebuild one."
        )

    pack, path = target
    record.with_active(pack_id, to_version).save(trained_root)

    return ActivationResult(
        pack_id=pack_id,
        version=to_version,
        previous_version=previous,
        path=str(path),
        checksum=pack.checksum or "",
        pattern_ids=tuple(p.id for p in pack.patterns),
    )


def _iter_pack_files(*roots: Path):
    for root in roots:
        if root.is_dir():
            for path in sorted(root.rglob("*.yaml")):
                if path.name == ACTIVATION_RECORD:
                    continue
                yield path


def find_version(
    pack_id: str, version: str, builtin_root: Path, trained_root: Path
) -> tuple[VendorPack, Path] | None:
    for path in _iter_pack_files(builtin_root, trained_root):
        pack = load_pack(path)
        if pack.pack_id == pack_id and pack.pack_version == version:
            return pack, path
    return None


def _shipped_active_version(pack_id: str, builtin_root: Path, trained_root: Path) -> str | None:
    """The version a platform ships as ACTIVE, before any activation record."""
    for path in _iter_pack_files(builtin_root, trained_root):
        pack = load_pack(path)
        if pack.pack_id == pack_id and pack.status is PackStatus.ACTIVE:
            return pack.pack_version
    return None
