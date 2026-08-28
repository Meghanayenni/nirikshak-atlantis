"""Loading vendor packs from disk.

Packs are data (Rule 5). At P3 they carry `detect` signatures and `identity`
patterns but no parsing `patterns` — a platform NIRIKSHAK recognises but cannot
yet audit. That is an honest state rather than a placeholder: detection works,
the whole file becomes residue, and every canonical field stays UNKNOWN.

**Two roots, deliberately separate** (decision D45). `packs/builtin/` holds packs
written by a person and reviewed in a pull request. `packs/trained/` holds packs
`api/train/` compiled at runtime from administrator confirmations — never
reviewed before they are loaded, which is precisely why the checksum below is
not optional for them. Keeping the two trees apart means "what did a human
write" and "what did this deployment learn" is answerable by listing a
directory, and a generated pack can never be mistaken for a shipped one.

Three defects found at P11 planning are fixed here, each of which was harmless
only while packs were hand-written and few:

  **DEF-11** — versions were ordered by string comparison, so `1.0.10` sorted
  *below* `1.0.9` and `1.2.0` above `1.10.0`. P11 mints versions programmatically
  and reaches `.10` in an afternoon.

  **DEF-12** — `TRAINED_ROOT` was defined and referenced nowhere, so a pack
  compiled into `packs/trained/` would have been silently invisible. A deferred
  capability must raise, never degrade.

  **DEF-13** — pack checksums were declared and never verified. See
  `api/ingest/pack_checksum.py` for the convention and the argument.
"""

from __future__ import annotations

import functools
from pathlib import Path

import yaml

from api.ingest.pack_activation import ACTIVATION_RECORD, ActivationRecord
from api.ingest.pack_checksum import PackChecksumError, verify_file
from api.models.pack import PackStatus, VendorPack

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PACKS_ROOT = REPO_ROOT / "packs" / "builtin"
TRAINED_ROOT = REPO_ROOT / "packs" / "trained"

PACK_ROOTS: tuple[Path, ...] = (PACKS_ROOT, TRAINED_ROOT)
"""Every directory a pack may legitimately be loaded from, builtin first."""


class PackLoadError(RuntimeError):
    """A pack file exists but could not be read as a VendorPack."""


class DuplicateActivePackError(PackLoadError):
    """Two ACTIVE packs claim the same platform (decision D46).

    Resolved by *raising*, never by picking one. Silently selecting the
    higher-sorting version would mean the fleet is parsed by a pack nobody chose,
    and the operator's evidence would cite a `pack_version` they never activated.
    Exactly one pack per platform may be active; making that another version's
    job is what `activate()` is for.
    """


def semver_key(version: str) -> tuple[int, ...]:
    """Order a pack version numerically (DEF-11).

    `"1.0.10"` must sort above `"1.0.9"`, which string comparison gets backwards.
    The contract already constrains `pack_version` to a three-part numeric
    version, so the split is total; a malformed version sorts last rather than
    raising, because the contract is the place that rejects one.
    """
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:  # pragma: no cover - the contract's SEMVER pattern precludes it
        return (-1,)


def load_pack(path: Path) -> VendorPack:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PackLoadError(f"{path.name}: invalid YAML — {exc}") from exc
    if not isinstance(raw, dict):
        raise PackLoadError(f"{path.name}: expected a mapping at the top level")
    try:
        return VendorPack(**raw)
    except Exception as exc:
        raise PackLoadError(f"{path.name}: {exc}") from exc


def verify_active_checksum(pack: VendorPack, path: Path) -> None:
    """Refuse to load an ACTIVE pack whose bytes do not match its checksum (D47).

    Fails closed, and fails loudly. The alternative — skipping the offending pack
    and carrying on — would leave a platform silently unparsed, which reads
    downstream as a device with no security configuration rather than as an
    integrity failure. The pack contract already requires an ACTIVE pack to carry
    a checksum; this is what makes that requirement mean something.

    A DRAFT or VALIDATED pack is not checked. It is still being edited, and
    demanding a stamp on every intermediate save would make the stamp a
    formality rather than an attestation.
    """
    if pack.status is not PackStatus.ACTIVE:
        return
    result = verify_file(path)
    if not result.verified:
        raise PackChecksumError(
            f"refusing to load ACTIVE pack {pack.pack_id} {pack.pack_version}: {result.describe()}"
        )


def discover_packs(
    root: Path | None = None, roots: tuple[Path, ...] | None = None
) -> list[VendorPack]:
    """Every pack under the given roots, newest version first within a platform.

    `root` loads a single directory and exists for tests that want one; the
    default reads both `packs/builtin/` and `packs/trained/` (D45).
    """
    search = (root,) if root is not None else (roots if roots is not None else PACK_ROOTS)

    packs: list[VendorPack] = []
    for directory in search:
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*.yaml")):
            if path.name == ACTIVATION_RECORD:
                continue
            pack = load_pack(path)
            verify_active_checksum(pack, path)
            packs.append(pack)

    packs.sort(key=lambda p: (p.vendor, p.os_family, semver_key(p.pack_version)), reverse=True)
    return packs


def active_packs(
    root: Path | None = None, roots: tuple[Path, ...] | None = None
) -> list[VendorPack]:
    """Only packs marked active — the ones detection is allowed to consult.

    Raises when a platform has more than one, rather than resolving the
    competition by sort order (D46).
    """
    found = discover_packs(root, roots)

    # The record is read from the root being searched, not from the default
    # trained root. A caller that points the loader at one directory — a test, or
    # a deployment with a relocated pack tree — must get that directory's
    # activation state, not this machine's.
    record_root = root if root is not None else TRAINED_ROOT
    record = ActivationRecord.load(record_root)

    chosen: list[VendorPack] = []
    for pack in found:
        pinned = record.version_for(pack.pack_id)
        if pinned is not None:
            # The deployment has chosen a version for this platform; the shipped
            # `status:` of every version is superseded by that choice.
            if pack.pack_version == pinned:
                chosen.append(pack)
            continue
        if pack.status is PackStatus.ACTIVE:
            chosen.append(pack)

    for pack_id, version in record.active.items():
        if not any(p.pack_id == pack_id for p in chosen):
            raise PackLoadError(
                f"the activation record names {pack_id} {version} as active, but no "
                "such pack version is on disk. Rather than silently falling back to "
                "another version, this refuses: an operator who activated a pack must "
                "not be parsed by a different one."
            )

    seen: dict[str, str] = {}
    for pack in chosen:
        if pack.pack_id in seen:
            raise DuplicateActivePackError(
                f"{pack.pack_id} has two ACTIVE packs: {seen[pack.pack_id]} and "
                f"{pack.pack_version}. Exactly one version of a platform may be "
                "active; deprecate the other rather than relying on load order."
            )
        seen[pack.pack_id] = pack.pack_version

    return chosen


@functools.lru_cache(maxsize=1)
def _cached_active() -> tuple[VendorPack, ...]:
    return tuple(active_packs())


def load_active_packs(*, use_cache: bool = True) -> list[VendorPack]:
    """Active packs, cached because detection reads them for every file.

    The cache is explicitly clearable: P11 activates new pack versions at
    runtime and must be able to invalidate this without a restart, which is the
    whole point of the no-redeployment clause.
    """
    if use_cache:
        return list(_cached_active())
    return active_packs()


def clear_pack_cache() -> None:
    _cached_active.cache_clear()


def find_pack(
    vendor: str | None, os_family: str | None, packs: list[VendorPack] | None = None
) -> VendorPack | None:
    if vendor is None or os_family is None:
        return None
    for pack in packs if packs is not None else load_active_packs():
        if pack.vendor == vendor and pack.os_family == os_family:
            return pack
    return None
