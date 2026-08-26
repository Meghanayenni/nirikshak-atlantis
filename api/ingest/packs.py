"""Loading vendor packs from disk.

Packs are data (Rule 5). At P3 they carry `detect` signatures and `identity`
patterns but no parsing `patterns` — a platform NIRIKSHAK recognises but cannot
yet audit. That is an honest state rather than a placeholder: detection works,
the whole file becomes residue, and every canonical field stays UNKNOWN.
"""

from __future__ import annotations

import functools
from pathlib import Path

import yaml

from api.models.pack import PackStatus, VendorPack

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PACKS_ROOT = REPO_ROOT / "packs" / "builtin"
TRAINED_ROOT = REPO_ROOT / "packs" / "trained"


class PackLoadError(RuntimeError):
    """A pack file exists but could not be read as a VendorPack."""


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


def discover_packs(root: Path = PACKS_ROOT) -> list[VendorPack]:
    """Every pack under `root`, newest version first within a platform."""
    if not root.is_dir():
        return []

    packs = [load_pack(path) for path in sorted(root.rglob("*.yaml"))]
    packs.sort(key=lambda p: (p.vendor, p.os_family, p.pack_version), reverse=True)
    return packs


def active_packs(root: Path = PACKS_ROOT) -> list[VendorPack]:
    """Only packs marked active — the ones detection is allowed to consult."""
    return [p for p in discover_packs(root) if p.status is PackStatus.ACTIVE]


@functools.lru_cache(maxsize=1)
def _cached_active() -> tuple[VendorPack, ...]:
    return tuple(active_packs())


def load_active_packs(*, use_cache: bool = True) -> list[VendorPack]:
    """Active packs, cached because detection reads them for every file.

    The cache is explicitly clearable: P11 activates new pack versions at
    runtime and must be able to invalidate this without a restart, which is the
    whole point of the no-redeployment clause.
    """
    if not use_cache:
        return active_packs()
    return list(_cached_active())


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
