"""Framework catalog indexes — what a control identifier is checked against.

A rule may cross-map itself to a framework control. Until P17 none did, and the
reason was never that the machinery was missing: `FrameworkRef` has carried
`version`, `citation` and `mapping_provenance` since P1. What was missing was a
way to know that a control identifier is **real**.

That is what an index is. `scripts/fetch_framework_catalog.py` reads an official
catalog and derives, per framework:

  * the catalog's own **sha256**, so the identifiers can be traced to an exact
    document rather than to a version string somebody typed;
  * its **edition** as the document itself declares it;
  * every **live** control identifier;
  * every **withdrawn** one, kept separately and deliberately.

Withdrawn controls matter more than they look. `AC-17(08)` ("Disable Nonsecure
Network Protocols") and `AU-08(01)` ("Synchronization with Authoritative Time
Source") are both withdrawn in Rev 5, and both are precisely what somebody would
write from memory for two of NIRIKSHAK's own checks. An index that merely
omitted them would report "no such control", which reads like a typo. Naming
them says *this identifier is real and you may not map to it*, which is the
thing worth knowing.

**Identifiers only.** No control text, no titles, no assessment procedure — per
`docs/CONTENT_POLICY.md`. The engine matches on identifiers and never on prose,
so nothing here costs the system a capability.

**The catalogs themselves are not in this repository.** An index is derived from
one; using it needs nothing at runtime. See ADR 0035 for the redistribution
question, which is recorded as open rather than answered.
"""

from __future__ import annotations

import functools
from collections.abc import Iterable
from pathlib import Path

import yaml

from api.models.enums import Framework

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FRAMEWORK_INDEX_ROOT = REPO_ROOT / "rules" / "frameworks"


class FrameworkIndexError(RuntimeError):
    """An index file exists but cannot be read as one."""


class UnsourcedFrameworkError(ValueError):
    """A caller asked to evaluate against a framework with no sourced catalog.

    Refused rather than answered with an empty result. "No findings" reads as a
    clean bill of health; "we have never read this benchmark" is a different
    statement, and a selector that returned the first for the second would turn
    a sourcing gap into a compliance claim.
    """


class CatalogIndex:
    """One framework catalog's identifiers, and where they came from."""

    __slots__ = ("framework", "document", "edition", "source_url", "sha256", "_live", "_withdrawn")

    def __init__(self, raw: dict, *, path: Path) -> None:
        try:
            self.framework = Framework(raw["framework"])
            self.document: str = raw["document"]
            self.edition: str = str(raw["edition"])
            self.source_url: str = raw.get("source_url", "")
            self.sha256: str = raw["catalog_sha256"]
            self._live = frozenset(raw.get("controls") or ())
            self._withdrawn = frozenset(raw.get("withdrawn") or ())
        except (KeyError, ValueError) as exc:
            raise FrameworkIndexError(f"{path.name}: {exc}") from exc

        if not self._live:
            raise FrameworkIndexError(
                f"{path.name} names no controls. An index that validates nothing "
                "would let any identifier through, which is worse than no index."
            )

    def knows(self, control_id: str) -> bool:
        return control_id in self._live

    def is_withdrawn(self, control_id: str) -> bool:
        return control_id in self._withdrawn

    def cite(self, control_id: str) -> str:
        """The citation a mapping to this control must carry.

        Names the document, its exact edition and the identifier — enough for a
        reader to look the control up themselves, which is the whole purpose of
        a citation and the limit of what the content policy permits storing.
        """
        return f"{self.document}, edition {self.edition}, control {control_id}"

    @property
    def control_count(self) -> int:
        return len(self._live)

    def describe(self) -> str:
        return (
            f"{self.framework.value}: {self.document} edition {self.edition}, "
            f"{len(self._live)} live and {len(self._withdrawn)} withdrawn controls, "
            f"sha256 {self.sha256[:12]}…"
        )


def load_indexes(root: Path = FRAMEWORK_INDEX_ROOT) -> dict[Framework, CatalogIndex]:
    """Every framework index on disk, keyed by framework.

    A framework absent from this mapping has **no sourced catalog**, and a rule
    may not map to it. That is the difference between "we support ISO 27001 and
    found nothing" and "we have never read ISO 27001", and the two must not
    render the same anywhere.
    """
    if not root.is_dir():
        return {}

    out: dict[Framework, CatalogIndex] = {}
    for path in sorted(root.glob("*.index.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise FrameworkIndexError(f"{path.name}: expected a mapping at the top level")
        index = CatalogIndex(raw, path=path)
        if index.framework in out:
            raise FrameworkIndexError(
                f"two indexes claim {index.framework.value}; one edition per framework, "
                "so a citation names exactly one document"
            )
        out[index.framework] = index
    return out


@functools.lru_cache(maxsize=1)
def _cached() -> tuple[tuple[Framework, CatalogIndex], ...]:
    return tuple(load_indexes().items())


def indexes() -> dict[Framework, CatalogIndex]:
    return dict(_cached())


def sourced_frameworks() -> frozenset[Framework]:
    """Frameworks with a catalog behind them.

    This is what a framework selector may offer. A framework with no sourced
    mapping is **absent** from the list rather than present and empty: an empty
    result reads as "your fleet is compliant", and that is not what "we never
    read this benchmark" means.
    """
    return frozenset(indexes())


def clear_index_cache() -> None:
    _cached.cache_clear()


def resolve_selection(names: Iterable[str]) -> frozenset[Framework]:
    """Turn requested framework names into a selection, or refuse.

    Refuses an unknown name and a known-but-unsourced one with different
    messages, because they send the caller to different places: a typo is theirs
    to fix, and a missing catalog is `SOURCING_BACKLOG` gap 4.
    """
    available = indexes()
    selected: set[Framework] = set()

    for name in names:
        key = name.strip().lower()
        if not key:
            continue
        try:
            framework = Framework(key)
        except ValueError:
            raise UnsourcedFrameworkError(
                f"{name!r} is not a framework this system knows. Available: "
                + ", ".join(sorted(f.value for f in available))
            ) from None
        if framework not in available:
            raise UnsourcedFrameworkError(
                f"no catalog has been sourced for {framework.value}, so no rule maps "
                "to it and evaluating against it would report zero findings — which "
                "reads as compliance. Available: "
                + (", ".join(sorted(f.value for f in available)) or "none")
            )
        selected.add(framework)

    return frozenset(selected)
