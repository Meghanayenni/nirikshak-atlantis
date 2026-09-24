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

**Where the source document lives differs by framework** (ADR 0052). The NIST
catalog is not in this repository (ADR 0035). The DISA STIG XCCDF is, at the
index's `held_at`, because it is a public-domain US Government work — so that
index is verifiable from the tree alone. The CIS Benchmark never is: its terms
forbid third-party hosting, so its index records the edition and sha256 of a file
read from outside the tree, and nothing else. An index is needed at runtime; its
source document never is.

**An edition may cover one platform.** NIST SP 800-53 is written for any system
and its index declares no `covers`. A STIG or a CIS Benchmark is written for one
product, so a mapping from a vendor-neutral rule to one of its identifiers holds
only on devices that product describes — a STIG identifier beside a finding on
another vendor's device would cite a document that says nothing about it. The
platform itself is data in the index; this module never names one.
"""

from __future__ import annotations

import enum
import functools
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import yaml

from api.models.enums import Framework
from api.models.rule import ComplianceRule, FrameworkRef

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


class Coverage(enum.Enum):
    """Whether an edition speaks about a given device."""

    COVERED = "covered"
    NOT_COVERED = "not_covered"
    UNDETERMINABLE = "undeterminable"
    """The platform matches but the release could not be read from the file.

    Treated as *not covered* everywhere it is consumed: an identifier shown
    beside a device the edition may not describe is a citation nobody checked.
    Kept distinct so the reason given to an operator is the true one.
    """


@dataclass(frozen=True, slots=True)
class PlatformScope:
    """The platform one edition is written for. Our words in `basis`, not theirs."""

    vendor: str
    os_family: str
    os_version: re.Pattern[str]
    basis: str

    def describe(self) -> str:
        return f"{self.vendor}/{self.os_family} with a release matching {self.os_version.pattern!r}"


class CatalogIndex:
    """One framework catalog's identifiers, and where they came from."""

    __slots__ = (
        "framework",
        "document",
        "edition",
        "source_url",
        "held_at",
        "source_note",
        "sha256",
        "covers",
        "_live",
        "_withdrawn",
    )

    def __init__(self, raw: dict, *, path: Path) -> None:
        try:
            self.framework = Framework(raw["framework"])
            self.document: str = raw["document"]
            self.edition: str = str(raw["edition"])
            self.source_url: str = raw.get("source_url", "")
            self.held_at: str = raw.get("held_at", "")
            self.source_note: str = raw.get("source_note", "")
            self.sha256: str = raw["catalog_sha256"]
            self._live = frozenset(str(c) for c in raw.get("controls") or ())
            self._withdrawn = frozenset(str(c) for c in raw.get("withdrawn") or ())
            covers = raw.get("covers")
            self.covers: PlatformScope | None = (
                None
                if covers is None
                else PlatformScope(
                    vendor=covers["vendor"],
                    os_family=covers["os_family"],
                    os_version=re.compile(covers["os_version"]),
                    basis=covers["basis"],
                )
            )
        except (KeyError, ValueError, re.error) as exc:
            raise FrameworkIndexError(f"{path.name}: {exc}") from exc

        if not self._live:
            raise FrameworkIndexError(
                f"{path.name} names no controls. An index that validates nothing "
                "would let any identifier through, which is worse than no index."
            )
        if not (self.source_url or self.held_at or self.source_note):
            raise FrameworkIndexError(
                f"{path.name} says nothing about where its catalog came from. A digest "
                "is only checkable by someone who can find the document it digests."
            )

    def coverage(
        self, vendor: str | None, os_family: str | None, os_version: str | None
    ) -> Coverage:
        """Whether this edition describes a device on this platform and release."""
        if self.covers is None:
            return Coverage.COVERED
        if vendor != self.covers.vendor or os_family != self.covers.os_family:
            return Coverage.NOT_COVERED
        if not os_version:
            return Coverage.UNDETERMINABLE
        if self.covers.os_version.search(os_version):
            return Coverage.COVERED
        return Coverage.NOT_COVERED

    def explain_coverage(
        self, vendor: str | None, os_family: str | None, os_version: str | None
    ) -> str:
        """The sentence an operator reads when this edition does not apply."""
        state = self.coverage(vendor, os_family, os_version)
        if state is Coverage.COVERED or self.covers is None:
            return f"{self.document} {self.edition} covers this device."
        platform = f"{vendor or 'unknown'}/{os_family or 'unknown'}"
        if state is Coverage.UNDETERMINABLE:
            return (
                f"{self.document} {self.edition} is written for "
                f"{self.covers.describe()}; this {platform} device's release could not "
                "be read from its configuration, so whether the edition applies is "
                "undetermined and none of its identifiers is shown."
            )
        release = f" release {os_version}" if os_version else ""
        return (
            f"{self.document} {self.edition} is written for {self.covers.describe()}; "
            f"this device is {platform}{release}, which the edition does not describe."
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


def mappings_for_device(
    rules: Iterable[ComplianceRule],
    vendor: str | None,
    os_family: str | None,
    os_version: str | None,
) -> dict[str, tuple[FrameworkRef, ...]]:
    """Each rule's mappings that hold on this device, keyed by rule id.

    What a persisted finding is re-attached with, because `frameworks` is
    rulepack data and is not stored per finding (ADR 0036, D96). Both routes that
    re-read findings — the report and the findings API — use this one function,
    so the two surfaces cannot disagree about which identifiers a device carries.
    The caller decides *whether* to attach: only when the run's rulepack version
    is the active one.
    """
    return {
        rule.rule_id: refs_for_device(rule.frameworks, vendor, os_family, os_version)
        for rule in rules
    }


def explain_absence(
    vendor: str | None, os_family: str | None, os_version: str | None
) -> dict[str, str]:
    """Why each framework contributes no identifier on this device, by name.

    Two different absences, and a report must not render them alike: *nobody has
    read this benchmark* (ISO/IEC 27001) and *the benchmark was read and does not
    describe this device* (one vendor's STIG, on another vendor's router). The first
    is `SOURCING_BACKLOG` gap 4; the second is a fact about the edition. Covered
    frameworks are omitted — they have nothing to explain.
    """
    available = indexes()
    out: dict[str, str] = {}
    for framework in Framework:
        index = available.get(framework)
        if index is None:
            out[framework.value] = (
                f"no {framework.value.upper()} catalog has been sourced, so this report "
                "says nothing about it either way"
            )
        elif index.coverage(vendor, os_family, os_version) is not Coverage.COVERED:
            out[framework.value] = index.explain_coverage(vendor, os_family, os_version)
    return out


def refs_for_device(
    refs: Iterable[FrameworkRef],
    vendor: str | None,
    os_family: str | None,
    os_version: str | None,
) -> tuple[FrameworkRef, ...]:
    """The mappings that are true of *this* device.

    A rule is vendor-neutral; a STIG or CIS identifier is not. `NRK-HTTP-001`
    maps to `CISC-ND-000470`, and that is a statement about the one platform the
    STIG describes — the same rule failing on another vendor's device is not a
    finding against that STIG.
    A ref survives only when its framework is sourced and its edition covers the
    device; an undeterminable release drops it, because an identifier shown
    beside a device the edition may not describe is a citation nobody checked.
    """
    available = indexes()
    return tuple(
        ref
        for ref in refs
        if (index := available.get(ref.framework)) is not None
        and index.coverage(vendor, os_family, os_version) is Coverage.COVERED
    )


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
