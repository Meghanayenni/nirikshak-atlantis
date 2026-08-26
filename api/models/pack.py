"""Vendor packs — how one platform's syntax maps to the canonical model.

Rule 5: packs are data. Adding a vendor is a configuration change, not a code
release. That is the clause the problem statement is really testing, so this
contract is what makes it true or false.

Patterns are deliberately boring (DEVELOPER_GUIDE.md §4). The compiler at P11 tokenises a
confirmed line, substitutes the captured token, escapes the rest and anchors it
— predictable enough that an administrator who does not write regular
expressions can still read one and see that it is right.
"""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import CastType, MatchType, PackStatus, PatternSource

SEMVER = r"^\d+\.\d+\.\d+$"
SHA256_PREFIXED = r"^sha256:[0-9a-f]{64}$"


class DetectSignature(BaseModel):
    """One weighted hint that a file belongs to this platform.

    Vendor detection is data too — adding a platform must not mean editing an
    if-chain in the ingestion layer.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: MatchType | str = Constraint(description="'regex' | 'filename' | 'xpath' | 'jsonpath'")
    pattern: str = Constraint(min_length=1)
    weight: float = Constraint(ge=0.0, le=1.0)


class MatchSpec(BaseModel):
    """How a pattern recognises a line or node — one of the five primitives."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: MatchType
    pattern: str = Constraint(min_length=1)
    template: str | None = Constraint(
        default=None, description="TextFSM template name, when type is textfsm"
    )

    @model_validator(mode="after")
    def _check(self) -> MatchSpec:
        if self.type is MatchType.REGEX:
            try:
                re.compile(self.pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex {self.pattern!r}: {exc}") from exc
            if not self.pattern.startswith("^"):
                raise ValueError(
                    f"regex {self.pattern!r} is not anchored — generated patterns "
                    "must be anchored with ^ (DEVELOPER_GUIDE.md §4)"
                )
        if self.type is MatchType.TEXTFSM and not self.template:
            raise ValueError("a textfsm match must name its template")
        return self


class CaptureSpec(BaseModel):
    """Which captured token becomes the canonical value, and how it is typed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: str = Constraint(min_length=1, description="e.g. '$1' or a named group")
    cast: CastType = CastType.STR
    map: dict[str, str] | None = Constraint(
        default=None, description="Literal to canonical-value mapping, e.g. {'enable': 'true'}"
    )


class PatternScope(BaseModel):
    """Where in the ConfigTree a pattern is allowed to apply (decision R4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    block: tuple[str, ...] | None = Constraint(
        default=None,
        description=(
            "Required enclosing chain prefix. Without this, 'exec-timeout 10 0' "
            "under 'line con 0' would be read as a management idle timeout."
        ),
    )


class PatternProvenance(BaseModel):
    """How an admin-trained pattern came to exist. Ties back to the audit chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    training_example_id: str | None = None
    suggestion_rank_accepted: int | None = Constraint(default=None, ge=1, le=3)
    audit_seq: int | None = Constraint(default=None, ge=0)


class PatternDef(BaseModel):
    """One mapping from platform syntax to a canonical field."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Constraint(min_length=1)
    field: str = Constraint(min_length=1, description="Canonical field name")
    scope: PatternScope = Constraint(default_factory=PatternScope)
    match: MatchSpec
    capture: CaptureSpec

    confidence: float = Constraint(
        default=1.0,
        ge=0.0,
        le=1.0,
        description=(
            "Parser confidence for this pattern. Not an ML probability (R7) — a "
            "deterministic match either fired or it did not."
        ),
    )
    source: PatternSource = PatternSource.BUILTIN

    examples: tuple[str, ...] = ()
    negative_examples: tuple[str, ...] = Constraint(
        default=(), description="Lines this pattern must NOT match"
    )
    provenance: PatternProvenance | None = None

    @model_validator(mode="after")
    def _check(self) -> PatternDef:
        if self.source is PatternSource.ADMIN_TRAINED and not self.examples:
            raise ValueError(
                f"admin-trained pattern {self.id!r} must retain the confirmed "
                "example it was compiled from, for validation and re-check"
            )
        overlap = set(self.examples) & set(self.negative_examples)
        if overlap:
            raise ValueError(
                f"pattern {self.id!r} lists {sorted(overlap)} as both a positive "
                "and a negative example"
            )
        return self

    def self_check(self) -> list[str]:
        """Verify the pattern against its own examples. Used by the P11 validator.

        Returns a list of failure descriptions; empty means the pattern behaves.
        """
        if self.match.type is not MatchType.REGEX:
            return []

        rx = re.compile(self.match.pattern)
        failures: list[str] = []
        for ex in self.examples:
            if not rx.search(ex):
                failures.append(f"positive example does not match: {ex!r}")
        for neg in self.negative_examples:
            if rx.search(neg):
                failures.append(f"negative example matches but must not: {neg!r}")
        return failures


class PlatformDefault(BaseModel):
    """A documented default, with the citation that makes it usable.

    Absence-aware evaluation depends on this being sourced rather than assumed:
    a guess wearing a citation field is worse than abstaining, because it looks
    authoritative.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1)
    value: str | int | bool | None = None
    applies_when: str | None = None
    citation: str = Constraint(min_length=1, description="Where this default is documented")


class PlatformCapability(BaseModel):
    """Whether a platform can express a control at all.

    `supported is None` means undocumented, which must produce abstention rather
    than an assumption in either direction.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1)
    supported: bool | None = None
    citation: str | None = None

    @model_validator(mode="after")
    def _check(self) -> PlatformCapability:
        if self.supported is not None and not self.citation:
            raise ValueError(
                f"capability claim for {self.field!r} asserts support="
                f"{self.supported} without a citation; assert nothing instead"
            )
        return self


class VendorPack(BaseModel):
    """A versioned, immutable description of one platform's syntax."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    vendor: str = Constraint(min_length=1)
    os_family: str = Constraint(min_length=1)
    pack_version: str = Constraint(pattern=SEMVER)
    status: PackStatus = PackStatus.DRAFT

    parent_version: str | None = Constraint(default=None, pattern=SEMVER)
    created_by: str | None = None
    created_at: datetime | None = None
    checksum: str | None = Constraint(default=None, pattern=SHA256_PREFIXED)

    detect: tuple[DetectSignature, ...] = ()
    patterns: tuple[PatternDef, ...] = ()
    defaults: tuple[PlatformDefault, ...] = ()
    capabilities: tuple[PlatformCapability, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> VendorPack:
        ids = [p.id for p in self.patterns]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate pattern ids in pack: {dupes}")

        if self.status is PackStatus.ACTIVE and not self.checksum:
            raise ValueError(
                "an ACTIVE pack must carry its checksum — activation is recorded "
                "in the audit chain and must be verifiable"
            )
        if self.parent_version == self.pack_version:
            raise ValueError("a pack version cannot be its own parent")
        return self

    # -- access ------------------------------------------------------------

    @property
    def pack_id(self) -> str:
        return f"{self.vendor}/{self.os_family}"

    def patterns_for(self, field: str) -> tuple[PatternDef, ...]:
        return tuple(p for p in self.patterns if p.field == field)

    def default_for(self, field: str) -> PlatformDefault | None:
        return next((d for d in self.defaults if d.field == field), None)

    def capability_for(self, field: str) -> PlatformCapability | None:
        return next((c for c in self.capabilities if c.field == field), None)

    def supports(self, field: str) -> bool | None:
        """True / False / None where None means undocumented — so abstain."""
        cap = self.capability_for(field)
        return cap.supported if cap else None

    def validate_patterns(self) -> dict[str, list[str]]:
        """Run every pattern against its own examples. Empty dict means clean."""
        results = {p.id: p.self_check() for p in self.patterns}
        return {k: v for k, v in results.items() if v}
