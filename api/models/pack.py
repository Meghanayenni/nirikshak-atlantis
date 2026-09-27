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

from api.models.enums import (
    AclDialect,
    AclType,
    CastType,
    MatchType,
    PackStatus,
    PatternSource,
    PlatformSourceType,
    ProvenanceStatus,
    SyntaxMode,
)

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
    distinct: bool = Constraint(
        default=False,
        description=(
            "For a multi-valued field: repeated captures name ONE object, so the "
            "value keeps each once (ADR 0065). A JunOS `set` file writes one syslog "
            "host as several lines; an IOS file listing a server twice does not."
        ),
    )


class PatternScope(BaseModel):
    """Where in the ConfigTree a pattern is allowed to apply (decision R4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    block: tuple[str, ...] | None = Constraint(
        default=None,
        description=(
            "Enclosing block headers as ANCHORED regular expressions, matched in "
            "full against each element of a node's block_path (decision D9). "
            "None means root level only; an empty tuple means any depth."
        ),
    )

    @model_validator(mode="after")
    def _check_anchored(self) -> PatternScope:
        """D9 — a scope matches a whole block header, never a substring.

        Unanchored matching cannot distinguish `line vty 0 4` from `line vty 0 15`,
        and a scope that quietly matches more blocks than its author intended is
        how a console timeout ends up reported as a management idle timeout.
        Matching uses `re.fullmatch`; requiring the leading `^` keeps the intent
        visible in the YAML rather than buried in the engine.
        """
        for entry in self.block or ():
            if not entry.startswith("^"):
                raise ValueError(
                    f"scope block pattern {entry!r} is not anchored. Write the full "
                    "block header, e.g. '^line vty 0 4$'. Numeric generalisation is "
                    "allowed but must be written deliberately, never assumed (D9)."
                )
            try:
                re.compile(entry)
            except re.error as exc:
                raise ValueError(f"invalid scope regex {entry!r}: {exc}") from exc
        return self

    def matches(self, block_path: tuple[str, ...]) -> bool:
        """Does a node at `block_path` fall inside this scope?"""
        if self.block is None:
            return len(block_path) == 0
        if len(block_path) < len(self.block):
            return False
        return all(
            re.fullmatch(pattern, actual) is not None
            for pattern, actual in zip(self.block, block_path[: len(self.block)], strict=True)
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

    @model_validator(mode="after")
    def _confidence_is_exact(self) -> PatternDef:
        """D6 — a deterministic match is worth exactly 1.0, and YAML cannot say otherwise."""
        if self.confidence != 1.0:
            raise ValueError(
                "deterministic confidence must be exactly 1.0; a pattern either "
                "matched or it did not. Fractional deterministic confidence needs "
                "a new ADR, not a YAML value (D6)."
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


class IdentityPattern(BaseModel):
    """How to read one device-identity field from this platform's syntax.

    Decision D3. Device identity — hostname, model, OS version, serial — is not
    a security control, so it has no place among the canonical `patterns`. It is
    still vendor-specific and must still be data rather than code, so it reuses
    the same `MatchSpec` and `CaptureSpec` types the parsing patterns use.

    Deterministic and data-driven, like everything else here: a pattern matched
    or it did not, and a field nothing matched stays UNKNOWN rather than being
    invented.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1, description="hostname · model · os_version · serial")
    match: MatchSpec
    capture: CaptureSpec = Constraint(default_factory=lambda: CaptureSpec(value="$1"))
    confidence: float = Constraint(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Parser confidence. Not an ML probability (R7).",
    )
    examples: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _confidence_is_exact(self) -> IdentityPattern:
        """D6 — a deterministic match is worth exactly 1.0, and YAML cannot say otherwise."""
        if self.confidence != 1.0:
            raise ValueError(
                "deterministic confidence must be exactly 1.0; a pattern either "
                "matched or it did not. Fractional deterministic confidence needs "
                "a new ADR, not a YAML value (D6)."
            )
        return self


IDENTITY_FIELDS: frozenset[str] = frozenset(
    {"hostname", "model", "os_version", "serial", "domain_name"}
)
"""Recognised identity fields. Reference rather than enforcement — the mapping
stays open so a platform exposing something else is a data change."""


class LiteralBlock(BaseModel):
    """A region whose body is free-form text rather than configuration (D7).

    Banner bodies, certificate blocks, key blocks — anywhere the lines between an
    opener and a terminator are content rather than commands.

    Two things go wrong when such a body is treated as configuration. It floods
    the training queue with prose, and — much worse — it becomes reachable by
    pattern matching, so a banner reading "ip ssh version 1 is prohibited" would
    produce a security fact that is not in effect. Declaring the block keeps its
    body preserved and citable while putting it beyond the engine's reach.

    Deliberately not banner-specific: a terminator is either a fixed literal
    (`quit` closing a certificate) or a delimiter captured from the opener
    (`^C` in `banner motd ^C`).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Constraint(min_length=1, description="e.g. 'banner', 'certificate'")
    open: str = Constraint(min_length=1, description="Anchored regex opening the block")
    terminator: str | None = Constraint(default=None, description="Fixed closing line, e.g. 'quit'")
    terminator_group: int | None = Constraint(
        default=None,
        ge=1,
        description="Capture group in `open` holding the delimiter, e.g. '^C'",
    )

    @model_validator(mode="after")
    def _check(self) -> LiteralBlock:
        if not self.open.startswith("^"):
            raise ValueError(f"literal block opener {self.open!r} must be anchored with ^")
        try:
            compiled = re.compile(self.open)
        except re.error as exc:
            raise ValueError(f"invalid literal block regex {self.open!r}: {exc}") from exc

        if (self.terminator is None) == (self.terminator_group is None):
            raise ValueError(
                f"literal block {self.name!r} must declare exactly one of terminator "
                "(a fixed closing line) or terminator_group (a delimiter captured "
                "from the opener)"
            )
        if self.terminator_group is not None and compiled.groups < self.terminator_group:
            raise ValueError(
                f"literal block {self.name!r} names capture group "
                f"{self.terminator_group} but {self.open!r} has {compiled.groups}"
            )
        return self


class PlatformProvenance(BaseModel):
    """Where a platform default or capability claim comes from (decision D11).

    Typed rather than a free string, because a free string is a place to write
    "general knowledge" and have it pass every test in the repository. A platform
    default is the one security claim NIRIKSHAK makes with **no configuration
    line to cite** — the whole premise is that the directive is absent — so the
    provenance is the entire justification. Making an unsourced claim
    unconstructable is the only mechanism that keeps that honest.

    `project_asserted` exists so a claim we cannot yet source can still be
    written down and reviewed. It is **not** vendor documentation, must never be
    presented as externally verified, and is not admissible: a field resting on
    one abstains rather than asserting.

    Per `docs/CONTENT_POLICY.md`, this records *identifiers and locators* only.
    Transcribed vendor prose does not belong in the repository, and nothing here
    is a place to put it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    platform: str = Constraint(
        min_length=1,
        description="Vendor/OS-family the claim is about, e.g. 'cisco/ios'",
    )
    source_type: PlatformSourceType
    source_id: str = Constraint(
        default="",
        description="Document identifier or title — never its prose",
    )
    locator: str = Constraint(
        default="",
        description="Where in that document: section, table, page or anchor",
    )
    status: ProvenanceStatus
    applies_to_versions: str | None = Constraint(
        default=None,
        description="OS version range the claim was verified against, if narrower",
    )

    @model_validator(mode="after")
    def _check(self) -> PlatformProvenance:
        asserted_type = self.source_type is PlatformSourceType.PROJECT_ASSERTED
        asserted_status = self.status is ProvenanceStatus.PROJECT_ASSERTED

        # Biconditional, so an assertion cannot be laundered into a sourced claim
        # by relabelling one half of the pair.
        if asserted_type != asserted_status:
            raise ValueError(
                "project_asserted provenance must use BOTH source_type and status "
                "'project_asserted'. Marking one without the other would let an "
                "assertion be presented as externally verified (D11)."
            )

        if self.status is ProvenanceStatus.SOURCED:
            if not self.source_id.strip():
                raise ValueError(
                    f"sourced provenance for {self.platform!r} names no document. "
                    "A claim that cannot be looked up is an assertion — mark it "
                    "project_asserted instead (D11)."
                )
            if not self.locator.strip():
                raise ValueError(
                    f"sourced provenance for {self.platform!r} names "
                    f"{self.source_id!r} but no locator. 'Somewhere in the "
                    "configuration guide' is not a citation (D11)."
                )
        return self

    @property
    def is_admissible(self) -> bool:
        """Whether a claim resting on this may support a compliance verdict.

        Only `SOURCED`. Everything else abstains — an unverified default must
        never become a PASS or a FAIL (Rule 3).
        """
        return self.status.is_admissible

    def cite(self) -> str:
        """Short human-readable citation for reports and `Field.default_ref`.

        A `project_asserted` claim says so in its own citation string, so it
        cannot be mistaken for a sourced one anywhere it is displayed.
        """
        if self.status is ProvenanceStatus.PROJECT_ASSERTED:
            return f"{self.platform} — NIRIKSHAK project assertion (not externally verified)"
        version = f" [{self.applies_to_versions}]" if self.applies_to_versions else ""
        return f"{self.platform} — {self.source_id}, {self.locator}{version}"


class PlatformDefault(BaseModel):
    """A documented default, with the provenance that makes it usable.

    Absence-aware evaluation depends on this being sourced rather than assumed:
    a guess wearing a citation field is worse than abstaining, because it looks
    authoritative.

    There is deliberately **no confidence field** (decision D13). The confidence
    an accepted default carries is a single configured value, not something a
    pack author chooses per entry — otherwise the number becomes a dial for
    making a weak claim look strong, which is the same failure D6 closed for
    deterministic patterns. `extra="forbid"` means YAML cannot add one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1)
    value: str | int | bool | None = None
    applies_when: str | None = None
    provenance: PlatformProvenance

    @property
    def is_admissible(self) -> bool:
        return self.provenance.is_admissible


class PlatformCapability(BaseModel):
    """Whether a platform can express a control at all.

    `supported is None` means undocumented, which must produce abstention rather
    than an assumption in either direction.

    Carries the same typed provenance as `PlatformDefault`, for the same reason:
    `supported: false` resolves to ABSENT_UNSUPPORTED, which is a determinable
    state a compliance rule may act on. An unsourced claim that a platform cannot
    express a control is exactly as capable of producing a wrong verdict as an
    unsourced default.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    field: str = Constraint(min_length=1)
    supported: bool | None = None
    provenance: PlatformProvenance | None = None

    @model_validator(mode="after")
    def _check(self) -> PlatformCapability:
        if self.supported is not None and self.provenance is None:
            raise ValueError(
                f"capability claim for {self.field!r} asserts support="
                f"{self.supported} without provenance; assert nothing instead"
            )
        return self

    @property
    def is_admissible(self) -> bool:
        """An undocumented capability is not a claim, so there is nothing to admit."""
        return self.provenance is not None and self.provenance.is_admissible


class InterfaceRole(BaseModel):
    """Which interface names are management-plane on a platform (decision D88).

    P12's exposure ranking abstains on every device with
    `indeterminate_interfaces`: interfaces are read, and nothing establishes
    which of them is the management plane. This is the construct that could say
    so, and it is deliberately **not** a heuristic.

    `Loopback0` carries the description `MGMT-LOOPBACK` and `fxp0` carries
    `OUT-OF-BAND-MGMT`. Reading "MGMT" out of an operator's free text would be a
    guess wearing a citation, and DEF-2 already settled that an undocumented
    interface is not a non-management one. So a role is a **claim about the
    platform** — the same kind of thing as `PlatformDefault` and
    `PlatformCapability`, carrying the same typed provenance, admissible only
    when `SOURCED`.

    **A name that matches nothing here is `None`, never `False`.** Declaring
    that `^Management\\d+$` is management says nothing whatever about
    `GigabitEthernet0/0`. Saying an interface is *not* management is its own
    declaration with `is_management: false` and its own citation, because
    `is_management is False` is a determinable state the exposure ranking acts
    on — exactly as capable of producing a wrong answer as a `True`.

    This is the second half of what DEF-2 protects. The first half was the
    accessor refusing to fold `None` into "not management"; this is the pack
    contract refusing to let silence do it instead.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name_pattern: str = Constraint(
        min_length=1,
        description="Anchored regex matching interface names this role covers",
    )
    is_management: bool
    provenance: PlatformProvenance
    examples: tuple[str, ...] = Constraint(
        default=(),
        description="Interface names a person read, for review",
    )

    @model_validator(mode="after")
    def _check(self) -> InterfaceRole:
        if not self.name_pattern.startswith("^"):
            raise ValueError(
                f"interface role pattern {self.name_pattern!r} is not anchored with ^. "
                "An unanchored pattern would classify 'not-Management0' as a "
                "management interface, which is how a role declaration becomes the "
                "heuristic it exists to replace."
            )
        try:
            compiled = re.compile(self.name_pattern)
        except re.error as exc:
            raise ValueError(
                f"interface role pattern {self.name_pattern!r} is invalid: {exc}"
            ) from exc

        for example in self.examples:
            if not compiled.match(example):
                raise ValueError(
                    f"interface role example {example!r} does not match its own "
                    f"pattern {self.name_pattern!r}"
                )
        return self

    @property
    def is_admissible(self) -> bool:
        """Whether this role may classify an interface at all.

        Only `SOURCED`. A `project_asserted` role can be written down and
        reviewed — that is what the status is for — but it may not reach the
        exposure ranking, because the ranking decides what an operator fixes
        first and an unverified claim must not.
        """
        return self.provenance.is_admissible


class AclExtraction(BaseModel):
    """How one platform writes access lists, declared as data (Rule 5).

    The regexes locate the *structure* — where a list opens, where it is bound
    to an interface. The entries themselves are read by the named `dialect`,
    because turning `0.0.0.255` into `/24` is arithmetic, not matching.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    dialect: AclDialect
    acl_type: AclType = AclType.EXTENDED

    named_block: str = Constraint(
        min_length=1,
        description="Anchored regex opening a named list; group 1 is the name.",
    )
    applied: str | None = Constraint(
        default=None,
        description=(
            "Anchored regex binding a list inside an interface block; group 1 is "
            "the name and group 2 the direction. None when the platform's binding "
            "syntax is not read yet — bindings are then absent rather than wrong."
        ),
    )
    remark: str | None = Constraint(
        default=None,
        description="Anchored regex for a comment line inside a list. Not an entry.",
    )
    brace_block: str | None = Constraint(
        default=None,
        description=(
            "Anchored regex opening a named list in a brace-nested file; group 1 "
            "is the name. A platform shipping one surface declares only "
            "`named_block`; JunOS ships two and declares both."
        ),
    )
    examples: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> AclExtraction:
        for name, raw in (
            ("named_block", self.named_block),
            ("applied", self.applied),
            ("brace_block", self.brace_block),
        ):
            if raw is None:
                continue
            if not raw.startswith("^"):
                raise ValueError(f"{name} regex {raw!r} is not anchored with ^")
            try:
                re.compile(raw)
            except re.error as exc:
                raise ValueError(f"{name} regex {raw!r} is invalid: {exc}") from exc
        return self


class InterfaceExtraction(BaseModel):
    """How one platform writes interfaces, declared as data (Rule 5)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    block: str = Constraint(
        min_length=1, description="Anchored regex opening an interface; group 1 is the name."
    )
    description: str | None = None
    ip_address: str | None = Constraint(
        default=None, description="Group 1 address, optional group 2 mask."
    )
    shutdown: str | None = None
    no_shutdown: str | None = None
    examples: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check(self) -> InterfaceExtraction:
        for name in ("block", "description", "ip_address", "shutdown", "no_shutdown"):
            raw = getattr(self, name)
            if raw is None:
                continue
            if not raw.startswith("^"):
                raise ValueError(f"{name} regex {raw!r} is not anchored with ^")
            try:
                re.compile(raw)
            except re.error as exc:
                raise ValueError(f"{name} regex {raw!r} is invalid: {exc}") from exc
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
    identity: tuple[IdentityPattern, ...] = Constraint(
        default=(), description="Device-identity extraction (D3)"
    )
    literal_blocks: tuple[LiteralBlock, ...] = Constraint(
        default=(), description="Regions whose bodies are text, not commands (D7)"
    )
    comment_prefixes: tuple[str, ...] = Constraint(
        default=(),
        description=(
            "Line prefixes marking a comment. A commented-out directive must never "
            "produce a PRESENT field, so these never become nodes."
        ),
    )
    syntax_mode: SyntaxMode | None = Constraint(
        default=None,
        description=(
            "How this platform's files express hierarchy, declared by the pack "
            "(ADR 0067). Absent on every pack written before it, which keep the "
            "mode `api/parse/service.py` assigns their OS family. A bootstrapped "
            "platform has no entry there, so it must say."
        ),
    )
    patterns: tuple[PatternDef, ...] = ()
    acl_extraction: AclExtraction | None = Constraint(
        default=None, description="How this platform writes access lists (P16)"
    )
    interface_extraction: InterfaceExtraction | None = Constraint(
        default=None, description="How this platform writes interfaces (P16)"
    )
    defaults: tuple[PlatformDefault, ...] = ()
    capabilities: tuple[PlatformCapability, ...] = ()
    interface_roles: tuple[InterfaceRole, ...] = ()

    @property
    def admissible_interface_roles(self) -> tuple[InterfaceRole, ...]:
        """Roles that may classify an interface — sourced ones only."""
        return tuple(role for role in self.interface_roles if role.is_admissible)

    @model_validator(mode="after")
    def _check(self) -> VendorPack:
        ids = [p.id for p in self.patterns]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate pattern ids in pack: {dupes}")

        patterns = [r.name_pattern for r in self.interface_roles]
        if len(patterns) != len(set(patterns)):
            dupes = sorted({p for p in patterns if patterns.count(p) > 1})
            raise ValueError(
                f"duplicate interface role patterns in pack: {dupes}. Two roles "
                "matching the same names would make the classification depend on "
                "declaration order."
            )

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

    def identity_for(self, field: str) -> IdentityPattern | None:
        """The first declared pattern for a field. See `identities_for`."""
        return next((i for i in self.identity if i.field == field), None)

    def identities_for(self, field: str) -> tuple[IdentityPattern, ...]:
        """**Every** declared pattern for a field, in declaration order.

        A platform can write one identity fact more than one way. JunOS ships
        the same configuration as `set system host-name r1` and as an indented
        `host-name r1;` inside a `system { … }` block, and a pack covering both
        surfaces declares both.

        `identity_for` returns only the first, so a second declaration was read
        by nothing — the shape DEF-12 is named for. It is kept because callers
        that legitimately want "the canonical one" exist, and because removing
        an accessor is not how that bug is prevented; `extract_identity` uses
        this one.
        """
        return tuple(i for i in self.identity if i.field == field)

    @property
    def is_detection_only(self) -> bool:
        """True when this pack recognises the platform and reads nothing from it.

        A legitimate state at P3, and the honest description of a vendor we know
        of but cannot yet audit: detection works, every canonical field is
        UNKNOWN, and the whole file becomes residue for the training queue.

        **Structure counts as parsing.** This tested only `patterns` until P18,
        by which point `juniper/junos` read access lists and four identity
        fields and still reported itself detection-only — a pack describing its
        own capability inaccurately, which is the same class of error as a
        document doing it. A pack that extracts an ACL has parsed something,
        whether or not it has produced a canonical security field.

        `reads_no_canonical_field` is the narrower question, and the one the
        evaluation harness cares about: a pack can read structure and identity
        and still have every compliance check abstain.
        """
        return bool(self.detect) and self.reads_no_canonical_field and not self.reads_structure

    @property
    def reads_no_canonical_field(self) -> bool:
        """True when no canonical security field can come from this pack.

        Every rule abstains with `no_match` on such a platform, and the P9
        harness reports recall 0 for it — correctly, and for a reason that is
        about coverage rather than about accuracy.
        """
        return not self.patterns

    @property
    def reads_structure(self) -> bool:
        """True when this pack extracts access lists or interfaces."""
        return self.acl_extraction is not None or self.interface_extraction is not None

    def validate_patterns(self) -> dict[str, list[str]]:
        """Run every pattern against its own examples. Empty dict means clean."""
        results = {p.id: p.self_check() for p in self.patterns}
        return {k: v for k, v in results.items() if v}
