"""The report view model - what a report says, decided separately from how it looks.

Two properties this module is built around, and both are structural rather than
conventions someone has to remember:

**It re-evaluates nothing.** A report is assembled from findings that were
persisted when the audit ran (decision D23). There is no import path from here to
`api.comply`, so a report cannot quietly become a fresh audit that happens to
agree with the recorded one.

**It states what it cannot say.** `disclosures` is computed by inspecting the
report's own content, not written as fixed prose. If every finding carries an
empty framework list, the report says so because that was measured - and the
sentence disappears on its own when the first sourced mapping arrives. A
disclosure that has to be maintained by hand is a disclosure that eventually
describes the previous release.

## Remediation is resolved here, not at evaluation time

`comply -> remediate` is a forbidden import edge: a verdict is decided before
anything is proposed to fix it. So `Finding.remediation` is `None` when the
engine emits it and `None` when it is stored, and resolution happens on this side
of the boundary (decision D26).

The cost is that a report can resolve against a library newer than the audit run.
That is why `ReportProvenance` records the snippet library version alongside the
engine and rulepack versions: the report states which library it used rather than
implying the audit knew.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from api.models.enums import Framework, Severity, SourceType, UnknownReason, Verdict
from api.models.finding import Finding
from api.models.rule import FrameworkRef
from api.models.source_limits import not_determinable
from api.remediate.library import SnippetLibrary
from api.remediate.resolver import RemediationResolution, ResolutionOutcome, resolve

SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

VERDICT_RANK: dict[Verdict, int] = {
    Verdict.FAIL: 0,
    Verdict.UNKNOWN: 1,
    Verdict.PASS: 2,
    Verdict.NOT_APPLICABLE: 3,
}

ORDERING_BASIS = (
    "Findings are ordered by verdict, then severity, then rule identifier. "
    "This is not an exposure ranking: exposure-aware prioritisation needs access "
    "lists and interface data that this build does not extract, so every "
    "finding's exposure score and priority rank are unset."
)
"""Stated in the report itself, not only here.

`docs/ui_reference.html` shows a device table headed "ranked by exposure, not
severity alone". That is the P12 target state. Printing a severity-ordered list
under that heading would be the report claiming an analysis it did not perform,
so the report describes the ordering it actually used.
"""


@dataclass(frozen=True)
class ReportedFinding:
    """One finding, paired with the remediation lookup for it."""

    finding: Finding
    remediation: RemediationResolution

    @property
    def rule_id(self) -> str:
        return self.finding.rule_id

    @property
    def sort_key(self) -> tuple[int, int, str]:
        return (
            VERDICT_RANK[self.finding.status],
            SEVERITY_RANK[self.finding.base_severity],
            self.finding.rule_id,
        )


@dataclass(frozen=True)
class ReportedIdentity:
    """What the report can say about which device this is.

    Until P18 the report named the subject only by `config_file_id`, a content
    hash. Every one of these fields was already extracted, stored in `device`
    and reaching the canonical model — they simply stopped at the report
    boundary, so an operator handed a report for `8995304d…` could not tell
    which router it was (ADR 0041).

    `serial_note` carries the reason the serial is absent rather than leaving it
    blank. Blank reads as "we failed to find it"; the truth is that a
    configuration export does not contain one, and those call for different
    responses from whoever reads the report.
    """

    hostname: str | None = None
    model: str | None = None
    os_version: str | None = None
    serial: str | None = None
    serial_note: str | None = None

    @property
    def is_empty(self) -> bool:
        return not any((self.hostname, self.model, self.os_version, self.serial))


@dataclass(frozen=True)
class ReportProvenance:
    """Exactly which code and data produced this document.

    A report read six months from now must be able to say what it rested on. The
    snippet library version is here for the reason given in the module docstring:
    remediation is resolved at render time, so the library is part of the
    report's provenance and not part of the audit's.
    """

    engine_version: str
    rulepack_id: str | None
    rulepack_version: str | None
    pack_versions: dict[str, str]
    snippet_library_version: str
    snippet_count: int
    generated_at: datetime


@dataclass(frozen=True)
class Report:
    """One audit run, rendered-ready.

    `config_file_id` is named for what it is. It is the SHA-256 of the uploaded
    configuration's content, so it changes whenever the file is edited and it is
    **not a stable device identity** (DEF-3). Calling the field `device_id` here
    would invite a reader - and a later template author - to treat it as one.
    """

    report_id: str
    audit_id: str

    config_file_id: str
    config_file_path: str | None
    vendor: str | None
    os_family: str | None

    evaluated_at: str | None
    findings: tuple[ReportedFinding, ...]
    verdict_counts: dict[str, int]
    provenance: ReportProvenance
    disclosures: tuple[str, ...]
    identity: ReportedIdentity = field(default_factory=ReportedIdentity)
    framework_selection: tuple[str, ...] = ()
    """Benchmarks this run was scoped to. Empty means no filter was applied —
    NIRIKSHAK's own checks — and is **not** the same as a benchmark that matched
    nothing, which the API refuses rather than persisting."""
    ordering_basis: str = ORDERING_BASIS

    @property
    def failures(self) -> tuple[ReportedFinding, ...]:
        return tuple(f for f in self.findings if f.finding.status is Verdict.FAIL)

    @property
    def abstentions(self) -> tuple[ReportedFinding, ...]:
        return tuple(f for f in self.findings if f.finding.status is Verdict.UNKNOWN)

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def platform_label(self) -> str:
        if self.vendor and self.os_family:
            return f"{self.vendor} / {self.os_family}"
        return "not identified"

    @property
    def resolved_remediation_count(self) -> int:
        return sum(1 for f in self.findings if f.remediation.outcome is ResolutionOutcome.RESOLVED)


def _identity(row: Mapping[str, Any]) -> ReportedIdentity:
    """The device row, with the serial's absence explained rather than blank."""
    serial = row.get("serial")
    return ReportedIdentity(
        hostname=row.get("hostname"),
        model=row.get("model"),
        os_version=row.get("os_version"),
        serial=serial,
        serial_note=None if serial else not_determinable("serial", SourceType.CLI),
    )


def _disclosures(
    reported: tuple[ReportedFinding, ...],
    library: SnippetLibrary,
    framework_absence: Mapping[str, str] | None = None,
) -> tuple[str, ...]:
    """What this report cannot claim, measured from what it contains.

    Every sentence below is produced by a condition over the actual findings. As
    the underlying gaps close - a sourced framework mapping, a vetted snippet, a
    documented platform default - the corresponding sentence stops being emitted
    without anyone having to remember to delete it.
    """
    out: list[str] = []

    if reported and all(not f.finding.frameworks for f in reported):
        out.append(
            "No framework control mappings are present. Every rule in this report is "
            "NIRIKSHAK's own check, mapped to no CIS, NIST SP 800-53, DISA STIG or "
            "ISO/IEC 27001 identifier. This report makes no claim of coverage against "
            "any of those frameworks."
        )

    mapped = {ref.framework for f in reported for ref in f.finding.frameworks}
    if mapped:
        named = ", ".join(sorted(f.value.upper() for f in mapped))
        out.append(
            f"Control identifiers in this report ({named}) were validated against the "
            "published catalog named in each citation, at the edition given. The "
            "mapping from a NIRIKSHAK check to a control is asserted by this project, "
            "not taken from a published crosswalk: a catalog publishes controls, not "
            "mappings. This report is evidence about a configuration, and is not a "
            "certification of compliance with any framework."
        )

    unmapped = sorted(framework for framework in Framework if framework not in mapped)
    if unmapped and mapped:
        # Two absences that must not read alike (ADR 0052): a benchmark nobody has
        # read, and one that was read and does not describe this device. The
        # route supplies which is which; without it, the sentence claims neither.
        reasons = framework_absence or {}
        named = "; ".join(
            f"{framework.value.upper()}: {reasons[framework.value]}"
            if framework.value in reasons
            else framework.value.upper()
            for framework in unmapped
        )
        out.append(
            f"No control mapping is present for {named}. The absence of a finding "
            "under a framework is not a passing result against it."
        )

    if library.is_empty:
        out.append(
            "The vetted remediation library is empty, so no finding in this report "
            "carries a command. Commands are only ever read from that library and are "
            "never generated, so an empty library yields no remediation rather than a "
            "suggested one."
        )

    if any(f.finding.exposure_score is None for f in reported):
        out.append(
            "No exposure scoring was performed. Findings are ordered by verdict and severity alone."
        )

    capability_unknown = sum(
        1 for f in reported if f.finding.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
    )
    if capability_unknown:
        out.append(
            f"{capability_unknown} check(s) abstained because it is not documented "
            "whether this platform supports the control or what it does by default. "
            "That is a gap in sourced vendor documentation, not a fault on the device, "
            "and it is not something administrator training can resolve."
        )

    out.append(
        "The subject of this report is identified by the content hash of the uploaded "
        "configuration file. It identifies that file, not the device it came from: "
        "editing the configuration produces a different identifier."
    )

    return tuple(out)


def build_report(
    *,
    report_id: str,
    audit_id: str,
    run: dict[str, Any],
    findings: tuple[Finding, ...],
    library: SnippetLibrary,
    vendor: str | None,
    os_family: str | None,
    config_file_path: str | None,
    generated_at: datetime | None = None,
    rule_frameworks: Mapping[str, tuple[FrameworkRef, ...]] | None = None,
    identity: Mapping[str, Any] | None = None,
    framework_absence: Mapping[str, str] | None = None,
) -> Report:
    """Assemble one report from a persisted run.

    `run` is the row `api.db.findings.read_run` returns. It arrives as a plain
    mapping rather than as a database handle on purpose: this package performs no
    I/O, which is what lets the whole of it be tested without a database and keeps
    it off every path that could reach a live configuration.

    `rule_frameworks` re-attaches each rule's control mappings, keyed by rule id.
    They are **not** stored per finding — they are rulepack data, and the run
    records which rulepack version produced it — so they are resolved at render
    time exactly as remediation snippets are, and become part of the *report's*
    provenance rather than the audit's.

    The caller supplies them because `report -> comply` is a forbidden import
    edge: a report renders persisted findings and must not be able to reach the
    layer that evaluates them. **A caller that supplies nothing gets a report
    with no control identifiers**, which is why the route only supplies them when
    the run's rulepack version matches the active one — showing today's mappings
    beside a verdict produced under a different rulepack would be a citation to
    a document that did not decide it.
    """
    mappings = dict(rule_frameworks or {})
    reported = tuple(
        ReportedFinding(
            finding=(
                finding.model_copy(update={"frameworks": mappings[finding.rule_id]})
                if finding.rule_id in mappings and not finding.frameworks
                else finding
            ),
            remediation=resolve(
                library,
                rule_id=finding.rule_id,
                vendor=vendor,
                os_family=os_family,
                actionable=finding.is_actionable,
            ),
        )
        for finding in findings
    )
    ordered = tuple(sorted(reported, key=lambda f: f.sort_key))

    return Report(
        report_id=report_id,
        audit_id=audit_id,
        config_file_id=run.get("device_id", ""),
        config_file_path=config_file_path,
        vendor=vendor,
        os_family=os_family,
        identity=_identity(identity or {}),
        evaluated_at=run.get("evaluated_at"),
        findings=ordered,
        verdict_counts=dict(run.get("verdicts", {})),
        provenance=ReportProvenance(
            engine_version=run.get("engine_version", "unknown"),
            rulepack_id=run.get("rulepack_id"),
            rulepack_version=run.get("rulepack_version") or None,
            pack_versions=dict(run.get("pack_versions", {})),
            snippet_library_version=library.version,
            snippet_count=len(library.snippets),
            generated_at=generated_at or datetime.now(UTC),
        ),
        framework_selection=tuple(run.get("framework_selection") or ()),
        disclosures=_disclosures(ordered, library, framework_absence),
    )
