"""The report view model and its rendering (P8).

A report is the only artefact most people will ever see, which makes it the place
where the project's refusals either survive or quietly evaporate. Three of them
are tested here directly:

    frameworks: []           must not become a column of blanks that reads as
                             "no findings" rather than "no mappings exist"
    priority_rank is None    must not become a severity list under an
                             exposure-ranked heading
    the empty snippet library must produce one specific sentence, every time

The rest is ordering, escaping, and the naming of the subject - which is a
configuration file's content hash and not a device (DEF-3).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from api.models.enums import (
    ConfidenceMethod,
    FieldState,
    Framework,
    MappingProvenance,
    Severity,
    SourceType,
    UnknownReason,
    Verdict,
)
from api.models.evidence import Evidence
from api.models.finding import Finding, FindingProvenance, ObservedValue
from api.models.rule import FrameworkRef
from api.remediate.library import SnippetLibrary
from api.remediate.resolver import NO_REMEDIATION_STATEMENT, ResolutionOutcome
from api.report.model import ORDERING_BASIS, build_report
from api.report.render import render_html
from tests.fixtures.snippets import FIXTURE_OS_FAMILY, FIXTURE_VENDOR, snippet

EMPTY_LIBRARY = SnippetLibrary(snippets=(), version="empty")

PROVENANCE = FindingProvenance(engine_version="0.1.0", rulepack_version="1.0.0")

RUN: dict[str, Any] = {
    "device_id": "a" * 64,
    "engine_version": "0.1.0",
    "rulepack_id": "canonical",
    "rulepack_version": "1.0.0",
    "pack_versions": {"cisco_ios": "1.1.0"},
    "verdicts": {"pass": 1, "fail": 1, "unknown": 1, "not_applicable": 0},
    "evaluated_at": "2026-08-27T10:00:00+00:00",
}


def evidence(raw_line: str = " transport input telnet ssh", line: int = 42) -> Evidence:
    return Evidence(
        file_id="f1",
        file_path="uploads/ab/cd.cfg",
        line_start=line,
        line_end=line,
        raw_line=raw_line,
        source_type=SourceType.CLI,
    )


def finding(
    rule_id: str,
    status: Verdict = Verdict.FAIL,
    severity: Severity = Severity.HIGH,
    *,
    with_evidence: bool = True,
    unknown_reason: UnknownReason | None = None,
    frameworks: tuple[FrameworkRef, ...] = (),
) -> Finding:
    return Finding(
        finding_id=f"finding-{rule_id}",
        audit_id="audit-1",
        device_id="a" * 64,
        rule_id=rule_id,
        status=status,
        base_severity=severity,
        observed=ObservedValue(
            value=True if status is Verdict.FAIL else None,
            state=FieldState.PRESENT if status is Verdict.FAIL else FieldState.UNKNOWN,
            confidence=1.0 if status is Verdict.FAIL else 0.0,
            confidence_method=ConfidenceMethod.DETERMINISTIC,
        ),
        expected=f"expectation for {rule_id}",
        evidence=(evidence(),) if with_evidence and status is not Verdict.UNKNOWN else (),
        unknown_reason=unknown_reason if status is Verdict.UNKNOWN else None,
        frameworks=frameworks,
        provenance=PROVENANCE,
    )


def build(*findings: Finding, library: SnippetLibrary = EMPTY_LIBRARY, **kwargs):
    defaults: dict[str, Any] = {
        "report_id": "report-1",
        "audit_id": "audit-1",
        "run": RUN,
        "library": library,
        "vendor": "cisco",
        "os_family": "ios",
        "config_file_path": "uploads/ab/cd.cfg",
        "generated_at": datetime(2026, 8, 27, 12, 0, tzinfo=UTC),
    }
    defaults.update(kwargs)
    return build_report(findings=findings, **defaults)


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------


def test_failures_come_before_abstentions_and_passes() -> None:
    """What is wrong is what the reader opened the document for."""
    report = build(
        finding("C", Verdict.PASS),
        finding("B", Verdict.UNKNOWN, unknown_reason=UnknownReason.NO_MATCH),
        finding("A", Verdict.FAIL),
    )
    assert [f.rule_id for f in report.findings] == ["A", "B", "C"]


def test_severity_orders_within_a_verdict() -> None:
    report = build(
        finding("low", Verdict.FAIL, Severity.LOW),
        finding("critical", Verdict.FAIL, Severity.CRITICAL),
        finding("medium", Verdict.FAIL, Severity.MEDIUM),
    )
    assert [f.rule_id for f in report.findings] == ["critical", "medium", "low"]


def test_the_rule_id_makes_the_order_total() -> None:
    """Two runs over the same findings must produce the same document."""
    a = finding("NRK-AAA-001", Verdict.FAIL, Severity.HIGH)
    b = finding("NRK-BBB-001", Verdict.FAIL, Severity.HIGH)

    assert [f.rule_id for f in build(b, a).findings] == ["NRK-AAA-001", "NRK-BBB-001"]


def test_the_report_states_the_ordering_it_actually_used() -> None:
    """P12 — the UI reference draws an exposure ranking. This build has none.

    Printing a severity-ordered list under an exposure-ranked heading would be
    the report claiming an analysis it did not perform.
    """
    report = build(finding("A"))

    assert report.ordering_basis == ORDERING_BASIS
    assert "not an exposure ranking" in report.ordering_basis

    # Matched on a clause rather than the whole sentence: autoescaping turns the
    # apostrophe in "finding's" into an entity, which is the escaping working.
    assert "This is not an exposure ranking" in render_html(report)


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


def test_every_failure_carries_the_mandated_sentence() -> None:
    report = build(finding("A"), finding("B"))

    for item in report.failures:
        assert item.remediation.outcome is ResolutionOutcome.NO_SNIPPET
        assert item.remediation.statement == NO_REMEDIATION_STATEMENT


def test_the_sentence_reaches_the_rendered_document() -> None:
    """The claim is about what the operator reads, not about an object graph."""
    html = render_html(build(finding("A")))
    assert NO_REMEDIATION_STATEMENT in html


def test_a_passing_finding_is_not_told_there_is_no_fix() -> None:
    """Distinct messages, because they mean opposite things."""
    report = build(finding("A", Verdict.PASS))
    item = report.findings[0]

    assert item.remediation.outcome is ResolutionOutcome.NOT_ACTIONABLE
    assert item.remediation.statement != NO_REMEDIATION_STATEMENT


def test_an_unknown_finding_receives_no_remediation() -> None:
    """Rule 3 — we do not know there is anything to fix."""
    report = build(finding("A", Verdict.UNKNOWN, unknown_reason=UnknownReason.NO_MATCH))

    assert report.findings[0].remediation.outcome is ResolutionOutcome.NOT_ACTIONABLE
    assert report.findings[0].remediation.snippet is None


def test_a_resolved_snippet_renders_its_commands() -> None:
    """The remediation block works; there is simply nothing for it to show.

    Exercised with a constructed snippet so the rendering path is not untested
    code waiting for the day the library is populated.
    """
    library = SnippetLibrary(
        snippets=(
            snippet(
                "fixture-alpha",
                rule_id="NRK-FIXTURE-001",
                commands=("fixture-command-alpha", "fixture-command-beta"),
                rollback=("fixture-undo",),
            ),
        ),
        version="test",
    )
    report = build(
        finding("NRK-FIXTURE-001"),
        library=library,
        vendor=FIXTURE_VENDOR,
        os_family=FIXTURE_OS_FAMILY,
    )
    html = render_html(report)

    assert report.resolved_remediation_count == 1
    assert "fixture-command-alpha" in html
    assert "fixture-command-beta" in html
    assert "fixture-undo" in html
    assert NO_REMEDIATION_STATEMENT not in html
    assert "NIRIKSHAK does not execute these commands" in html


# ---------------------------------------------------------------------------
# Disclosures — measured, not written
# ---------------------------------------------------------------------------


def test_the_report_says_it_claims_no_framework_coverage() -> None:
    """D16 — every rule ships `frameworks: []`."""
    report = build(finding("A"))
    joined = " ".join(report.disclosures)

    assert "no claim of coverage" in joined.lower()
    for framework in ("CIS", "NIST", "DISA STIG", "ISO/IEC 27001"):
        assert framework in joined


def test_the_framework_disclosure_disappears_when_a_mapping_exists() -> None:
    """The sentence is a measurement, not maintained prose.

    When the first sourced mapping arrives it stops being emitted, without
    anyone having to remember to delete it.
    """
    mapped = finding(
        "A",
        frameworks=(
            FrameworkRef(
                framework=Framework.CIS,
                control_id="sourced-later",
                citation="a real document",
                mapping_provenance=MappingProvenance.OFFICIAL,
            ),
        ),
    )
    joined = " ".join(build(mapped).disclosures)
    assert "no claim of coverage" not in joined.lower()


def test_the_report_says_the_remediation_library_is_empty() -> None:
    joined = " ".join(build(finding("A")).disclosures)
    assert "vetted remediation library is empty" in joined


def test_the_empty_library_disclosure_disappears_when_one_is_present() -> None:
    library = SnippetLibrary(snippets=(snippet("alpha"),), version="test")
    joined = " ".join(build(finding("A"), library=library).disclosures)
    assert "vetted remediation library is empty" not in joined


def test_the_report_explains_a_capability_unknown_abstention() -> None:
    """It is a documentation gap, and not one training can close.

    An operator who reads UNKNOWN and assumes their device is misconfigured has
    been misled by the report rather than by the device.
    """
    report = build(finding("A", Verdict.UNKNOWN, unknown_reason=UnknownReason.CAPABILITY_UNKNOWN))
    joined = " ".join(report.disclosures)

    assert "not documented" in joined
    assert "not a fault on the device" in joined
    assert "administrator training" in joined


def test_the_report_always_explains_what_its_subject_is() -> None:
    """DEF-3 — the identifier is a file's content hash, not a device identity."""
    joined = " ".join(build(finding("A")).disclosures)
    assert "content hash" in joined
    assert "not the device it came from" in joined


# ---------------------------------------------------------------------------
# The subject is a file, not a device
# ---------------------------------------------------------------------------


def test_the_subject_field_is_named_for_what_it_is() -> None:
    report = build(finding("A"))

    assert report.config_file_id == RUN["device_id"]
    assert not hasattr(report, "device_id")


def test_the_rendered_document_never_calls_it_a_device_identity() -> None:
    html = render_html(build(finding("A")))

    assert "device_id" not in html
    assert "editing the configuration produces a different" in html.lower()


def test_an_unidentified_platform_is_reported_as_such() -> None:
    report = build(finding("A"), vendor=None, os_family=None)

    assert report.platform_label == "not identified"
    assert "not identified" in render_html(report)


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_the_report_records_the_library_it_resolved_against() -> None:
    """D26 — remediation is resolved at render time, not at evaluation time.

    So the library is part of the report's provenance rather than the audit's,
    and a reader can tell which one produced the commands they are looking at.
    """
    report = build(finding("A"))

    assert report.provenance.snippet_library_version == "empty"
    assert report.provenance.snippet_count == 0
    assert "empty" in render_html(report)


def test_the_report_records_the_engine_and_rulepack_that_ran() -> None:
    report = build(finding("A"))

    assert report.provenance.engine_version == "0.1.0"
    assert report.provenance.rulepack_id == "canonical"
    assert report.provenance.rulepack_version == "1.0.0"
    assert report.provenance.pack_versions == {"cisco_ios": "1.1.0"}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def test_evidence_is_rendered_with_its_line_number() -> None:
    """Rule 2 — the citation is the finding. Losing the line loses the claim."""
    html = render_html(build(finding("A")))

    assert "transport input telnet ssh" in html
    assert ">42<" in html
    assert "uploads/ab/cd.cfg" in html


def test_configuration_text_is_escaped_not_executed() -> None:
    """A banner containing markup is still a banner.

    Rule 2 requires the raw line be shown exactly; escaping is what lets that be
    true and safe at once.
    """
    hostile = finding("A")
    object.__setattr__(
        hostile, "evidence", (evidence(raw_line=" banner motd <script>alert(1)</script>"),)
    )
    html = render_html(build(hostile))

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_an_abstention_renders_its_reason() -> None:
    """Rule 3 — silent uncertainty is indistinguishable from an oversight."""
    html = render_html(
        build(finding("A", Verdict.UNKNOWN, unknown_reason=UnknownReason.LOW_CONFIDENCE))
    )

    assert "low confidence" in html
    assert "abstained" in html.lower()


def test_a_deterministic_confidence_is_not_presented_as_a_probability() -> None:
    """R7 — a UI that renders it as one would be misreporting it."""
    html = render_html(build(finding("A")))
    assert "Not a probability" in html


def test_a_report_with_no_findings_still_renders() -> None:
    report = build()
    html = render_html(report)

    assert report.total == 0
    assert "recorded no findings" in html


def test_the_rendered_report_is_self_contained() -> None:
    """Rule 6 — no CDN, no linked stylesheet, no web font."""
    html = render_html(build(finding("A")))

    assert "<style>" in html
    assert "http://" not in html
    assert "https://" not in html
    assert "<script" not in html


def test_rendering_is_deterministic() -> None:
    """Two renders of one report must be byte-identical, or nothing is diffable."""
    report = build(finding("A"), finding("B", Verdict.PASS))
    assert render_html(report) == render_html(report)


def test_a_template_field_that_does_not_exist_raises() -> None:
    """StrictUndefined — a blank remediation block looks like a control with no fix."""
    from jinja2 import StrictUndefined, UndefinedError

    from api.report.render import environment

    assert environment().undefined is StrictUndefined
    with pytest.raises(UndefinedError):
        environment().from_string("{{ report.not_a_field }}").render(report=build(finding("A")))
