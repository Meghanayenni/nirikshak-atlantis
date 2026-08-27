"""Evidence-linked reports over HTTP (P8).

Two representations of one resource, and the difference between them is entirely
environmental:

    GET /compliance/audits/{id}/report.html    always works
    GET /compliance/audits/{id}/report.pdf     needs the WeasyPrint/GTK stack

**The PDF path never degrades into the HTML one.** When the native runtime is
absent this returns 503 naming the missing libraries and pointing at ADR 0006.
Returning the HTML document under a `.pdf` name would tell a caller their request
succeeded when it did not, and would put a file on disk whose extension lies
about its contents.

This module does the I/O that `api/report/` deliberately does not: it reads the
run, its findings and the file's detected platform, hands them to the view model
as plain data, and appends the chain record afterwards. That is what keeps the
reporting package free of any path to a database or a configuration file, and it
is the same division `api/routers/ingest.py` uses for the ingestion service.
"""

from __future__ import annotations

import sqlite3
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import HTMLResponse

from api.audit.chain import AuditChain
from api.config import settings
from api.db import findings as finding_store
from api.db.connection import connect
from api.models.audit import Subject
from api.models.auth import User
from api.models.enums import AuditAction
from api.remediate.library import load_active_library
from api.remediate.resolver import ResolutionOutcome, order_snippets
from api.report.errors import PdfBackendUnavailableError
from api.report.model import Report, ReportedFinding, build_report
from api.report.pdf import availability, render_pdf
from api.report.render import render_html
from api.routers.deps import Conn, CurrentUser, require_access

router = APIRouter(prefix="/compliance/audits", tags=["reports"])


def _platform(conn: sqlite3.Connection, file_id: str) -> tuple[str | None, str | None, str | None]:
    """The detected vendor, OS family and stored path for one ingested file.

    All three may be `None`. A file whose platform was never identified still has
    an auditable run - every check abstains - and it still deserves a report that
    says so, rather than a 500 because a lookup came back empty.
    """
    row = conn.execute(
        "SELECT detected_vendor, detected_os_family, blob_path FROM config_file WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    if row is None:
        return None, None, None
    return row["detected_vendor"], row["detected_os_family"], row["blob_path"]


def _authorise(conn: sqlite3.Connection, user: User, audit_id: str) -> None:
    """Ownership, before anything else happens.

    A run the caller may not see answers 404 rather than 403 (decision D25) -
    403 would confirm the id exists and let someone walk the id space.

    Split out from `_assemble` so the PDF route can authorise *before* probing
    for the renderer. Probing first would make a non-owner's answer depend on
    whether GTK happened to be installed: 404 on a machine with it, 503 on a
    machine without. An access-control answer must not vary with the
    environment.
    """
    exists, owner_id = finding_store.run_owner(conn, audit_id)
    require_access(user, exists=exists, owner_id=owner_id)


def _assemble(conn: sqlite3.Connection, user: User, audit_id: str) -> Report:
    """Authorise, load, and build the view model. Shared by both representations."""
    _authorise(conn, user, audit_id)

    run = finding_store.read_run(conn, audit_id)
    if run is None:  # pragma: no cover - run_owner already established existence
        raise HTTPException(status_code=404, detail="not found")

    findings = tuple(finding_store.read_findings(conn, audit_id))
    vendor, os_family, blob_path = _platform(conn, run["device_id"])

    return build_report(
        report_id=uuid.uuid4().hex,
        audit_id=audit_id,
        run=run,
        findings=findings,
        library=load_active_library(),
        vendor=vendor,
        os_family=os_family,
        config_file_path=blob_path,
    )


def _record(report: Report, *, fmt: str) -> None:
    """Append the REPORT_GENERATED entry.

    **Identifiers, counts and versions only.** The chain records that a report was
    produced, for which run, in which format, and what it resolved against. It
    records nothing a finding said and no line from any configuration: that
    content lives in the operational store, and keeping the two apart is what
    makes "no configuration content in the audit database" checkable by opening
    the file (decision D4).

    The subject field is named `config_file_id` rather than `device_id` because
    that is what it is - the content hash of an uploaded file, which changes when
    the file is edited and is not a stable device identity (DEF-3).
    """
    conn = connect(settings.audit_db_path)
    try:
        AuditChain(conn).append_system(
            AuditAction.REPORT_GENERATED,
            Subject(kind="report", id=report.report_id),
            payload={
                "audit_id": report.audit_id,
                "config_file_id": report.config_file_id,
                "format": fmt,
                "rules_reported": report.total,
                "verdicts": dict(report.verdict_counts),
                "engine_version": report.provenance.engine_version,
                "rulepack_id": report.provenance.rulepack_id or "",
                "rulepack_version": report.provenance.rulepack_version or "",
                "snippet_library_version": report.provenance.snippet_library_version,
                "snippet_count": report.provenance.snippet_count,
                "remediation_resolved": report.resolved_remediation_count,
            },
        )
    finally:
        conn.close()


@router.get("/{audit_id}/report.html", response_class=HTMLResponse)
def html_report(conn: Conn, user: CurrentUser, audit_id: str) -> HTMLResponse:
    """One audit run as a self-contained HTML document.

    No external stylesheet, script or font: the file can be saved, mailed and
    opened on a machine with no network, which is the same property Rule 6 asks
    of everything else in the system.

    Rendered first, recorded second - the ordering the ingestion and compliance
    services use, for the same reason: the log should never attest to a document
    that then failed to produce.
    """
    report = _assemble(conn, user, audit_id)
    html = render_html(report)
    _record(report, fmt="html")
    return HTMLResponse(content=html)


@router.get(
    "/{audit_id}/report.pdf",
    response_class=Response,
    responses={503: {"description": "the WeasyPrint/GTK runtime is not available here"}},
)
def pdf_report(conn: Conn, user: CurrentUser, audit_id: str) -> Response:
    """The same report as PDF, or 503 explaining exactly what is missing.

    Authorise, probe, then render. Authorisation is first so a non-owner gets the
    same 404 whether or not this machine can produce a PDF; the probe is second
    so an owner who cannot receive one is told immediately, rather than after the
    server has read a run, resolved remediation for every finding and rendered a
    document it is about to throw away.
    """
    _authorise(conn, user, audit_id)

    state = availability()
    if not state.available:
        raise HTTPException(
            status_code=503,
            detail=str(
                PdfBackendUnavailableError(
                    weasyprint_installed=state.weasyprint_installed,
                    missing_libraries=state.missing_libraries,
                )
            ),
        )

    report = _assemble(conn, user, audit_id)
    html = render_html(report)

    try:
        pdf = render_pdf(html)
    except PdfBackendUnavailableError as exc:  # pragma: no cover - probe passed, render failed
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    _record(report, fmt="pdf")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="nirikshak-{audit_id[:12]}.pdf"',
        },
    )


def _step(item: ReportedFinding, *, position: int | None) -> dict[str, Any]:
    """One line of a remediation plan.

    `apply_order` is `None` when nothing resolved. A numbered step with no
    command would imply there is something to do at that point in the sequence.
    """
    snippet = item.remediation.snippet
    return {
        "apply_order": position,
        "rule_id": item.finding.rule_id,
        "severity": item.finding.base_severity.value,
        "expected": item.finding.expected,
        "outcome": item.remediation.outcome.value,
        "statement": item.remediation.statement,
        "snippet": None
        if snippet is None
        else {
            "snippet_id": snippet.snippet_id,
            "vendor": snippet.vendor,
            "os_family": snippet.os_family,
            "commands": list(snippet.commands),
            "rollback": list(snippet.rollback),
            "preconditions": list(snippet.preconditions),
            "verification": list(snippet.verification),
            "lockout_risk": snippet.impact.lockout_risk.value,
            "service_affecting": snippet.impact.service_affecting,
            "requires_reload": snippet.impact.requires_reload,
            "depends_on": list(snippet.depends_on),
            "vetted_by": snippet.vetted_by,
            "reference": snippet.reference,
        },
    }


@router.get("/{audit_id}/remediation")
def remediation_plan(conn: Conn, user: CurrentUser, audit_id: str) -> dict[str, Any]:
    """What the operator would apply, in the order they would apply it.

    Every failing finding appears, whether or not anything resolved. A plan that
    silently omitted the rules with no snippet would understate the work by
    exactly the amount nobody has vetted yet, which is currently all of it.

    `statement` carries the operator-facing sentence and `outcome` the
    machine-readable reason, so a future interface can distinguish "no snippet
    exists" from "the platform was never identified" without the two ever
    disagreeing about whether a command is available.

    The steps that resolved are sequenced by `order_snippets` - dependencies
    first, then lowest lockout risk first, so a change that could strand the
    operator is applied only after its prerequisites. Steps that resolved to
    nothing follow, in severity order, since there is no action to sequence.
    """
    report = _assemble(conn, user, audit_id)

    resolved = [f for f in report.failures if f.remediation.snippet is not None]
    unresolved = [f for f in report.failures if f.remediation.snippet is None]

    by_snippet_id = {f.remediation.snippet.snippet_id: f for f in resolved if f.remediation.snippet}
    sequence = order_snippets(
        tuple(f.remediation.snippet for f in resolved if f.remediation.snippet)
    )
    ordered = [by_snippet_id[s.snippet_id] for s in sequence]

    steps = [_step(item, position=index + 1) for index, item in enumerate(ordered)] + [
        _step(item, position=None) for item in unresolved
    ]

    return {
        "audit_id": audit_id,
        "config_file_id": report.config_file_id,
        "platform": report.platform_label,
        "failing_findings": len(steps),
        "resolved": sum(1 for s in steps if s["outcome"] == ResolutionOutcome.RESOLVED.value),
        "snippet_library_version": report.provenance.snippet_library_version,
        "steps": steps,
        "note": (
            "NIRIKSHAK does not apply these commands. Remediation is read from the "
            "vetted snippet library and never generated; where no vetted snippet "
            "exists, no command is offered."
        ),
    }
