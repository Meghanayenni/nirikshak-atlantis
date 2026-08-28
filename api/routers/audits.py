"""Compliance audits over HTTP — the first API the eventual UI will consume.

Mounted under `/compliance/` rather than `/audits`, deliberately. P2 already owns
`/audit/*` for the hash-chained audit LOG, which is read-only by design, and
`/audit/head` beside `/audits` would be two unrelated resources one character
apart. A test caught the collision; the names were the thing worth fixing.

Four endpoints, all authenticated (decision D25), all scoped to what the caller
owns unless they are an admin. Deliberately narrow: these are the shapes P8's
reporting layer needs, and P8 is the first real client. Anything speculative
waits for the phase that needs it, because an endpoint nobody exercises is an
endpoint designed against a guess.

The pipeline runs in-process — parse, normalise, evaluate, analyse — and the
result is **persisted** (decision D23), so a later request describes the audit
that ran rather than a fresh one that happens to agree with it.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query

from api.analyse.service import analyse_device
from api.comply.engine import evaluate_device, new_audit_id
from api.comply.rulepacks import load_active_rulepack
from api.comply.service import summarise
from api.config import settings
from api.db import findings as finding_store
from api.ingest import blobs
from api.ingest.packs import find_pack
from api.models.finding import Finding
from api.normalise.service import build_csm
from api.parse.service import parse_configuration
from api.remediate.library import load_active_library
from api.remediate.resolver import RemediationResolution, resolve
from api.routers.deps import Conn, CurrentUser, owner_filter, require_access
from api.train import service as train_service

router = APIRouter(prefix="/compliance/audits", tags=["compliance"])


def _platform(conn: sqlite3.Connection, file_id: str) -> tuple[str | None, str | None]:
    """The detected vendor and OS family for one ingested file, or `(None, None)`.

    A snippet key is `(vendor, os_family, rule_id)`. Without the first two there
    is nothing to look up, and the resolver says so rather than guessing which
    platform a command should be written for.
    """
    row = conn.execute(
        "SELECT detected_vendor, detected_os_family FROM config_file WHERE file_id = ?",
        (file_id,),
    ).fetchone()
    if row is None:
        return None, None
    return row["detected_vendor"], row["detected_os_family"]


def _finding_json(finding: Finding, resolution: RemediationResolution) -> dict[str, Any]:
    """One finding, as the UI will consume it.

    Evidence is included in full — an operator reading a FAIL needs the line that
    caused it, and a report that says "telnet is enabled" without showing where
    is not evidence of anything (Rule 2).

    Remediation arrives already resolved rather than being looked up here. It is
    resolved **downstream of the engine** — `comply` may not import `remediate`,
    because a verdict is decided before anything is proposed to fix it — so
    `finding.remediation` is `None` on every finding the engine emits and on
    every finding read back from storage (decision D26).
    """
    return {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "status": finding.status.value,
        "severity": finding.base_severity.value,
        "expected": finding.expected,
        "observed": {
            "value": finding.observed.value,
            "state": finding.observed.state.value,
            "confidence": finding.observed.confidence,
            "confidence_method": finding.observed.confidence_method.value,
            # R7 — a deterministic confidence is not a probability, and a UI that
            # renders it as one would be misreporting it.
            "is_probability": finding.observed.confidence_is_probability,
        },
        "unknown_reason": finding.unknown_reason.value if finding.unknown_reason else None,
        "absence_reason": finding.absence_reason,
        "evidence": [
            {
                "file_id": e.file_id,
                "file_path": e.file_path,
                "line_start": e.line_start,
                "line_end": e.line_end,
                "raw_line": e.raw_line,
                "cite": e.cite(),
            }
            for e in finding.evidence
        ],
        # Empty until a benchmark edition is sourced (decision D16). Present in
        # the payload so the UI can render the column without a later reshape.
        "frameworks": [
            {"framework": f.framework.value, "control_id": f.control_id} for f in finding.frameworks
        ],
        # Rule 4 — a command here was read from `snippets/`, or there is no
        # command. `outcome` says which case this is and `statement` carries the
        # sentence an operator should read; `commands` is present only when a
        # vetted snippet was found, and is never a suggestion.
        "remediation": {
            "outcome": resolution.outcome.value,
            "statement": resolution.statement,
            "snippet_id": resolution.snippet.snippet_id if resolution.snippet else None,
            "commands": list(resolution.snippet.commands) if resolution.snippet else [],
            "rollback": list(resolution.snippet.rollback) if resolution.snippet else [],
            "vetted_by": resolution.snippet.vetted_by if resolution.snippet else None,
            "reference": resolution.snippet.reference if resolution.snippet else None,
        },
    }


@router.post("", status_code=201)
def run_audit_endpoint(conn: Conn, user: CurrentUser, file_id: str) -> dict[str, Any]:
    """Audit one ingested configuration, and persist the result.

    The caller must own the upload. Ownership is checked before anything is read
    from disk, so an unauthorised request never touches another user's file.
    """
    row = conn.execute(
        """
        SELECT cf.file_id, cf.blob_path, cf.detected_vendor, cf.detected_os_family,
               (SELECT owner_id FROM ingestion WHERE file_id = cf.file_id
                 ORDER BY received_at LIMIT 1) AS owner_id
        FROM config_file cf WHERE cf.file_id = ?
        """,
        (file_id,),
    ).fetchone()

    require_access(user, exists=row is not None, owner_id=row["owner_id"] if row else None)
    assert row is not None  # narrowed by require_access

    if not row["detected_vendor"]:
        raise HTTPException(
            status_code=409,
            detail=(
                "the platform for this file was not identified, so no vendor pack "
                "applies and nothing can be audited. This is UNKNOWN, not a failure."
            ),
        )

    pack = find_pack(row["detected_vendor"], row["detected_os_family"])
    if pack is None:
        raise HTTPException(status_code=409, detail="no active pack for this platform")

    raw = blobs.read(settings.blob_root, file_id)
    text = raw.decode("utf-8", errors="replace")
    parsed = parse_configuration(text, pack, file_id=file_id, file_path=row["blob_path"])
    csm = build_csm(parsed, pack, device_id=file_id)

    # P11 (D49) — residue becomes the durable training queue. Recorded on every
    # audit, and the file's previous entries are replaced, so re-auditing after
    # activating a pack shrinks the queue instead of duplicating it. A line the
    # new pack now reads simply stops being produced.
    residue_recorded = train_service.record_residue(
        conn,
        csm.residue,
        file_id=file_id,
        vendor=row["detected_vendor"],
        os_family=row["detected_os_family"],
    )
    conn.commit()

    audit_id = new_audit_id()
    evaluated_at = datetime.now(UTC)
    results = evaluate_device(
        csm, load_active_rulepack(), audit_id=audit_id, evaluated_at=evaluated_at
    )
    acl_result = analyse_device(csm, audit_id=audit_id, analysed_at=evaluated_at)

    finding_store.save_run(
        conn,
        audit_id=audit_id,
        device_id=file_id,
        owner_id=user.user_id,
        findings=results,
        rulepack_id=load_active_rulepack().rulepack_id,
        summary=summarise(results),
    )

    return {
        "audit_id": audit_id,
        "device_id": file_id,
        "verdicts": summarise(results),
        "rules_evaluated": len(results),
        # The size of the training queue this file contributes. Expected to fall
        # after an administrator confirms a mapping and the pack is activated.
        "residue_lines": residue_recorded,
        # A separate rail from findings, and reported as one (decision D22).
        "acl_analysis": {
            "analysed_nothing": acl_result.analysed_nothing,
            "summary": acl_result.summary(),
        },
    }


@router.get("")
def list_audits(
    conn: Conn,
    user: CurrentUser,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, Any]:
    """Recent runs. A user sees their own; an admin sees the fleet."""
    runs = finding_store.list_runs(conn, owner_id=owner_filter(user), limit=limit)
    return {"count": len(runs), "audits": runs}


@router.get("/{audit_id}")
def get_audit(conn: Conn, user: CurrentUser, audit_id: str) -> dict[str, Any]:
    exists, owner_id = finding_store.run_owner(conn, audit_id)
    require_access(user, exists=exists, owner_id=owner_id)

    run = finding_store.read_run(conn, audit_id)
    assert run is not None
    return run


@router.get("/{audit_id}/findings")
def get_findings(
    conn: Conn,
    user: CurrentUser,
    audit_id: str,
    status: Annotated[str | None, Query()] = None,
    severity: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Findings for one run, with their evidence.

    Filterable by verdict and severity because a report needs "every FAIL" and a
    dashboard needs "every critical", and both would otherwise page through
    everything.
    """
    exists, owner_id = finding_store.run_owner(conn, audit_id)
    require_access(user, exists=exists, owner_id=owner_id)

    results = finding_store.read_findings(conn, audit_id, status=status, severity=severity)

    # Remediation is resolved per response, against the library as it is now,
    # because the audit that produced these findings was forbidden from doing it
    # (decision D26). The library version is reported alongside so a caller can
    # tell which library the answer came from.
    run = finding_store.read_run(conn, audit_id)
    vendor, os_family = _platform(conn, run["device_id"]) if run else (None, None)
    library = load_active_library()

    return {
        "audit_id": audit_id,
        "count": len(results),
        "snippet_library_version": library.version,
        "findings": [
            _finding_json(
                f,
                resolve(
                    library,
                    rule_id=f.rule_id,
                    vendor=vendor,
                    os_family=os_family,
                    actionable=f.is_actionable,
                ),
            )
            for f in results
        ],
    }
