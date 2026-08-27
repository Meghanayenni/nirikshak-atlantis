"""Persisting audit runs and findings (decision D23).

Historical audits must be viewable without re-running the configuration. Two
reasons, and the second is the one that matters:

  * a report generated later would otherwise have to re-parse and re-evaluate,
    which is slow;
  * more importantly, it would describe a **fresh** audit that happens to agree
    with the original rather than the audit that actually ran. If a pack version
    changed in between, the report would silently describe something else.

**The boundary, restated at the point of use.** This writes to the OPERATIONAL
database. The audit chain, in its own database file, records that a run happened
and how many findings of each verdict — never what a finding said. Nothing here
touches the chain, and nothing here may be used to reconstruct one.

Evidence is stored as **pointers** — `(file_id, line_start, line_end)` — which
resolve through `config_line` and `line_cache` to the exact stored bytes. Storing
the raw line again would create a second copy that could drift from the first,
and evidence whose two copies disagree is worse than evidence with one.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from api.models.enums import (
    ConfidenceMethod,
    FieldState,
    Severity,
    SourceType,
    UnknownReason,
    Verdict,
)
from api.models.evidence import Evidence
from api.models.finding import Finding, FindingProvenance, ObservedValue


def save_run(
    conn: sqlite3.Connection,
    *,
    audit_id: str,
    device_id: str,
    owner_id: str | None,
    findings: tuple[Finding, ...],
    rulepack_id: str,
    summary: dict[str, int],
) -> None:
    """Persist one run and its findings, atomically.

    One transaction: a run whose findings failed to write would claim a verdict
    count it cannot show, which is worse than no record at all.
    """
    if not findings:
        raise ValueError("an audit run with no findings is not worth recording")

    provenance = findings[0].provenance

    with conn:
        conn.execute(
            """
            INSERT INTO audit_run (
                audit_id, device_id, owner_id, engine_version, rulepack_id,
                rulepack_version, pack_versions, rules_evaluated,
                count_pass, count_fail, count_unknown, count_na, evaluated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                audit_id,
                device_id,
                owner_id,
                provenance.engine_version,
                rulepack_id,
                provenance.rulepack_version or "",
                json.dumps(provenance.pack_versions, sort_keys=True),
                len(findings),
                summary.get("pass", 0),
                summary.get("fail", 0),
                summary.get("unknown", 0),
                summary.get("not_applicable", 0),
                provenance.evaluated_at.isoformat() if provenance.evaluated_at else "",
            ),
        )

        for finding in findings:
            conn.execute(
                """
                INSERT INTO finding (
                    finding_id, audit_id, device_id, rule_id, status, base_severity,
                    observed_value, observed_state, confidence, confidence_method,
                    expected, absence_reason, unknown_reason
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    finding.finding_id,
                    audit_id,
                    finding.device_id,
                    finding.rule_id,
                    finding.status.value,
                    finding.base_severity.value,
                    json.dumps(finding.observed.value),
                    finding.observed.state.value,
                    finding.observed.confidence,
                    finding.observed.confidence_method.value,
                    finding.expected,
                    finding.absence_reason,
                    finding.unknown_reason.value if finding.unknown_reason else None,
                ),
            )
            for ordinal, evidence in enumerate(finding.evidence):
                conn.execute(
                    "INSERT INTO finding_evidence "
                    "(finding_id, ordinal, file_id, line_start, line_end) VALUES (?,?,?,?,?)",
                    (
                        finding.finding_id,
                        ordinal,
                        evidence.file_id,
                        evidence.line_start,
                        evidence.line_end,
                    ),
                )


def read_run(conn: sqlite3.Connection, audit_id: str) -> dict[str, Any] | None:
    """Run metadata, or `None` when there is no such run."""
    row = conn.execute("SELECT * FROM audit_run WHERE audit_id = ?", (audit_id,)).fetchone()
    if row is None:
        return None
    return {
        "audit_id": row["audit_id"],
        "device_id": row["device_id"],
        "owner_id": row["owner_id"],
        "engine_version": row["engine_version"],
        "rulepack_id": row["rulepack_id"],
        "rulepack_version": row["rulepack_version"],
        "pack_versions": json.loads(row["pack_versions"]),
        "rules_evaluated": row["rules_evaluated"],
        "verdicts": {
            "pass": row["count_pass"],
            "fail": row["count_fail"],
            "unknown": row["count_unknown"],
            "not_applicable": row["count_na"],
        },
        "evaluated_at": row["evaluated_at"],
    }


def run_owner(conn: sqlite3.Connection, audit_id: str) -> tuple[bool, str | None]:
    """`(exists, owner_id)` — so a caller can tell "not found" from "not yours".

    Returned together deliberately. A route that checks existence and ownership
    in two queries can leak which audit ids exist by answering 404 and 403
    differently; with both in hand it can answer one way for both.
    """
    row = conn.execute("SELECT owner_id FROM audit_run WHERE audit_id = ?", (audit_id,)).fetchone()
    if row is None:
        return False, None
    return True, row["owner_id"]


def read_findings(
    conn: sqlite3.Connection,
    audit_id: str,
    *,
    status: str | None = None,
    severity: str | None = None,
) -> list[Finding]:
    """Findings for one run, rebuilt through the contract.

    Reconstructed as `Finding` objects rather than returned as rows, so every
    invariant is re-checked on the way out: a stored row that would violate
    Rule 2 or Rule 3 raises here instead of being rendered into a report.
    """
    sql = "SELECT * FROM finding WHERE audit_id = ?"
    params: list[Any] = [audit_id]
    if status:
        sql += " AND status = ?"
        params.append(status)
    if severity:
        sql += " AND base_severity = ?"
        params.append(severity)
    sql += " ORDER BY rule_id"

    run = read_run(conn, audit_id)
    rows = conn.execute(sql, params).fetchall()
    return [_to_finding(conn, row, run) for row in rows]


def _to_finding(conn: sqlite3.Connection, row: sqlite3.Row, run: dict[str, Any] | None) -> Finding:
    evidence = _read_evidence(conn, row["finding_id"])
    return Finding(
        finding_id=row["finding_id"],
        audit_id=row["audit_id"],
        device_id=row["device_id"],
        rule_id=row["rule_id"],
        status=Verdict(row["status"]),
        base_severity=Severity(row["base_severity"]),
        observed=ObservedValue(
            value=json.loads(row["observed_value"]) if row["observed_value"] else None,
            state=FieldState(row["observed_state"]),
            confidence=row["confidence"],
            confidence_method=ConfidenceMethod(row["confidence_method"]),
        ),
        expected=row["expected"],
        evidence=evidence,
        absence_reason=row["absence_reason"],
        unknown_reason=UnknownReason(row["unknown_reason"]) if row["unknown_reason"] else None,
        provenance=FindingProvenance(
            engine_version=run["engine_version"] if run else "unknown",
            rulepack_version=run["rulepack_version"] if run else None,
            pack_versions=run["pack_versions"] if run else {},
        ),
    )


def _read_evidence(conn: sqlite3.Connection, finding_id: str) -> tuple[Evidence, ...]:
    """Resolve evidence pointers back to the exact stored source text.

    The raw line comes from `line_cache`, which is the same text the parser read
    and the same text `config_line` hashes. A citation therefore quotes the
    operator's own file rather than a copy of it.
    """
    rows = conn.execute(
        """
        SELECT fe.file_id, fe.line_start, fe.line_end,
               cf.blob_path, cf.file_format, lc.text
        FROM finding_evidence fe
        LEFT JOIN config_file cf ON cf.file_id = fe.file_id
        LEFT JOIN config_line cl
               ON cl.file_id = fe.file_id AND cl.line_number = fe.line_start
        LEFT JOIN line_cache lc ON lc.line_sha256 = cl.line_sha256
        WHERE fe.finding_id = ?
        ORDER BY fe.ordinal
        """,
        (finding_id,),
    ).fetchall()

    out: list[Evidence] = []
    for row in rows:
        text = row["text"]
        if text is None:
            # The pointer outlived the file it points into. Reporting the gap is
            # right; inventing a line to fill it would not be.
            continue
        out.append(
            Evidence(
                file_id=row["file_id"],
                file_path=row["blob_path"] or row["file_id"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                raw_line=text,
                # Carried from the stored file rather than assumed: a citation
                # must say what kind of artefact it points into.
                source_type=SourceType(row["file_format"])
                if row["file_format"]
                else SourceType.CLI,
            )
        )
    return tuple(out)


def list_runs(
    conn: sqlite3.Connection, *, owner_id: str | None = None, limit: int = 50
) -> list[dict[str, Any]]:
    """Recent runs, optionally restricted to one owner.

    `owner_id=None` means unrestricted and is reserved for admins. The route
    decides that, not this function — but the parameter is named so a reader can
    see which call is the privileged one.
    """
    sql = "SELECT audit_id FROM audit_run"
    params: list[Any] = []
    if owner_id is not None:
        sql += " WHERE owner_id = ?"
        params.append(owner_id)
    sql += " ORDER BY evaluated_at DESC LIMIT ?"
    params.append(limit)

    ids = [row["audit_id"] for row in conn.execute(sql, params).fetchall()]
    return [run for run in (read_run(conn, audit_id) for audit_id in ids) if run]
