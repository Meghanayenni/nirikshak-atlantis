"""Per-device compliance posture over HTTP (ADR 0068).

    GET /compliance/devices/{device_id}/posture

Read-only. Nothing was stored to make it: the gate is read from the review
queue and the decisions recorded against it, and the posture is rolled up from
the latest run's persisted findings with the rulepack's mappings, re-attached by
content exactly as the findings view does (ADR 0056, 0057).

The interface renders this and decides nothing. In every state but `ready` the
response carries the gate and its reason and **no number that could be read as
a score** — no percentage, no counts, no bar.

The report route builds its posture section with `assemble_posture`, so the
document and the screen cannot disagree about whether a device was scored.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter

from api.comply.posture import decide_gate, device_posture, superseded_gate
from api.comply.rulepacks import load_active_rulepack
from api.config import settings
from api.db import findings as finding_store
from api.db import training as training_store
from api.models.auth import User
from api.models.enums import Verdict
from api.models.evidence import Evidence
from api.models.posture import ControlState, DevicePosture, GateState, ReviewProgress
from api.remediate.library import load_active_library
from api.remediate.resolver import resolve
from api.routers.audits import remediation_json
from api.routers.deps import Conn, CurrentUser, require_access
from api.train.bootstrap import corpus_guard

router = APIRouter(prefix="/compliance/devices", tags=["compliance"])


def _latest_run(conn: sqlite3.Connection, device_id: str, user: User) -> dict[str, Any] | None:
    """The newest run of this configuration the caller may see."""
    sql = "SELECT audit_id FROM audit_run WHERE device_id = ?"
    params: list[Any] = [device_id]
    if not user.is_admin:
        sql += " AND owner_id = ?"
        params.append(user.user_id)
    row = conn.execute(sql + " ORDER BY evaluated_at DESC LIMIT 1", params).fetchone()
    return finding_store.read_run(conn, row["audit_id"]) if row else None


def _file_row(conn: sqlite3.Connection, device_id: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT cf.detected_vendor, cf.detected_os_family,
               (SELECT owner_id FROM ingestion WHERE file_id = cf.file_id
                 ORDER BY received_at LIMIT 1) AS owner_id,
               (SELECT os_version FROM device WHERE device_id = cf.file_id) AS os_version
        FROM config_file cf WHERE cf.file_id = ?
        """,
        (device_id,),
    ).fetchone()


def assemble_posture(
    conn: sqlite3.Connection,
    user: User,
    device_id: str,
    *,
    run: dict[str, Any] | None = None,
) -> tuple[DevicePosture, dict[str, str | None]]:
    """The gate and posture for one device, and the platform it was decided on.

    `run` is given by the report route, which renders a specific run. When that
    run is not the device's latest, the gate is `superseded`: the review queue
    describes the newest parse and says nothing about an older one.
    """
    row = _file_row(conn, device_id)
    require_access(user, exists=row is not None, owner_id=row["owner_id"] if row else None)
    assert row is not None

    vendor, os_family = row["detected_vendor"], row["detected_os_family"]
    platform = {"vendor": vendor, "os_family": os_family, "os_version": row["os_version"]}

    latest = _latest_run(conn, device_id, user)
    if run is not None and latest is not None and run["audit_id"] != latest["audit_id"]:
        return DevicePosture(gate=superseded_gate(run, latest["evaluated_at"])), platform

    reviewed, total, last_decision = (
        training_store.review_progress(conn, device_id, vendor=vendor, os_family=os_family)
        if vendor
        else (0, 0, None)
    )
    # The same manifest check the bootstrap and the training routes use: an
    # evaluation or held-out corpus file is never reviewed, so never scored.
    guard = corpus_guard(settings.corpus_manifest)
    split = guard.protected.get(device_id)
    gate = decide_gate(
        run=latest,
        platform_identified=bool(vendor),
        review=ReviewProgress(reviewed=reviewed, total=total),
        last_decision_at=last_decision,
        is_admin=user.is_admin,
        reserved_split={"eval": "evaluation", "holdout": "held-out"}.get(split, split)
        if split
        else None,
    )
    findings = (
        finding_store.read_findings(conn, latest["audit_id"])
        if latest is not None and gate.state is GateState.READY
        else ()
    )
    rulepack = load_active_rulepack()
    posture = device_posture(
        gate,
        run=latest,
        findings=findings,
        rulepack_checksum=rulepack.checksum,
        rulepack_version=rulepack.version,
        rules=rulepack.rules,
        vendor=vendor,
        os_family=os_family,
        os_version=row["os_version"],
    )
    return posture, platform


def _evidence_json(evidence: Evidence) -> dict[str, Any]:
    return {
        "file_id": evidence.file_id,
        "file_path": evidence.file_path,
        "line_start": evidence.line_start,
        "line_end": evidence.line_end,
        "raw_line": evidence.raw_line,
        "cite": evidence.cite(),
    }


def posture_json(posture: DevicePosture, platform: dict[str, str | None]) -> dict[str, Any]:
    """The response. Scores appear only under `posture`, and only when ready."""
    gate = posture.gate
    body: dict[str, Any] = {
        "gate": {
            "state": gate.state.value,
            "message": gate.message,
            "next_step": gate.next_step,
            "review": gate.review.model_dump() if gate.review else None,
            "audit_id": gate.audit_id,
            "evaluated_at": gate.evaluated_at,
            "last_decision_at": gate.last_decision_at,
        },
        "posture": None,
    }
    if gate.state is not GateState.READY:
        return body

    library = load_active_library()
    vendor, os_family = platform["vendor"], platform["os_family"]

    def rule_json(contribution: Any, *, with_remediation: bool) -> dict[str, Any]:
        out: dict[str, Any] = {
            "rule_id": contribution.rule_id,
            "verdict": contribution.verdict.value if contribution.verdict else None,
            "finding_id": contribution.finding_id,
            "unknown_reason": (
                contribution.unknown_reason.value if contribution.unknown_reason else None
            ),
            "absence_reason": contribution.absence_reason,
            "evidence": [_evidence_json(e) for e in contribution.evidence],
            # The mapping's judgement: whether this rule tests all of the control.
            "coverage": contribution.coverage.value,
            "coverage_reason": contribution.coverage_reason,
        }
        if with_remediation:
            out["remediation"] = remediation_json(
                resolve(
                    library,
                    rule_id=contribution.rule_id,
                    vendor=vendor,
                    os_family=os_family,
                    actionable=True,
                )
            )
        return out

    def control_json(control: Any, edition: str) -> dict[str, Any]:
        violated = control.state is ControlState.VIOLATED
        undetermined = control.state is ControlState.UNDETERMINED
        return {
            "control_id": control.control_id,
            "edition": edition,
            "state": control.state.value,
            "reason": control.reason,
            # A violated control lists only the checks that failed, each with
            # the line it cites and the vetted fix — or the statement that none
            # exists. An undetermined one lists every check that did not pass.
            # A satisfied or no-violation-found one lists every mapped check,
            # each with how much of the control it tests and why.
            "rules": [
                rule_json(c, with_remediation=violated)
                for c in control.rules
                if (
                    c.verdict is Verdict.FAIL
                    if violated
                    else c.verdict is not Verdict.PASS
                    if undetermined
                    else True
                )
            ],
        }

    frameworks = []
    for fw in posture.frameworks:
        entry: dict[str, Any] = {
            "framework": fw.framework,
            "document": fw.document,
            "edition": fw.edition,
            "status": fw.status.value,
            "reason": fw.reason,
            "coverage": {
                "assessed": fw.assessed,
                "catalog_total": fw.catalog_total,
                "basis": fw.catalog_basis,
            },
        }
        if fw.status.value == "assessed":
            # The headline is `satisfied` of `assessed` — a fraction, never a
            # percentage — and it travels only inside these counts (ADR 0068).
            entry["counts"] = {
                "satisfied": fw.satisfied,
                "no_violation_found": fw.no_violation_found,
                "violated": fw.violated,
                "undetermined": fw.undetermined,
                "assessed": fw.assessed,
            }
            for state in ControlState:
                entry[state.value] = [
                    control_json(c, fw.edition) for c in fw.controls if c.state is state
                ]
        frameworks.append(entry)

    body["posture"] = {
        "mappings_attached": posture.mappings_attached,
        "withheld_reason": posture.withheld_reason,
        "frameworks": frameworks,
        "unsourced": posture.unsourced,
        "note": (
            "Control mappings are this project's judgement, not from a published "
            "crosswalk. This is evidence about one configuration, not a certification."
        ),
    }
    return body


@router.get("/{device_id}/posture")
def device_posture_endpoint(conn: Conn, user: CurrentUser, device_id: str) -> dict[str, Any]:
    """Whether this device may be scored, and — only if so — its posture per framework."""
    posture, platform = assemble_posture(conn, user, device_id)
    return {"device_id": device_id, "platform": platform, **posture_json(posture, platform)}
