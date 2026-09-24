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
from api.audit.chain import AuditChain
from api.comply.engine import evaluate_device, new_audit_id
from api.comply.frameworks import (
    UnsourcedFrameworkError,
    device_framework_options,
    indexes,
    resolve_selection,
    run_framework_view,
    scope_selection,
)
from api.comply.rulepacks import load_active_rulepack
from api.comply.service import audit_payload, summarise
from api.config import settings
from api.db import findings as finding_store
from api.ingest import blobs
from api.ingest.device_identity import extract_identity
from api.ingest.lines import split_lines
from api.ingest.packs import find_pack
from api.models.audit import Subject
from api.models.enums import AuditAction, Framework
from api.models.finding import Finding
from api.normalise.service import build_csm
from api.parse.service import parse_configuration
from api.prioritise.service import prioritise
from api.remediate.library import load_active_library
from api.remediate.resolver import RemediationResolution, resolve
from api.routers.deps import AuditConn, Conn, CurrentUser, owner_filter, require_access
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


def _os_version(conn: sqlite3.Connection, device_id: str) -> str | None:
    """The release ingestion read from the file — what an edition's scope is tested on."""
    row = conn.execute("SELECT os_version FROM device WHERE device_id = ?", (device_id,)).fetchone()
    return row["os_version"] if row is not None else None


def _finding_json(
    finding: Finding,
    resolution: RemediationResolution,
    declined: tuple[tuple[Framework, str], ...] = (),
) -> dict[str, Any]:
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
        # Only identifiers whose edition describes this device (ADR 0052), each
        # with the edition it was validated against and whose judgement the
        # mapping is — a control ID without its provenance claims more than the
        # repository supports (ADR 0057).
        "frameworks": [
            {
                "framework": f.framework.value,
                "control_id": f.control_id,
                "edition": f.version,
                "citation": f.citation,
                "mapping_provenance": f.mapping_provenance.value,
            }
            for f in finding.frameworks
        ],
        # Sourced frameworks that describe this device and that this rule
        # deliberately does not map to, with the reason the rule records.
        "declined": [{"framework": f.value, "reason": why} for f, why in declined],
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


@router.get("/frameworks")
def list_frameworks() -> dict[str, Any]:
    """Which benchmarks this deployment can evaluate against.

    **A framework with no sourced catalog is absent from this list**, never
    present with a zero beside it. An empty result reads as "your fleet is
    compliant", and "we have never read this benchmark" is a different
    statement — rendering them the same is how a sourcing gap becomes a
    compliance claim (ADR 0036).

    Each entry names the exact document edition and the sha256 of the catalog
    the identifiers were read from, so a reviewer can obtain the same file.
    """
    return {
        "frameworks": [
            {
                "framework": framework.value,
                "document": index.document,
                "edition": index.edition,
                "catalog_sha256": index.sha256,
                "source_url": index.source_url,
                # Where the digested document is: a path in this repository (the
                # STIG), or a statement that it is deliberately not held (CIS).
                "held_at": index.held_at or None,
                "source_note": index.source_note or None,
                # The platform the edition is written for; None means any. A
                # STIG or CIS identifier is true only there (ADR 0052).
                "covers": index.covers.describe() if index.covers else None,
                "controls_indexed": index.control_count,
            }
            for framework, index in sorted(indexes().items(), key=lambda kv: kv[0].value)
        ],
        "note": (
            "Mappings from NIRIKSHAK checks to these controls are asserted by this "
            "project, not taken from a published crosswalk. A catalog publishes "
            "controls; it does not publish mappings."
        ),
    }


@router.get("/frameworks/device/{file_id}")
def frameworks_for_device(conn: Conn, user: CurrentUser, file_id: str) -> dict[str, Any]:
    """What a selector may offer for one device (ADR 0058).

    Every sourced framework, and whether its edition describes this device —
    with the reason when it does not. An unsourced framework is absent, as on
    the unscoped list. The interface renders this; it decides nothing. The audit
    route still refuses a non-describing selection with 409 on its own, so a
    client that ignored this answer would be refused, not misled.
    """
    row = conn.execute(
        """
        SELECT cf.detected_vendor, cf.detected_os_family,
               (SELECT owner_id FROM ingestion WHERE file_id = cf.file_id
                 ORDER BY received_at LIMIT 1) AS owner_id
        FROM config_file cf WHERE cf.file_id = ?
        """,
        (file_id,),
    ).fetchone()
    require_access(user, exists=row is not None, owner_id=row["owner_id"] if row else None)
    assert row is not None

    os_version = _os_version(conn, file_id)
    return {
        "file_id": file_id,
        "platform": {
            "vendor": row["detected_vendor"],
            "os_family": row["detected_os_family"],
            "os_version": os_version,
        },
        "frameworks": device_framework_options(
            row["detected_vendor"], row["detected_os_family"], os_version
        ),
        "note": (
            "Mappings from NIRIKSHAK checks to these controls are asserted by this "
            "project, not taken from a published crosswalk."
        ),
    }


@router.post("", status_code=201)
def run_audit_endpoint(
    conn: Conn,
    audit_conn: AuditConn,
    user: CurrentUser,
    file_id: str,
    framework: Annotated[list[str] | None, Query()] = None,
) -> dict[str, Any]:
    """Audit one ingested configuration, and persist the result.

    The caller must own the upload. Ownership is checked before anything is read
    from disk, so an unauthorised request never touches another user's file.

    `framework` scopes the audit to user-selected benchmarks (PS 26155). Omitted,
    every applicable rule runs — NIRIKSHAK's own checks. A framework with no
    sourced catalog is **refused with 400**, never answered with an empty
    result.
    """
    try:
        selection = resolve_selection(framework or [])
    except UnsourcedFrameworkError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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

    # DEF-15 (P12) — the detected identity now reaches the canonical model.
    #
    # `build_csm` has accepted a `detected_identity` since P5 and no production
    # caller ever passed one, so every audited device carried hostname, model,
    # os_version and serial as None while ingestion had already read and stored
    # them. Rule applicability was unaffected (vendor and os_family fall back to
    # the pack) and the report omits identity by design, so nothing produced a
    # wrong answer — but peer-baseline grouping at P12 needs to know which device
    # it is looking at, and "the model has no idea" is not a workable input.
    identity = extract_identity(
        pack,
        split_lines(text),
        file_id=file_id,
        file_path=row["blob_path"],
    )
    csm = build_csm(parsed, pack, device_id=file_id, detected_identity=identity)

    # ADR 0054 — a selection is resolved against THIS device before anything is
    # recorded. A STIG or CIS edition describes one platform and release; asked
    # of a device it does not describe, it would evaluate nothing and report
    # zero findings, which reads as compliance. Refused here, with the reason,
    # before the training queue or the store is touched.
    scope = scope_selection(
        selection,
        load_active_rulepack().rules,
        csm.device.vendor,
        csm.device.os_family,
        csm.device.os_version,
    )
    if scope.refused:
        raise HTTPException(status_code=409, detail=scope.refusal())

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
        csm,
        load_active_rulepack(),
        audit_id=audit_id,
        evaluated_at=evaluated_at,
        frameworks=scope.effective,
    )
    if not results:
        # Reachable only through a framework selection that matches no rule: a
        # platform selector cannot empty the rulepack, because every rule
        # applies to every platform by default. Raising rather than persisting
        # an empty run — `save_run` would refuse it anyway, as a 500 naming
        # nothing, and "zero findings" must never render as "nothing wrong".
        raise HTTPException(
            status_code=409,
            detail=(
                "no rule maps to the selected framework(s) "
                f"{sorted(f.value for f in selection)}, so this audit would report "
                "zero findings. That is a coverage gap, not a compliant device."
            ),
        )

    acl_result = analyse_device(csm, audit_id=audit_id, analysed_at=evaluated_at)
    ranking = prioritise(csm, results, load_active_rulepack())

    finding_store.save_run(
        conn,
        audit_id=audit_id,
        device_id=file_id,
        owner_id=user.user_id,
        findings=results,
        rulepack_id=load_active_rulepack().rulepack_id,
        summary=summarise(results),
        framework_selection=selection,
    )

    # DEF-14 (found at P11, fixed here) — the chain records that this audit ran.
    #
    # `api/comply/service.run_audit` has appended AUDIT_RUN since P6 and this
    # route never called it, so the one action DEVELOPER_GUIDE.md §9 names alongside
    # suggestions, corrections and pack changes — "audit results" — was the only
    # one the chain never held. The payload is `comply.service.audit_payload`,
    # unchanged: counts, identifiers and versions, never a value and never a line.
    AuditChain(audit_conn).append_system(
        AuditAction.AUDIT_RUN,
        Subject(kind="audit", id=audit_id),
        payload=audit_payload(csm, load_active_rulepack(), results),
    )

    return {
        "audit_id": audit_id,
        "device_id": file_id,
        "verdicts": summarise(results),
        "rules_evaluated": len(results),
        # None means the run was not scoped to a benchmark. Reported so a reader
        # can tell a narrowed scope from a device that produced fewer findings.
        "framework_selection": sorted(f.value for f in selection) or None,
        # Selected, but written for a platform or release this device is not.
        # Named with the reason, never silently dropped from the scope.
        "frameworks_not_describing_device": {
            f.value: why for f, why in sorted(scope.excluded.items())
        },
        # Rules the selection left out, each with the reason the rule records.
        # Not findings and not abstentions: "this framework does not ask for
        # this" is a statement about the framework, not about the device.
        "not_assessed": [{"rule_id": n.rule_id, "reason": n.reason} for n in scope.not_assessed],
        # The size of the training queue this file contributes. Expected to fall
        # after an administrator confirms a mapping and the pack is activated.
        "residue_lines": residue_recorded,
        # A separate rail from findings, and reported as one (decision D22).
        "acl_analysis": {
            "analysed_nothing": acl_result.analysed_nothing,
            "summary": acl_result.summary(),
            # A list recognised and then dropped is NOT the same as a device
            # with no access lists, and both arrive as an empty tuple. Naming
            # the list and the line that defeated the parser is what lets an
            # operator tell "nobody has taught this syntax" from "this device
            # filters nothing" — and tells whoever maintains the dialect what to
            # add next.
            "not_analysed": [
                {
                    "acl_name": f.acl_name,
                    "entry_line": f.entry_line,
                    "entry_text": f.entry_text,
                    "reason": f.reason,
                    "summary": f.describe(),
                }
                for f in csm.acl_failures
            ],
        },
        # P12 — the Prioritise stage. On a model with no interfaces and no access
        # lists this reports that it could not rank, and which input was missing,
        # rather than falling back to a severity sort (DEVELOPER_GUIDE.md §7).
        "prioritisation": {
            "ranked": ranking.ranked,
            "reason": ranking.reason,
            "determined": ranking.determined,
            "undetermined": ranking.undetermined,
            "blockers": ranking.blockers(),
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

    # Control mappings are rulepack data and are not stored per finding (D96).
    # Resolved by the same view the report uses (ADR 0057), so the interface
    # reading this route and the document cannot disagree — and when nothing
    # is attached, the reason travels with the response rather than leaving the
    # interface to guess at one.
    rulepack = load_active_rulepack()
    view = run_framework_view(
        rulepack.checksum,
        rulepack.version,
        rulepack.rules,
        run or {},
        vendor,
        os_family,
        _os_version(conn, run["device_id"]) if run else None,
    )
    if view.attached:
        results = [
            f.model_copy(update={"frameworks": view.mappings.get(f.rule_id, ())})
            if not f.frameworks
            else f
            for f in results
        ]

    return {
        "audit_id": audit_id,
        "count": len(results),
        "snippet_library_version": library.version,
        "framework_view": {
            "attached": view.attached,
            "withheld_reason": view.withheld_reason,
            "absent": view.absent,
            "selection": (run or {}).get("framework_selection"),
            "not_applied": (
                {f.value: why for f, why in sorted(view.scope.excluded.items())}
                if view.scope
                else {}
            ),
            "not_assessed": (
                [{"rule_id": n.rule_id, "reason": n.reason} for n in view.scope.not_assessed]
                if view.scope
                else []
            ),
        },
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
                view.declined.get(f.rule_id, ()),
            )
            for f in results
        ],
    }
