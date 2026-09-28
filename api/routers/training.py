"""The confirmation loop over HTTP — the API P13's training screen will consume.

**Every endpoint here is admin-only**, including the read. That is stricter than
the rest of the API, where a user sees what they uploaded, and it is deliberate:
the queue is fleet-wide by construction — one shape across thirty devices is one
decision worth thirty — so reading it means reading configuration lines from
files the caller may not own. And confirming is a higher privilege than anything
else in NIRIKSHAK: a confirmation changes how every future device of that
platform is parsed, permanently, for everyone.

**Two steps, never one** (D51). `/compile` produces a DRAFT and hands back the
generated regex; `/activate` is a separate call. DEVELOPER_GUIDE.md §4 requires the pattern
be shown to the administrator and editable before activation, and an endpoint
that compiled-and-activated in one request would delete that review while
appearing to be a convenience.

**Suggestions are ranked, never scored as probabilities.** The payload carries
`rank`, the raw score, and `is_probability: false` — because a frontend given a
bare float will eventually render it as a percentage, and R7 exists to stop
exactly that. When no suggestion could be produced the payload says so with a
reason (D50); it never returns an empty list as though the model had run.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from pydantic import Field as Constraint

from api.audit.chain import AuditChain
from api.config import settings
from api.db import training as store
from api.ingest.packs import load_active_packs
from api.models.csm import CANONICAL_FIELD_NAMES
from api.models.enums import CastType, PatternSource, SyntaxMode, TrainingOutcome
from api.routers.deps import AdminUser, AuditConn, Conn
from api.train import bootstrap, service
from api.train.compile import CompileRequest
from api.train.errors import BootstrapError, TrainError
from api.train.queue import QueueEntry, TrainingQueue

router = APIRouter(prefix="/training", tags=["training"])


def _suggestion_json(entry: QueueEntry) -> dict[str, Any]:
    """Suggestions plus the state that explains them (D50).

    `state` is always present and `suggestions` is meaningful only when it reads
    `ranked`. The two travel together so a client cannot render an empty list as
    "nothing similar found" when the truth is "nothing was searched".
    """
    outcome = entry.outcome
    return {
        "state": str(outcome.state),
        "reason": outcome.reason,
        "is_probability": False,
        "confidence_note": (
            "Similarity scores are rankings, not probabilities. No calibrator is "
            "fitted (decision D42), so every suggestion abstains and the field "
            "stays UNKNOWN until an administrator confirms a mapping."
        ),
        "suggestions": [
            {
                "rank": s.rank,
                "field": s.field,
                "raw_score": s.raw_score,
                "calibrated_confidence": s.calibrated_confidence,
                "confidence_method": str(s.confidence_method),
            }
            for s in outcome.suggestions
        ],
    }


SPLIT_NAMES = {"eval": "evaluation", "holdout": "held-out"}


def split_reason(split: str) -> str:
    return (
        f"This line is read from a corpus {SPLIT_NAMES.get(split, split)} file, which "
        "is reserved for measuring the parser. A decision on it would compile a "
        "pattern from the data the parser is measured on (DEF-16), so it is refused."
    )


def reserved_reason(
    conn: sqlite3.Connection, *, file_id: str | None, cluster_id: str | None, line: str
) -> str | None:
    """Why a decision on this line is refused, or None (DEF-16, ADR 0068).

    Refused when the file the line is being reviewed from is an evaluation or
    held-out corpus file, or when every file whose queue holds the line is one.
    A line also present in a development file or an operator's own upload is
    not exclusive to the measured data, which is the condition the corpus
    policy suite already tests pack examples against.

    Reuses the bootstrap's corpus guard: the manifest's sha256 per split, read
    without opening any corpus file. A deployment without the manifest cannot
    run this check and is not refused anything.
    """
    guard = bootstrap.corpus_guard(settings.corpus_manifest)
    if not guard.present:
        return None
    sources = {file_id} if file_id else set()
    sources |= store.files_with_line(conn, cluster_id, line)
    reserved = sources & set(guard.protected)
    if file_id in guard.protected:
        return split_reason(guard.protected[file_id])
    if sources and reserved == sources:
        return split_reason(guard.protected[sorted(reserved)[0]])
    return None


def _decided(conn: sqlite3.Connection, file_id: str | None) -> set[str]:
    """Queue entries decided on their platform — the gate's own function (ADR 0068)."""
    sql = "SELECT DISTINCT cluster_id, vendor, os_family FROM unknown_line"
    params: tuple = ()
    if file_id is not None:
        sql += " WHERE file_id = ?"
        params = (file_id,)
    by_platform: dict[tuple, list[str]] = {}
    for row in conn.execute(sql, params):
        by_platform.setdefault((row["vendor"], row["os_family"]), []).append(row["cluster_id"])
    decided: set[str] = set()
    for (vendor, os_family), clusters in by_platform.items():
        decided |= set(store.decided_clusters(conn, clusters, vendor=vendor, os_family=os_family))
    return decided


def _queue_json(queue: TrainingQueue, decided: set[str] | None = None) -> dict[str, Any]:
    decided = decided or set()
    return {
        "size": queue.size,
        # One count, computed where the posture gate computes it (ADR 0068).
        "reviewed": sum(1 for e in queue.entries if e.cluster_id in decided),
        "confirmable": len(queue.confirmable),
        # ADR 0017 requires this sentence on the training screen: a person judging
        # a ranking deserves to know it was drawn from eleven examples of one
        # vendor rather than from a corpus.
        "index": queue.index_description,
        "model": {
            "available": queue.model.available if queue.model else False,
            "summary": queue.model.summary if queue.model else "unprobed",
            "package_installed": queue.model.package_installed if queue.model else False,
            "weights_present": queue.model.weights_present if queue.model else False,
            "airgap": queue.model.airgap if queue.model else False,
        },
        "scrubbed": queue.scrubbed,
        "entries": [
            {
                "cluster_id": e.cluster_id,
                "signature": e.cluster.signature,
                "line": e.exemplar_text,
                "occurrences": e.cluster.size,
                "file_count": e.cluster.file_count,
                "confirmable": e.cluster.is_confirmable,
                "decided": e.cluster_id in decided,
                "block_path": list(e.cluster.exemplar.block_path),
                "file_id": e.cluster.exemplar.file_id,
                "line_number": e.cluster.exemplar.line_number,
                **_suggestion_json(e),
            }
            for e in queue.entries
        ],
    }


@router.get("/queue")
def read_queue(
    conn: Conn,
    _admin: AdminUser,
    file_id: Annotated[str | None, Query()] = None,
    vendor: Annotated[str | None, Query()] = None,
) -> dict[str, Any]:
    """Unknown shapes, most frequent first, with suggestions or a stated absence.

    Each entry says whether it is decided, by the function the posture gate
    uses. For one file the response also says when that file is reserved for
    measurement, so the review screen can say so before anyone tries.
    """
    body = _queue_json(
        service.training_queue(conn, file_id=file_id, vendor=vendor), _decided(conn, file_id)
    )
    guard = bootstrap.corpus_guard(settings.corpus_manifest)
    body["reserved"] = (
        split_reason(guard.protected[file_id]) if file_id in guard.protected else None
    )
    return body


class ConfirmBody(BaseModel):
    """One decision. The administrator's identity comes from authentication,
    never from the body — a caller must not be able to attribute a confirmation
    to somebody else."""

    model_config = ConfigDict(extra="forbid")

    cluster_id: str = Constraint(min_length=1)
    line: str = Constraint(min_length=1)
    vendor: str = Constraint(min_length=1)
    os_family: str = Constraint(min_length=1)
    outcome: TrainingOutcome
    field: str | None = None
    value_semantics: str | None = None
    file_id: str | None = None
    """The file the line is being reviewed from, when there is one (DEF-16)."""


@router.post("/confirm", status_code=201)
def confirm(
    conn: Conn, audit_conn: AuditConn, admin: AdminUser, body: ConfirmBody
) -> dict[str, Any]:
    """Record what the administrator decided, and audit that they decided it."""
    refused = reserved_reason(
        conn, file_id=body.file_id, cluster_id=body.cluster_id, line=body.line
    )
    if refused:
        raise HTTPException(status_code=409, detail=refused)

    entry = service.training_queue(conn).find(body.cluster_id)
    shown = entry.outcome.suggestions if entry else ()

    # A generic shape carries no command vocabulary, so one mapping over it
    # would cover lines with nothing in common. Dismissing it compiles nothing
    # and is allowed, so such an entry can always be reviewed (ADR 0068).
    if (
        entry is not None
        and not entry.cluster.is_confirmable
        and body.outcome is not TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "this shape is too generic to map as one decision; it can only be "
                "marked not security relevant"
            ),
        )

    decision = service.Decision(
        cluster_id=body.cluster_id,
        line=body.line,
        vendor=body.vendor,
        os_family=body.os_family,
        outcome=body.outcome,
        field=body.field,
        value_semantics=body.value_semantics,
        suggestions_shown=shown,
    )
    try:
        example = service.confirm(
            conn, decision, confirmed_by=admin.username, chain=AuditChain(audit_conn)
        )
    except (TrainError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "example_id": example.example_id,
        "field": example.field,
        "outcome": str(example.outcome),
        "confirmed_by": example.confirmed_by,
        "audit_seq": example.audit_seq,
        "improved_coverage": example.improved_coverage,
    }


class CompileBody(BaseModel):
    """What to compile, and how the administrator wants the value read."""

    model_config = ConfigDict(extra="forbid")

    example_id: str = Constraint(min_length=1)
    value_token: int | None = Constraint(default=None, ge=0)
    literal_value: str | None = None
    cast: CastType = CastType.STR
    block_path: tuple[str, ...] = ()
    generalise_numeric_scope: bool = False
    pattern_override: str | None = Constraint(
        default=None,
        description="An edited regex (DEVELOPER_GUIDE.md §4). Re-validated, never trusted.",
    )


@router.post("/compile", status_code=201)
def compile_draft(
    conn: Conn, audit_conn: AuditConn, admin: AdminUser, body: CompileBody
) -> dict[str, Any]:
    """Compile a recorded decision into a DRAFT pack. Activation is separate."""
    example = store.read_example(conn, body.example_id)
    if example is None:
        raise HTTPException(status_code=404, detail="no such training example")
    refused = reserved_reason(
        conn, file_id=None, cluster_id=example.cluster_id, line=example.raw_line_scrubbed
    )
    if refused:
        raise HTTPException(status_code=409, detail=refused)

    request = CompileRequest(
        value_token=body.value_token,
        literal_value=body.literal_value,
        cast=body.cast,
        block_path=body.block_path,
        generalise_numeric_scope=body.generalise_numeric_scope,
    )
    try:
        draft = service.compile_confirmation(
            conn,
            example,
            request,
            pattern_override=body.pattern_override,
            chain=AuditChain(audit_conn),
            actor_id=admin.username,
        )
    except TrainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "pack_id": draft.pack.pack_id,
        "pack_version": draft.pack.pack_version,
        "parent_version": draft.pack.parent_version,
        "status": str(draft.pack.status),
        "pattern_id": draft.pattern.id,
        "field": draft.pattern.field,
        # The whole point of the DRAFT step: this is what a person reads and may
        # edit before anything is activated.
        "pattern": draft.regex,
        "scope": list(draft.pattern.scope.block or ()),
        "capture": draft.pattern.capture.value,
        "cast": str(draft.pattern.capture.cast),
        "edited": draft.edited,
        "examples": list(draft.pattern.examples),
    }


class ActivateBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str = Constraint(min_length=1)
    pack_version: str = Constraint(min_length=1)


@router.post("/activate")
def activate(audit_conn: AuditConn, admin: AdminUser, body: ActivateBody) -> dict[str, Any]:
    """Validate and activate a DRAFT. The next parse uses it — no restart."""
    try:
        draft = service.load_draft(body.pack_id, body.pack_version)
        result = service.activate_draft(
            draft, activated_by=admin.username, chain=AuditChain(audit_conn)
        )
    except TrainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "pack_id": result.pack_id,
        "pack_version": result.version,
        "previous_version": result.previous_version,
        "checksum": result.checksum,
        "patterns": list(result.pattern_ids),
        "note": "Re-audit affected files to apply the new pack to them.",
    }


class RollbackBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str = Constraint(min_length=1)
    to_version: str = Constraint(min_length=1)


@router.post("/rollback")
def rollback(audit_conn: AuditConn, admin: AdminUser, body: RollbackBody) -> dict[str, Any]:
    """Return a platform to an earlier pack version, exactly as it was."""
    try:
        result = service.rollback_pack(
            body.pack_id,
            body.to_version,
            rolled_back_by=admin.username,
            chain=AuditChain(audit_conn),
        )
    except TrainError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {
        "pack_id": result.pack_id,
        "pack_version": result.version,
        "rolled_back_from": result.previous_version,
        "checksum": result.checksum,
    }


@router.get("/examples")
def list_examples(
    conn: Conn,
    _admin: AdminUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Recorded decisions — the labelled population gap 7 needs (SOURCING_BACKLOG).

    Reported as a count and a list, with no accuracy figure derived from it. Top-3
    accuracy stays NOT MEASURED until there is a population worth measuring, and
    it is not this router's job to decide that it has arrived.
    """
    found = store.examples(conn, limit=limit)
    return {
        "count": store.example_count(conn),
        "examples": [
            {
                "example_id": e.example_id,
                "vendor": e.vendor,
                "os_family": e.os_family,
                "line": e.raw_line_scrubbed,
                "field": e.field,
                "outcome": str(e.outcome),
                "confirmed_by": e.confirmed_by,
                "audit_seq": e.audit_seq,
                "top3_hit": e.top3_hit,
            }
            for e in found
        ],
    }


# ---------------------------------------------------------------------------
# The pack inventory
# ---------------------------------------------------------------------------


def _pattern_json(pattern: Any) -> dict[str, Any]:
    """One mapping, as the administrator needs to read it.

    The regex is shown in full. DEVELOPER_GUIDE.md §4 requires that a pattern be readable
    by the person who has to stand behind it, and a screen that showed the field
    name but hid the expression would leave them approving something they cannot
    check.
    """
    provenance = pattern.provenance
    return {
        "id": pattern.id,
        "field": pattern.field,
        "source": str(pattern.source),
        "match_type": str(pattern.match.type),
        "pattern": pattern.match.pattern,
        "capture": pattern.capture.value,
        "cast": str(pattern.capture.cast),
        "scope_block": list(pattern.scope.block or ()),
        "examples": list(pattern.examples),
        "training_example_id": provenance.training_example_id if provenance else None,
        "audit_seq": provenance.audit_seq if provenance else None,
        # Only an admin-trained pattern may be withdrawn (see
        # `draft_without_pattern`). Compared against the enum rather than a
        # string literal: the wire value is `admin_trained` and a hand-written
        # spelling here would silently mark every trained mapping permanent.
        # Stated in the payload so the UI does not re-derive the rule and cannot
        # disagree with the backend about it.
        "withdrawable": pattern.source is PatternSource.ADMIN_TRAINED,
    }


@router.get("/packs")
def list_packs(_admin: AdminUser) -> dict[str, Any]:
    """Every vendor pack version on disk, newest first, active one marked.

    Superseded versions are included deliberately: they are what rollback selects
    between, and an inventory that showed only the active version would make the
    versioning look decorative.
    """
    summaries = service.pack_inventory()
    return {
        "count": len(summaries),
        # The canonical schema and the cast vocabulary, served rather than
        # duplicated in the client. Rule 5 — adding a field is a data change, and
        # a hardcoded list in the interface would make it a frontend release too.
        # It is also the honest list: a field the interface offers that the model
        # does not have would produce a mapping that compiles and reads nothing.
        "canonical_fields": sorted(CANONICAL_FIELD_NAMES),
        "casts": [c.value for c in CastType],
        "packs": [
            {
                "pack_id": s.pack.pack_id,
                "vendor": s.pack.vendor,
                "os_family": s.pack.os_family,
                "pack_version": s.pack.pack_version,
                "parent_version": s.pack.parent_version,
                "status": str(s.pack.status),
                "origin": s.origin,
                "is_active": s.is_active,
                "checksum": s.pack.checksum,
                "created_at": (s.pack.created_at.isoformat() if s.pack.created_at else None),
                "pattern_count": len(s.pack.patterns),
                "admin_trained_count": sum(
                    1 for p in s.pack.patterns if p.source is PatternSource.ADMIN_TRAINED
                ),
                "patterns": [_pattern_json(p) for p in s.pack.patterns],
            }
            for s in summaries
        ],
    }


class WithdrawBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pack_id: str = Constraint(min_length=1)
    pattern_id: str = Constraint(min_length=1)
    reason: str | None = Constraint(default=None, max_length=500)


@router.post("/withdraw")
def withdraw(audit_conn: AuditConn, admin: AdminUser, body: WithdrawBody) -> dict[str, Any]:
    """Retire one admin-trained mapping from the active pack.

    Not a delete. A new pack version is drafted without the pattern, validated,
    and activated; the version that contained it stays on disk so an audit run
    under it can still be explained, and the training example that produced it is
    left alone — a decision an administrator made is an event that happened.

    `withdrawn_by` comes from the authenticated identity, never from the body,
    for the same reason `confirmed_by` does.
    """
    chain = AuditChain(audit_conn)
    try:
        result = service.withdraw_pattern(
            body.pack_id,
            body.pattern_id,
            withdrawn_by=admin.username,
            reason=body.reason,
            chain=chain,
        )
    except TrainError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return {
        "pack_id": result.pack_id,
        "pack_version": result.version,
        "previous_version": result.previous_version,
        "withdrawn_pattern_id": body.pattern_id,
        "checksum": result.checksum,
        "pattern_count": len(result.pattern_ids),
    }


# ---------------------------------------------------------------------------
# Bootstrapping a platform no pack knows (ADR 0067)
# ---------------------------------------------------------------------------


def _fingerprint_json(f: bootstrap.Fingerprint) -> dict[str, Any]:
    return {
        "stem": f.stem,
        "pattern": f.pattern,
        "example": f.example,
        "line_number": f.line_number,
        "occurrences": f.occurrences,
        "pasted": f.pasted,
    }


def _limits() -> dict[str, float]:
    return {
        "min_score": settings.detection_min_score,
        "min_margin": settings.detection_min_margin,
    }


@router.get("/bootstrap/{file_id}")
def bootstrap_assessment(conn: Conn, _admin: AdminUser, file_id: str) -> dict[str, Any]:
    """What this file shows about its own structure — and never whose it is."""
    try:
        found = bootstrap.assess(
            conn,
            file_id,
            blob_root=settings.blob_root,
            packs=load_active_packs(use_cache=False),
            guard=bootstrap.corpus_guard(settings.corpus_manifest),
            **_limits(),
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="no such file") from None

    s = found.structure
    return {
        "file_id": found.file_id,
        "filename": found.filename,
        "eligible": found.eligible,
        "reason": found.reason,
        "principle": found.principle,
        "detection": {
            "outcome": found.detection_outcome,
            "explanation": found.detection_explanation,
            **_limits(),
        },
        "split_check": found.split_check,
        # Set once this file has been bootstrapped: the page offers "Discard and
        # start over" for it, and for nothing that ships with NIRIKSHAK.
        "bootstrapped_platform": bootstrap.bootstrapped_platform(conn, file_id),
        "syntax": {
            "derived": str(found.syntax.mode),
            "evidence": list(found.syntax.evidence),
            "parseable": found.syntax.parseable,
            "implemented_modes": list(found.implemented_modes),
        },
        "comments": {"prefix": found.comments.prefix, "counts": found.comments.counts},
        "structure": {
            "total_lines": s.total_lines,
            "blank_lines": s.blank_lines,
            "comment_lines": s.comment_lines,
            "content_lines": s.content_lines,
            "indented_lines": s.indented_lines,
            "max_depth": s.max_depth,
            "block_headers": list(s.block_headers),
            "section_path_lines": s.section_path_lines,
        },
        "fingerprints": {
            "candidates": [_fingerprint_json(f) for f in found.candidates],
            "excluded_as_used_elsewhere": found.excluded_stems,
            "choose": [bootstrap.MIN_FINGERPRINTS, bootstrap.MAX_FINGERPRINTS],
        },
    }


class BootstrapBody(BaseModel):
    """The administrator's answer. Every derived value arrives here as a choice."""

    model_config = ConfigDict(extra="forbid")

    file_id: str = Constraint(min_length=1)
    vendor: str = Constraint(min_length=1)
    os_family: str = Constraint(min_length=1)
    syntax_mode: SyntaxMode
    fingerprints: list[str] = []
    pasted_lines: list[str] = []
    comment_prefixes: list[str] | None = None


@router.post("/bootstrap", status_code=201)
def bootstrap_platform(
    conn: Conn, audit_conn: AuditConn, admin: AdminUser, body: BootstrapBody
) -> dict[str, Any]:
    """Write a stub pack for a new platform, activate it, and re-detect the file."""
    request = bootstrap.BootstrapRequest(
        file_id=body.file_id,
        vendor=body.vendor,
        os_family=body.os_family,
        syntax_mode=body.syntax_mode,
        chosen_stems=tuple(body.fingerprints),
        pasted_lines=tuple(body.pasted_lines),
        comment_prefixes=tuple(body.comment_prefixes)
        if body.comment_prefixes is not None
        else None,
    )
    try:
        result = bootstrap.create(
            conn,
            request,
            admin=admin.username,
            blob_root=settings.blob_root,
            guard=bootstrap.corpus_guard(settings.corpus_manifest),
            chain=AuditChain(audit_conn),
            **_limits(),
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="no such file") from None
    except BootstrapError as exc:
        raise HTTPException(status_code=409 if exc.conflict else 422, detail=str(exc)) from exc

    return {
        "pack_id": result.pack.pack_id,
        "pack_version": result.pack.pack_version,
        "checksum": result.pack.checksum,
        "syntax_mode": str(result.pack.syntax_mode),
        "syntax_mode_derived": str(result.derived_mode),
        "comment_prefixes": list(result.pack.comment_prefixes),
        "detect": [{"pattern": d.pattern, "weight": d.weight} for d in result.pack.detect],
        "fingerprints": [_fingerprint_json(f) for f in result.fingerprints],
        "detection": {
            "outcome": str(result.detection.outcome),
            "score": result.detection.score,
            "margin": result.detection.margin,
            "explanation": result.detection.explain(),
        },
        "also_matches": [
            {"file_id": c.file_id, "filename": c.filename} for c in result.also_matches
        ],
        "next": (
            "Run an audit of this file. Every line is unknown to the new pack, so "
            "every line enters the review queue, where each mapping is confirmed "
            "one at a time."
        ),
    }


@router.delete("/bootstrap/{vendor}/{os_family}")
def discard_bootstrap(
    conn: Conn, audit_conn: AuditConn, admin: AdminUser, vendor: str, os_family: str
) -> dict[str, Any]:
    """Discard and start over: every version removed, its files undetected again."""
    try:
        result = bootstrap.discard(
            conn,
            f"{vendor}/{os_family}",
            admin=admin.username,
            blob_root=settings.blob_root,
            chain=AuditChain(audit_conn),
            **_limits(),
        )
    except KeyError:
        raise HTTPException(
            status_code=404, detail="no bootstrapped platform by that name"
        ) from None
    except BootstrapError as exc:
        raise HTTPException(status_code=409 if exc.conflict else 422, detail=str(exc)) from exc

    return {
        "pack_id": result.pack_id,
        "versions_removed": list(result.versions_removed),
        "files_reset": list(result.files_reset),
    }
