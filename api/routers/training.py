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

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from pydantic import Field as Constraint

from api.audit.chain import AuditChain
from api.db import training as store
from api.models.enums import CastType, TrainingOutcome
from api.routers.deps import AdminUser, AuditConn, Conn
from api.train import service
from api.train.compile import CompileRequest
from api.train.errors import TrainError
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


def _queue_json(queue: TrainingQueue) -> dict[str, Any]:
    return {
        "size": queue.size,
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
    """Unknown shapes, most frequent first, with suggestions or a stated absence."""
    return _queue_json(service.training_queue(conn, file_id=file_id, vendor=vendor))


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


@router.post("/confirm", status_code=201)
def confirm(
    conn: Conn, audit_conn: AuditConn, admin: AdminUser, body: ConfirmBody
) -> dict[str, Any]:
    """Record what the administrator decided, and audit that they decided it."""
    entry = service.training_queue(conn).find(body.cluster_id)
    shown = entry.outcome.suggestions if entry else ()

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
