"""Read-only HTTP surface over the audit chain.

**GET only, deliberately.** Records are appended by the services that perform
the actions — ingestion, the training workflow, pack activation — never by an
external caller. If an endpoint could inject a record, the log would attest to
whatever a client claimed rather than to what the system did.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from api.audit import store
from api.audit.verify import verify_chain
from api.db.connection import connect, table_exists
from api.routers.deps import CurrentUser

router = APIRouter(prefix="/audit", tags=["audit"])


def get_conn() -> Any:
    from api.config import settings

    # The chain lives in its own database (decision D4), separate from the
    # operational store that holds configuration content.
    conn = connect(settings.audit_db_path)
    try:
        if not table_exists(conn, "audit_log"):
            raise HTTPException(status_code=503, detail="audit log is not initialised")
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


@router.get("/head")
def read_head(conn: Conn, user: CurrentUser) -> dict[str, Any]:
    """Current chain head."""
    head = store.read_head(conn)
    if head is None:
        return {"empty": True, "last_seq": None, "last_hash": None, "record_count": 0}
    return {
        "empty": False,
        "last_seq": head.last_seq,
        "last_hash": head.last_hash,
        "record_count": head.record_count,
        "updated_at": head.updated_at,
    }


@router.get("/records")
def list_records(
    conn: Conn,
    user: CurrentUser,
    action: str | None = None,
    actor_id: str | None = None,
    subject_kind: str | None = None,
    subject_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict[str, Any]:
    """Filtered history, for display.

    Always reported as `verifiable: false`. A filtered or paginated set has no
    links between its rows, so it carries no integrity claim — presenting it as
    verified would be exactly the quiet overstatement this design avoids. Use
    `/audit/verify` for that.
    """
    rows = store.query(
        conn,
        action=action,
        actor_id=actor_id,
        subject_kind=subject_kind,
        subject_id=subject_id,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    return {
        "verifiable": False,
        "reason": "a filtered view has no links between its rows; use /audit/verify",
        "count": len(rows),
        "records": [
            {
                "seq": r["seq"],
                "timestamp": r["timestamp"],
                "actor": {"type": r["actor_type"], "id": r["actor_id"], "role": r["actor_role"]},
                "action": r["action"],
                "subject": {"kind": r["subject_kind"], "id": r["subject_id"]},
                "payload": r["payload_json"],
                "entry_hash": r["entry_hash"],
            }
            for r in rows
        ],
    }


@router.get("/verify")
def verify(
    conn: Conn,
    user: CurrentUser,
    start: Annotated[int, Query(ge=0)] = 0,
    end: int | None = None,
) -> dict[str, Any]:
    """Run the same verification the CLI runs.

    The CLI is the authority; this endpoint exists for convenience and for the
    dashboard banner. Both call the identical function.
    """
    return verify_chain(conn, start=start, end=end).to_dict()
