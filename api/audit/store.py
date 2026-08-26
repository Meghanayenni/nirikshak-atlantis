"""SQL for the audit chain. No hashing logic, no HTTP, no policy.

This module is also where decision D2 is enforced: payload values must be
JSON-native before anything is hashed or stored.
"""

from __future__ import annotations

import json
import math
import sqlite3
from dataclasses import dataclass
from typing import Any

from api.audit.errors import PayloadNotJsonNativeError
from api.db.connection import trigger_exists
from api.models import Actor, AuditRecord, Subject
from api.models.audit import canonical_json, canonical_timestamp

APPEND_ONLY_TRIGGERS = ("audit_log_no_update", "audit_log_no_delete")

DEFAULT_HASH_ALGO = "sha256"
"""P2 uses an unkeyed SHA-256 chain. The column exists so decision R17 — a keyed
or externally anchored successor — can arrive by migration rather than by
rewriting history."""

_JSON_SCALARS = (str, int, float, bool, type(None))


def validate_json_native(value: Any, path: str = "payload") -> None:
    """Reject anything JSON cannot represent exactly (decision D2).

    ``canonical_json`` carries ``default=str`` as a backstop. Relying on it
    would mean ``{"when": datetime(...)}`` and ``{"when": "2026-08-26 12:00:00+00:00"}``
    hash identically — distinct payloads collapsing to one digest. Callers
    serialise their own objects instead, which is what an audit payload should
    do anyway.
    """
    if isinstance(value, bool) or value is None or isinstance(value, str | int):
        return

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise PayloadNotJsonNativeError(
                f"{path} is {value!r}; NaN and Infinity are not representable in JSON"
            )
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise PayloadNotJsonNativeError(
                    f"{path} has a non-string key {key!r} ({type(key).__name__}); "
                    "JSON object keys must be strings"
                )
            validate_json_native(item, f"{path}.{key}")
        return

    if isinstance(value, list | tuple):
        for index, item in enumerate(value):
            validate_json_native(item, f"{path}[{index}]")
        return

    raise PayloadNotJsonNativeError(
        f"{path} is a {type(value).__name__}, which JSON cannot represent. "
        "Audit payloads accept str, int, float, bool, None, list and dict only — "
        "serialise it explicitly rather than letting str() decide (D2)."
    )


@dataclass(frozen=True)
class ChainHead:
    last_seq: int
    last_hash: str
    record_count: int
    updated_at: str


@dataclass(frozen=True)
class StoredRecord:
    """A row exactly as it sits on disk, before any interpretation."""

    record: AuditRecord
    payload_json: str
    hash_algo: str


def read_head(conn: sqlite3.Connection) -> ChainHead | None:
    row = conn.execute(
        "SELECT last_seq, last_hash, record_count, updated_at FROM audit_chain_head WHERE id = 1"
    ).fetchone()
    if row is None:
        return None
    return ChainHead(
        last_seq=row["last_seq"],
        last_hash=row["last_hash"],
        record_count=row["record_count"],
        updated_at=row["updated_at"],
    )


def max_seq(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT MAX(seq) AS m FROM audit_log").fetchone()
    return row["m"] if row and row["m"] is not None else None


def record_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]


def insert_record(conn: sqlite3.Connection, record: AuditRecord, payload_json: str) -> None:
    """Write one record. The canonical payload string is stored verbatim.

    Storing the exact bytes that were hashed — rather than re-serialising a dict
    on read — is what keeps verification independent of any future change in
    Python's JSON behaviour.
    """
    conn.execute(
        """
        INSERT INTO audit_log (
            seq, timestamp, actor_type, actor_id, actor_role,
            action, subject_kind, subject_id,
            payload_json, payload_hash, prev_hash, entry_hash, hash_algo
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.seq,
            canonical_timestamp(record.timestamp),
            str(record.actor.type),
            record.actor.id,
            record.actor.role,
            str(record.action),
            record.subject.kind,
            record.subject.id,
            payload_json,
            record.payload_hash,
            record.prev_hash,
            record.entry_hash,
            DEFAULT_HASH_ALGO,
        ),
    )


def upsert_head(conn: sqlite3.Connection, record: AuditRecord, count: int) -> None:
    conn.execute(
        """
        INSERT INTO audit_chain_head (id, last_seq, last_hash, record_count, updated_at)
        VALUES (1, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            last_seq = excluded.last_seq,
            last_hash = excluded.last_hash,
            record_count = excluded.record_count,
            updated_at = excluded.updated_at
        """,
        (
            record.seq,
            record.entry_hash,
            count,
            canonical_timestamp(record.timestamp),
        ),
    )


def _row_to_stored(row: sqlite3.Row) -> StoredRecord:
    """Rebuild an AuditRecord from a row without letting the row lie.

    The contract's own validators run during construction, so a row whose hashes
    disagree with its contents raises here. Verification catches that and
    reports it as a failure rather than propagating the exception, because a
    tampered row is a finding, not a crash.
    """
    record = AuditRecord(
        seq=row["seq"],
        timestamp=row["timestamp"],
        actor=Actor(
            type=row["actor_type"],
            id=row["actor_id"],
            role=row["actor_role"],
        ),
        action=row["action"],
        subject=Subject(kind=row["subject_kind"], id=row["subject_id"]),
        payload=json.loads(row["payload_json"]),
        payload_hash=row["payload_hash"],
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
    )
    return StoredRecord(
        record=record,
        payload_json=row["payload_json"],
        hash_algo=row["hash_algo"],
    )


def read_raw_range(
    conn: sqlite3.Connection, start: int = 0, end: int | None = None
) -> list[sqlite3.Row]:
    """Rows in seq order. Verification works from these, not from objects."""
    if end is None:
        return conn.execute(
            "SELECT * FROM audit_log WHERE seq >= ? ORDER BY seq ASC", (start,)
        ).fetchall()
    return conn.execute(
        "SELECT * FROM audit_log WHERE seq >= ? AND seq <= ? ORDER BY seq ASC", (start, end)
    ).fetchall()


def read_range(
    conn: sqlite3.Connection, start: int = 0, end: int | None = None
) -> list[StoredRecord]:
    return [_row_to_stored(row) for row in read_raw_range(conn, start, end)]


def read_one(conn: sqlite3.Connection, seq: int) -> StoredRecord | None:
    row = conn.execute("SELECT * FROM audit_log WHERE seq = ?", (seq,)).fetchone()
    return _row_to_stored(row) if row else None


def query(
    conn: sqlite3.Connection,
    *,
    action: str | None = None,
    actor_id: str | None = None,
    subject_kind: str | None = None,
    subject_id: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[sqlite3.Row]:
    """Filtered history for display.

    A filtered result is never verifiable: the links between its rows are
    absent. Callers must present it as history, not as attested history — see
    the `verifiable: false` marker in the router.
    """
    clauses: list[str] = []
    params: list[Any] = []
    for column, value in (
        ("action", action),
        ("actor_id", actor_id),
        ("subject_kind", subject_kind),
        ("subject_id", subject_id),
    ):
        if value is not None:
            clauses.append(f"{column} = ?")
            params.append(value)
    if since is not None:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until is not None:
        clauses.append("timestamp <= ?")
        params.append(until)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.extend([limit, offset])
    return conn.execute(
        f"SELECT * FROM audit_log {where} ORDER BY seq ASC LIMIT ? OFFSET ?", params
    ).fetchall()


def missing_triggers(conn: sqlite3.Connection) -> list[str]:
    """Append-only triggers that are no longer present."""
    return [name for name in APPEND_ONLY_TRIGGERS if not trigger_exists(conn, name)]


def canonical_payload(payload: dict[str, Any]) -> str:
    """Validate then canonicalise. The only route a payload takes to disk."""
    validate_json_native(payload)
    return canonical_json(payload)
