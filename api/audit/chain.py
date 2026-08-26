"""Appending to the audit chain.

Every AI suggestion, human correction, pack change and audit result enters here.
The chain is inherently serial — each record's `prev_hash` depends on its
predecessor — so a writer lock is the correct shape rather than a scalability
compromise.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime
from typing import Any

from api.audit import store
from api.audit.errors import ChainIntegrityError
from api.db.connection import immediate_transaction
from api.models import (
    GENESIS_HASH,
    Actor,
    ActorType,
    AuditAction,
    AuditRecord,
    Subject,
)


class AuditChain:
    """Append-only writer over one SQLite connection.

    The lock is per-instance and in-process: it spares the common case a round
    trip through SQLITE_BUSY. Correctness across processes rests on
    `BEGIN IMMEDIATE` and the primary key, not on this lock.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.Lock()

    # -- append ------------------------------------------------------------

    def append(
        self,
        *,
        actor: Actor,
        action: AuditAction,
        subject: Subject,
        payload: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> AuditRecord:
        """Add one record, atomically, and return it.

        The insert and the head update share a single transaction, so an
        interrupted write leaves either both or neither. There is no window in
        which the log and the head can disagree because of this code path.
        """
        payload = payload or {}

        # D2 — refuse non-JSON-native values before anything is hashed, so a
        # str() fallback can never decide what a record attests to.
        payload_json = store.canonical_payload(payload)

        when = timestamp or datetime.now(UTC)

        with self._lock, immediate_transaction(self._conn):
            head = store.read_head(self._conn)
            if head is None:
                seq, prev_hash = 0, GENESIS_HASH
                count = 1
            else:
                seq, prev_hash = head.last_seq + 1, head.last_hash
                count = head.record_count + 1

            record = AuditRecord(
                seq=seq,
                timestamp=when,
                actor=actor,
                action=action,
                subject=subject,
                payload=payload,
                prev_hash=prev_hash,
            )

            store.insert_record(self._conn, record, payload_json)
            store.upsert_head(self._conn, record, count)

        return record

    # -- convenience -------------------------------------------------------

    def append_system(
        self,
        action: AuditAction,
        subject: Subject,
        payload: dict[str, Any] | None = None,
        *,
        actor_id: str = "nirikshak",
    ) -> AuditRecord:
        return self.append(
            actor=Actor(type=ActorType.SYSTEM, id=actor_id),
            action=action,
            subject=subject,
            payload=payload,
        )

    def head(self) -> store.ChainHead | None:
        return store.read_head(self._conn)

    def length(self) -> int:
        return store.record_count(self._conn)

    # -- startup reconciliation -------------------------------------------

    def reconcile_head(self, *, allow_forward_repair: bool = True) -> str:
        """Compare the head against the log after a crash or a restore.

        The two directions are treated asymmetrically on purpose. A head that
        lags the log can be rebuilt forward, because the evidence still exists.
        A head that runs *ahead* of the log means records are missing, and
        rebuilding it backwards would erase the only signal that they ever
        existed — so the system refuses and reports instead.
        """
        head = store.read_head(self._conn)
        top = store.max_seq(self._conn)

        if head is None and top is None:
            return "empty"
        if head is None:
            raise ChainIntegrityError(
                f"audit_chain_head is missing while the log holds records up to "
                f"seq {top}; refusing to reconstruct it silently"
            )
        if top is None:
            raise ChainIntegrityError(
                f"audit_chain_head claims {head.record_count} records up to seq "
                f"{head.last_seq}, but the log is empty — the chain has been truncated"
            )

        if head.last_seq > top:
            raise ChainIntegrityError(
                f"audit_chain_head is ahead of the log (head seq {head.last_seq}, "
                f"log seq {top}); records are missing and will not be papered over"
            )

        if head.last_seq < top:
            if not allow_forward_repair:
                raise ChainIntegrityError(
                    f"audit_chain_head lags the log (head {head.last_seq}, log {top})"
                )
            last = store.read_one(self._conn, top)
            if last is None:  # pragma: no cover - guarded by max_seq
                raise ChainIntegrityError("log tail vanished during reconciliation")
            with immediate_transaction(self._conn):
                store.upsert_head(self._conn, last.record, store.record_count(self._conn))
            return "repaired_forward"

        return "consistent"
