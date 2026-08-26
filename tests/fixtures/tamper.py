"""Helpers for building chains and damaging them in specific ways.

Every mutation here drops the append-only triggers first, then restores them.
That is the only way to simulate an attacker who has database access rather than
application access — which is precisely the adversary the chain is meant to
leave evidence against.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from api.audit.chain import AuditChain
from api.db.connection import connect
from api.db.migrate import migrate
from api.models import Actor, ActorType, AuditAction, Subject

TRIGGER_SQL = {
    "audit_log_no_update": (
        "CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log "
        "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"
    ),
    "audit_log_no_delete": (
        "CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log "
        "BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END"
    ),
}


def new_db(tmp_path: Path, name: str = "audit.db") -> sqlite3.Connection:
    """A migrated, empty database."""
    conn = connect(tmp_path / name)
    migrate(conn)
    return conn


def build_chain(conn: sqlite3.Connection, count: int = 5) -> AuditChain:
    """Append `count` plausible records with distinct timestamps."""
    chain = AuditChain(conn)
    base = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)

    for index in range(count):
        chain.append(
            actor=Actor(type=ActorType.HUMAN, id="admin@ntro", role="administrator"),
            action=AuditAction.PACK_ACTIVATED,
            subject=Subject(kind="vendor_pack", id=f"acme/acme-os@1.{index}.0"),
            payload={"from": f"1.{index}.0", "to": f"1.{index + 1}.0", "index": index},
            timestamp=base + timedelta(minutes=index),
        )
    return chain


def drop_triggers(conn: sqlite3.Connection) -> None:
    for name in TRIGGER_SQL:
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")


def restore_triggers(conn: sqlite3.Connection) -> None:
    for name, sql in TRIGGER_SQL.items():
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")
        conn.execute(sql)


class database_access:  # noqa: N801 - reads as a context manager, not a class
    """Temporarily remove the append-only guards, as an attacker would have to."""

    def __init__(self, conn: sqlite3.Connection, *, restore: bool = True) -> None:
        self.conn = conn
        self.restore = restore

    def __enter__(self) -> sqlite3.Connection:
        drop_triggers(self.conn)
        return self.conn

    def __exit__(self, *exc: object) -> None:
        if self.restore:
            restore_triggers(self.conn)


# --- individual mutations -------------------------------------------------


def modify_payload(conn: sqlite3.Connection, seq: int) -> None:
    with database_access(conn) as c:
        c.execute(
            "UPDATE audit_log SET payload_json = ? WHERE seq = ?",
            ('{"from":"1.0.0","index":0,"to":"9.9.9"}', seq),
        )


def modify_field(conn: sqlite3.Connection, seq: int, column: str, value: object) -> None:
    with database_access(conn) as c:
        c.execute(f"UPDATE audit_log SET {column} = ? WHERE seq = ?", (value, seq))


def delete_record(conn: sqlite3.Connection, seq: int) -> None:
    with database_access(conn) as c:
        c.execute("DELETE FROM audit_log WHERE seq = ?", (seq,))


def delete_all_records(conn: sqlite3.Connection, *, also_head: bool = False) -> None:
    with database_access(conn) as c:
        c.execute("DELETE FROM audit_log")
        if also_head:
            c.execute("DELETE FROM audit_chain_head")


def swap_seq(conn: sqlite3.Connection, a: int, b: int) -> None:
    with database_access(conn) as c:
        spare = 10_000_000
        c.execute("UPDATE audit_log SET seq = ? WHERE seq = ?", (spare, a))
        c.execute("UPDATE audit_log SET seq = ? WHERE seq = ?", (a, b))
        c.execute("UPDATE audit_log SET seq = ? WHERE seq = ?", (b, spare))


def swap_payloads(conn: sqlite3.Connection, a: int, b: int) -> None:
    with database_access(conn) as c:
        pa = c.execute("SELECT payload_json FROM audit_log WHERE seq = ?", (a,)).fetchone()[0]
        pb = c.execute("SELECT payload_json FROM audit_log WHERE seq = ?", (b,)).fetchone()[0]
        c.execute("UPDATE audit_log SET payload_json = ? WHERE seq = ?", (pb, a))
        c.execute("UPDATE audit_log SET payload_json = ? WHERE seq = ?", (pa, b))


def rewrite_prev_hash(conn: sqlite3.Connection, seq: int) -> None:
    with database_access(conn) as c:
        c.execute("UPDATE audit_log SET prev_hash = ? WHERE seq = ?", ("b" * 64, seq))


def recompute_whole_chain(conn: sqlite3.Connection, *, at_seq: int, new_payload: str) -> None:
    """Rewrite a record and rebuild every hash after it, consistently.

    This is the adversary an unkeyed chain cannot exclude: given database write
    access and the same public hash function, every link can be rebuilt so the
    result verifies. Used by the intentional non-detection fixture.
    """
    from api.models import Actor, AuditRecord, Subject
    from api.models.audit import canonical_timestamp

    with database_access(conn) as c:
        c.execute(
            "UPDATE audit_log SET payload_json = ?, payload_hash = ? WHERE seq = ?",
            (new_payload, hash_payload_of_string(new_payload), at_seq),
        )

        rows = c.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
        prev = None
        for row in rows:
            prev_hash = "0" * 64 if prev is None else prev
            entry = AuditRecord.compute_entry_hash(
                seq=row["seq"],
                timestamp=canonical_timestamp(row["timestamp"]),
                actor=Actor(
                    type=row["actor_type"], id=row["actor_id"], role=row["actor_role"]
                ).model_dump(mode="json"),
                action=row["action"],
                subject=Subject(kind=row["subject_kind"], id=row["subject_id"]).model_dump(
                    mode="json"
                ),
                payload_hash=row["payload_hash"],
                prev_hash=prev_hash,
            )
            c.execute(
                "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE seq = ?",
                (prev_hash, entry, row["seq"]),
            )
            prev = entry

        c.execute(
            "UPDATE audit_chain_head SET last_hash = ? WHERE id = 1",
            (prev,),
        )


def hash_payload_of_string(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()
