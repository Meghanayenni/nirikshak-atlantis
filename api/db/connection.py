"""SQLite connection management.

Standard-library `sqlite3` only — no ORM. The audit chain is an integrity
artefact, so the pragmas here are chosen for durability over throughput. The
volume is a handful of records per audit run; the cost of `synchronous=FULL` is
irrelevant at that scale and the cost of losing the last records to a power
failure is not.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

BUSY_TIMEOUT_MS = 5000


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open a connection with NIRIKSHAK's pragmas applied.

    `isolation_level=None` turns off the driver's implicit transaction handling
    so the append path can issue `BEGIN IMMEDIATE` itself — which it must, to
    take the write lock before reading the chain head.
    """
    conn = sqlite3.connect(
        str(db_path),
        isolation_level=None,
        timeout=BUSY_TIMEOUT_MS / 1000,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    # WAL lets readers query history while an audit run is appending.
    # It is unavailable for :memory: databases, which is harmless.
    conn.execute("PRAGMA journal_mode=WAL")
    # An audit log that loses its most recent records on power loss is not an
    # audit log. FULL is the correct trade at this volume.
    conn.execute("PRAGMA synchronous=FULL")

    return conn


@contextmanager
def immediate_transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block inside `BEGIN IMMEDIATE`, committing or rolling back whole.

    `IMMEDIATE` rather than the default deferred transaction: the append path
    reads the chain head and then extends it, so it must hold the write lock
    across both. With a deferred transaction two writers can read the same head,
    both compute the same next `seq`, and one discovers the collision only at
    INSERT — after doing all its work.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except Exception:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone()
    return row is not None


def trigger_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
    ).fetchone()
    return row is not None
