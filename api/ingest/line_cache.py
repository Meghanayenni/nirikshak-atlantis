"""The fleet-wide line cache.

The Concept Report asks that identical lines across a large estate be resolved
once. The structure that achieves that also guarantees exact evidence
reconstruction, so one mechanism does both jobs:

    config_line   (file_id, line_number) -> line_sha256     position -> content
    line_cache     line_sha256 -> text                      content -> text, once

Evidence for any citation resolves through both without opening the blob.
Deduplication falls out of the same tables. And at P4 the parse result attaches
to `line_sha256`, so a line repeated across four hundred devices is parsed once.

`occurrence_count` is incidentally the raw material for P12's peer-baseline
analysis — "forty-seven switches have this line and three do not" is a query
over this table.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from api.models.ingestion import LineRecord


def store_lines(conn: sqlite3.Connection, file_id: str, records: list[LineRecord]) -> int:
    """Record a file's lines and fold them into the fleet cache.

    Returns the number of line texts that were new to the fleet — the useful
    half of the caching claim, and worth reporting rather than assuming.
    """
    now = datetime.now(UTC).isoformat()
    new_texts = 0

    for record in records:
        existing = conn.execute(
            "SELECT 1 FROM line_cache WHERE line_sha256 = ?", (record.line_sha256,)
        ).fetchone()

        if existing is None:
            conn.execute(
                "INSERT INTO line_cache (line_sha256, text, occurrence_count, first_seen_at) "
                "VALUES (?, ?, 1, ?)",
                (record.line_sha256, record.text, now),
            )
            new_texts += 1
        else:
            conn.execute(
                "UPDATE line_cache SET occurrence_count = occurrence_count + 1 "
                "WHERE line_sha256 = ?",
                (record.line_sha256,),
            )

        conn.execute(
            "INSERT OR REPLACE INTO config_line (file_id, line_number, line_sha256) "
            "VALUES (?, ?, ?)",
            (file_id, record.line_number, record.line_sha256),
        )

    return new_texts


def read_lines(conn: sqlite3.Connection, file_id: str) -> list[LineRecord]:
    """Every line of a file, in order, resolved through the cache."""
    rows = conn.execute(
        """
        SELECT cl.line_number, lc.text, cl.line_sha256
        FROM config_line cl
        JOIN line_cache lc ON lc.line_sha256 = cl.line_sha256
        WHERE cl.file_id = ?
        ORDER BY cl.line_number ASC
        """,
        (file_id,),
    ).fetchall()
    return [
        LineRecord(line_number=r["line_number"], text=r["text"], line_sha256=r["line_sha256"])
        for r in rows
    ]


def read_line(conn: sqlite3.Connection, file_id: str, line_number: int) -> LineRecord | None:
    """One line, for rendering a single citation."""
    row = conn.execute(
        """
        SELECT cl.line_number, lc.text, cl.line_sha256
        FROM config_line cl
        JOIN line_cache lc ON lc.line_sha256 = cl.line_sha256
        WHERE cl.file_id = ? AND cl.line_number = ?
        """,
        (file_id, line_number),
    ).fetchone()
    if row is None:
        return None
    return LineRecord(
        line_number=row["line_number"], text=row["text"], line_sha256=row["line_sha256"]
    )


def cache_stats(conn: sqlite3.Connection) -> dict[str, int]:
    """How much the fleet cache is actually saving."""
    distinct = conn.execute("SELECT COUNT(*) AS c FROM line_cache").fetchone()["c"]
    total = conn.execute("SELECT COUNT(*) AS c FROM config_line").fetchone()["c"]
    return {
        "distinct_lines": distinct,
        "total_line_positions": total,
        "deduplicated": total - distinct,
    }
