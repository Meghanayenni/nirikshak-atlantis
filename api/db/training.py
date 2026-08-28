"""SQL for the training queue and the decisions made on it.

No clustering, no compiling, no policy — those belong to `api/train/`. This
module moves rows, and its one editorial opinion is stated in the migration: the
text it stores is always the scrubbed text, because everything here can end up in
front of a person or inside an embedding model.

Mirrors `api/db/findings.py` in shape: plain functions over a connection, no ORM,
no session object, and the caller owns the transaction.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

from api.models.csm import UnknownLine
from api.models.enums import ExampleSource, TrainingOutcome
from api.models.training import Suggestion, TrainingExample


def record_unknown_lines(
    conn: sqlite3.Connection,
    lines: tuple[UnknownLine, ...],
    *,
    signatures: dict[int, str],
    cluster_ids: dict[int, str],
    vendor: str | None = None,
    os_family: str | None = None,
) -> int:
    """Persist one file's residue as queue entries.

    `signatures` and `cluster_ids` are keyed by line number and supplied by the
    caller: computing them needs `api/learn/`, which this layer must not import.

    `INSERT OR REPLACE` because re-auditing the same file after activating a pack
    is the normal case, and the residue for that file is then genuinely different
    — smaller, if the confirmation did its job.
    """
    now = datetime.now(UTC).isoformat()
    written = 0
    for line in lines:
        conn.execute(
            """
            INSERT OR REPLACE INTO unknown_line (
                file_id, line_number, text_scrubbed, signature, cluster_id,
                block_path, vendor, os_family, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                line.file_id,
                line.line_number,
                line.raw_line_scrubbed,
                signatures.get(line.line_number, ""),
                cluster_ids.get(line.line_number, ""),
                json.dumps(list(line.block_path)),
                vendor,
                os_family,
                now,
            ),
        )
        written += 1
    return written


def clear_unknown_lines(conn: sqlite3.Connection, file_id: str) -> int:
    """Drop a file's queue entries — used before recording a fresh parse.

    Without this, a line recognised by a newly activated pack would linger in the
    queue forever: the re-parse simply would not mention it, and `INSERT OR
    REPLACE` cannot delete what it is not told about. A queue that never shrinks
    would make the whole loop look ineffective while it was working.
    """
    cursor = conn.execute("DELETE FROM unknown_line WHERE file_id = ?", (file_id,))
    return cursor.rowcount


def unknown_lines(
    conn: sqlite3.Connection,
    *,
    file_id: str | None = None,
    vendor: str | None = None,
    limit: int = 5000,
) -> tuple[UnknownLine, ...]:
    """The queue, as `UnknownLine` contracts, in file and line order."""
    clauses: list[str] = []
    params: list[object] = []
    if file_id is not None:
        clauses.append("file_id = ?")
        params.append(file_id)
    if vendor is not None:
        clauses.append("vendor = ?")
        params.append(vendor)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)

    rows = conn.execute(
        f"SELECT * FROM unknown_line {where} ORDER BY file_id, line_number LIMIT ?",
        params,
    ).fetchall()

    return tuple(
        UnknownLine(
            line_number=row["line_number"],
            raw_line_scrubbed=row["text_scrubbed"],
            normalised_line=row["signature"],
            file_id=row["file_id"],
            block_path=tuple(json.loads(row["block_path"])),
        )
        for row in rows
    )


def queue_size(conn: sqlite3.Connection, *, file_id: str | None = None) -> int:
    if file_id is None:
        return conn.execute("SELECT COUNT(*) AS c FROM unknown_line").fetchone()["c"]
    return conn.execute(
        "SELECT COUNT(*) AS c FROM unknown_line WHERE file_id = ?", (file_id,)
    ).fetchone()["c"]


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def save_example(conn: sqlite3.Connection, example: TrainingExample) -> None:
    """Record one administrator decision.

    A plain INSERT, not an upsert. A decision is an event that happened at a
    moment, by a named person; overwriting one would rewrite history in a table
    the audit chain attests to.
    """
    conn.execute(
        """
        INSERT INTO training_example (
            example_id, vendor, os_family, raw_line_scrubbed, normalised_line,
            cluster_id, field, value_semantics, suggestions_json, outcome,
            confirmed_by, confirmed_at, source, audit_seq
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            example.example_id,
            example.vendor,
            example.os_family,
            example.raw_line_scrubbed,
            example.normalised_line,
            example.cluster_id,
            example.field,
            example.value_semantics,
            json.dumps([s.model_dump(mode="json") for s in example.suggestions_shown]),
            str(example.outcome),
            example.confirmed_by,
            example.confirmed_at.isoformat() if example.confirmed_at else None,
            str(example.source),
            example.audit_seq,
        ),
    )


def _row_to_example(row: sqlite3.Row) -> TrainingExample:
    return TrainingExample(
        example_id=row["example_id"],
        vendor=row["vendor"],
        os_family=row["os_family"],
        raw_line_scrubbed=row["raw_line_scrubbed"],
        normalised_line=row["normalised_line"],
        cluster_id=row["cluster_id"],
        field=row["field"],
        value_semantics=row["value_semantics"],
        suggestions_shown=tuple(
            Suggestion(**s) for s in json.loads(row["suggestions_json"] or "[]")
        ),
        outcome=TrainingOutcome(row["outcome"]),
        confirmed_by=row["confirmed_by"],
        confirmed_at=row["confirmed_at"],
        source=ExampleSource(row["source"]),
        audit_seq=row["audit_seq"],
    )


def read_example(conn: sqlite3.Connection, example_id: str) -> TrainingExample | None:
    row = conn.execute(
        "SELECT * FROM training_example WHERE example_id = ?", (example_id,)
    ).fetchone()
    return _row_to_example(row) if row else None


def examples(
    conn: sqlite3.Connection,
    *,
    vendor: str | None = None,
    os_family: str | None = None,
    confirmed_only: bool = False,
    limit: int = 1000,
) -> tuple[TrainingExample, ...]:
    """Recorded decisions, oldest first.

    `confirmed_only` excludes rejections, which is what the similarity index
    wants: a line an administrator judged not security relevant is a real
    decision worth keeping, and is not a labelled example of anything.
    """
    clauses: list[str] = []
    params: list[object] = []
    if vendor is not None:
        clauses.append("vendor = ?")
        params.append(vendor)
    if os_family is not None:
        clauses.append("os_family = ?")
        params.append(os_family)
    if confirmed_only:
        clauses.append("field IS NOT NULL")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)

    rows = conn.execute(
        f"SELECT * FROM training_example {where} ORDER BY rowid ASC LIMIT ?", params
    ).fetchall()
    return tuple(_row_to_example(row) for row in rows)


def example_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) AS c FROM training_example").fetchone()["c"]
