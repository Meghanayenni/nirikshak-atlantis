"""Detecting a stored file again, against a different set of packs (ADR 0067).

Ingestion decides a file's platform once, when it arrives. Bootstrapping a
platform changes the packs detection may consult, and the file the platform was
described from must then be decided again — by the same function, with the same
threshold and margin, and recorded in the same columns. Nothing here scores
differently from ingestion; it only runs the scoring later.

`preview` is the same run without writing, for every stored file. A pack that
would move a file already identified as another platform is refused before it
exists, rather than discovered afterwards in someone else's fleet.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from api.ingest import blobs, lines, vendor_detect
from api.ingest.device_identity import extract_identity
from api.ingest.packs import find_pack
from api.ingest.validate import decode
from api.models.ingestion import DetectionResult
from api.models.pack import VendorPack


@dataclass(frozen=True)
class StoredFile:
    file_id: str
    filename: str
    vendor: str | None
    os_family: str | None
    physical: tuple[str, ...]


def stored_file(conn: sqlite3.Connection, blob_root: Path, file_id: str) -> StoredFile | None:
    row = conn.execute(
        """
        SELECT cf.file_id, cf.detected_vendor, cf.detected_os_family,
               (SELECT original_filename FROM ingestion WHERE file_id = cf.file_id
                 ORDER BY received_at LIMIT 1) AS filename
        FROM config_file cf WHERE cf.file_id = ?
        """,
        (file_id,),
    ).fetchone()
    if row is None:
        return None
    text = decode(blobs.read(blob_root, file_id), min_printable=0.0).text
    return StoredFile(
        file_id=row["file_id"],
        filename=row["filename"] or "",
        vendor=row["detected_vendor"],
        os_family=row["detected_os_family"],
        physical=tuple(lines.split_lines(text)),
    )


def detect_stored(
    stored: StoredFile, packs: list[VendorPack], *, min_score: float, min_margin: float
) -> DetectionResult:
    return vendor_detect.detect_vendor(
        packs,
        list(stored.physical),
        filename=stored.filename,
        min_score=min_score,
        min_margin=min_margin,
    )


@dataclass(frozen=True)
class DetectionChange:
    """A stored file whose platform would change under a proposed pack set."""

    file_id: str
    filename: str
    before: str | None
    after: str | None


def _platform(vendor: str | None, os_family: str | None) -> str | None:
    return f"{vendor}/{os_family}" if vendor and os_family else None


def preview(
    conn: sqlite3.Connection,
    blob_root: Path,
    packs: list[VendorPack],
    *,
    min_score: float,
    min_margin: float,
) -> tuple[DetectionChange, ...]:
    """Every stored file whose detected platform would differ under `packs`."""
    changes: list[DetectionChange] = []
    for (file_id,) in conn.execute("SELECT file_id FROM config_file ORDER BY file_id"):
        stored = stored_file(conn, blob_root, file_id)
        if stored is None:  # pragma: no cover - selected from the same table
            continue
        result = detect_stored(stored, packs, min_score=min_score, min_margin=min_margin)
        before = _platform(stored.vendor, stored.os_family)
        after = _platform(result.vendor, result.os_family)
        if before != after:
            changes.append(DetectionChange(file_id, stored.filename, before, after))
    return tuple(changes)


def record(
    conn: sqlite3.Connection,
    blob_root: Path,
    file_id: str,
    packs: list[VendorPack],
    *,
    min_score: float,
    min_margin: float,
) -> DetectionResult:
    """Detect one stored file again and write the result where ingestion wrote it."""
    stored = stored_file(conn, blob_root, file_id)
    if stored is None:
        raise KeyError(file_id)
    result = detect_stored(stored, packs, min_score=min_score, min_margin=min_margin)

    pack = find_pack(result.vendor, result.os_family, packs)
    identity = (
        extract_identity(pack, list(stored.physical), file_id=file_id, file_path=stored.filename)
        if pack is not None
        else None
    )
    known = identity.known_fields() if identity is not None else {}

    # Autocommit connection (api/db/connection.py): the two rows change
    # together or not at all, as ingestion writes them.
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            """
            UPDATE config_file
               SET detected_vendor = ?, detected_os_family = ?, detection_score = ?,
                   detection_margin = ?, detection_reason = ?, detection_evidence = ?
             WHERE file_id = ?
            """,
            (
                result.vendor,
                result.os_family,
                result.score,
                result.margin,
                str(result.outcome),
                json.dumps(
                    [
                        {
                            "vendor": c.vendor,
                            "os_family": c.os_family,
                            "score": c.score,
                            "hits": [{"pattern": h.pattern, "line": h.line_number} for h in c.hits],
                        }
                        for c in result.candidates
                    ]
                ),
                file_id,
            ),
        )
        conn.execute(
            """
            UPDATE device SET vendor = ?, os_family = ?, hostname = ?, os_version = ?, model = ?
             WHERE file_id = ?
            """,
            (
                result.vendor,
                result.os_family,
                known.get("hostname"),
                known.get("os_version"),
                known.get("model"),
                file_id,
            ),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return result
