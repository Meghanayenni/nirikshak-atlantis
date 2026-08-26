"""HTTP surface for configuration ingestion.

Upload is the one write this API accepts, and it writes configuration data —
never audit records directly. The chain is appended by the service that did the
work, so the log attests to what the system did rather than to what a client
claimed.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile

from api.audit.chain import AuditChain
from api.config import settings
from api.db.connection import connect, table_exists
from api.ingest import line_cache
from api.ingest.service import IngestionLimits, IngestionService, UploadedFile

router = APIRouter(prefix="/ingest", tags=["ingest"])


def limits_from_settings() -> IngestionLimits:
    return IngestionLimits(
        max_file_bytes=settings.max_file_bytes,
        max_batch_files=settings.max_batch_files,
        max_batch_bytes=settings.max_batch_bytes,
        max_archive_entries=settings.max_archive_entries,
        max_archive_uncompressed_bytes=settings.max_archive_uncompressed_bytes,
        max_compression_ratio=settings.max_compression_ratio,
        min_printable_ratio=settings.min_printable_ratio,
        detection_min_score=settings.detection_min_score,
        detection_min_margin=settings.detection_min_margin,
    )


def get_conn() -> Any:
    conn = connect(settings.db_path)
    try:
        if not table_exists(conn, "config_file"):
            raise HTTPException(status_code=503, detail="operational store is not initialised")
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


@router.post("/upload")
async def upload(conn: Conn, files: list[UploadFile]) -> dict[str, Any]:
    """Ingest one or more configuration files, or a ZIP of them.

    Returns a per-file result. A malformed or binary file is reported alongside
    the successes rather than failing the batch.
    """
    if not files:
        raise HTTPException(status_code=400, detail="no files supplied")

    uploads: list[UploadedFile] = []
    total = 0
    for item in files:
        data = await item.read()
        total += len(data)
        if total > settings.max_batch_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"batch exceeds {settings.max_batch_bytes:,} bytes",
            )
        uploads.append(UploadedFile(filename=item.filename or "unnamed", data=data))

    audit_conn = connect(settings.audit_db_path)
    try:
        service = IngestionService(
            conn,
            AuditChain(audit_conn),
            blob_root=settings.blob_root,
            limits=limits_from_settings(),
        )
        batch = service.ingest_batch(uploads)
    finally:
        audit_conn.close()

    return {
        "batch_id": batch.batch_id,
        "summary": batch.summary(),
        "accepted": [
            {
                "file_id": f.file_id,
                "filename": f.original_filename,
                "size_bytes": f.size_bytes,
                "line_count": f.line_count,
                "encoding": f.encoding,
                "format": str(f.file_format),
                "duplicate": f.duplicate_of_existing,
                "detection": {
                    "outcome": str(f.detection.outcome),
                    "vendor": f.detection.vendor,
                    "os_family": f.detection.os_family,
                    "score": f.detection.score,
                    "margin": f.detection.margin,
                    "explanation": f.detection.explain(),
                },
                "identity": f.identity.known_fields(),
            }
            for f in batch.accepted
        ],
        "rejected": [
            {
                "filename": r.original_filename,
                "reason": str(r.reason),
                "detail": r.detail,
                "size_bytes": r.size_bytes,
            }
            for r in batch.rejected
        ],
    }


@router.get("/files")
def list_files(
    conn: Conn,
    vendor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    clause, params = "", []
    if vendor is not None:
        clause = "WHERE detected_vendor = ?"
        params.append(vendor)
    params.append(limit)

    rows = conn.execute(
        f"SELECT * FROM config_file {clause} ORDER BY first_seen_at DESC LIMIT ?", params
    ).fetchall()
    return {
        "count": len(rows),
        "files": [
            {
                "file_id": r["file_id"],
                "size_bytes": r["size_bytes"],
                "line_count": r["line_count"],
                "encoding": r["encoding"],
                "format": r["file_format"],
                "vendor": r["detected_vendor"],
                "os_family": r["detected_os_family"],
                "detection_reason": r["detection_reason"],
                "detection_score": r["detection_score"],
            }
            for r in rows
        ],
    }


@router.get("/files/{file_id}/lines")
def file_lines(
    conn: Conn,
    file_id: str,
    start: Annotated[int, Query(ge=1)] = 1,
    count: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Lines with their exact numbers — the same numbers evidence cites."""
    records = line_cache.read_lines(conn, file_id)
    if not records:
        raise HTTPException(status_code=404, detail="no such file, or it has no lines")
    window = [r for r in records if start <= r.line_number < start + count]
    return {
        "file_id": file_id,
        "total_lines": len(records),
        "lines": [
            {"line_number": r.line_number, "text": r.text, "sha256": r.line_sha256} for r in window
        ],
    }


@router.get("/devices")
def list_devices(conn: Conn) -> dict[str, Any]:
    rows = conn.execute("SELECT * FROM device ORDER BY hostname IS NULL, hostname").fetchall()
    return {
        "count": len(rows),
        "devices": [
            {
                "device_id": r["device_id"],
                "hostname": r["hostname"],
                "vendor": r["vendor"],
                "os_family": r["os_family"],
                "os_version": r["os_version"],
                "model": r["model"],
            }
            for r in rows
        ],
    }


@router.get("/stats")
def stats(conn: Conn) -> dict[str, Any]:
    """Fleet-wide line-cache effectiveness — the deduplication claim, measured."""
    return line_cache.cache_stats(conn)
