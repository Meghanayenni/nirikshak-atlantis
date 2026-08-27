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
from api.routers.deps import AdminUser, CurrentUser, owner_filter, require_access

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
async def upload(conn: Conn, user: CurrentUser, files: list[UploadFile]) -> dict[str, Any]:
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
            owner_id=user.user_id,
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
    user: CurrentUser,
    vendor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    # A user sees only files they uploaded; an admin sees the fleet. The join is
    # through `ingestion`, because config_file is content-addressed and shared:
    # two people uploading the same configuration share one row.
    conditions, params = [], []
    if vendor is not None:
        conditions.append("cf.detected_vendor = ?")
        params.append(vendor)

    owner = owner_filter(user)
    if owner is not None:
        conditions.append(
            "EXISTS (SELECT 1 FROM ingestion i WHERE i.file_id = cf.file_id AND i.owner_id = ?)"
        )
        params.append(owner)

    clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)

    rows = conn.execute(
        f"SELECT cf.* FROM config_file cf {clause} ORDER BY cf.first_seen_at DESC LIMIT ?",
        params,
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
    user: CurrentUser,
    file_id: str,
    start: Annotated[int, Query(ge=1)] = 1,
    count: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict[str, Any]:
    """Lines with their exact numbers — the same numbers evidence cites."""
    # Authorised before a single line is read: raw configuration is the most
    # sensitive thing this API serves, and the Concept Report separates access to
    # it from access to findings.
    owned = conn.execute(
        "SELECT owner_id FROM ingestion WHERE file_id = ? ORDER BY received_at LIMIT 1",
        (file_id,),
    ).fetchone()
    require_access(user, exists=owned is not None, owner_id=owned["owner_id"] if owned else None)

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
def list_devices(conn: Conn, user: CurrentUser) -> dict[str, Any]:
    owner = owner_filter(user)
    if owner is None:
        rows = conn.execute("SELECT * FROM device ORDER BY hostname IS NULL, hostname").fetchall()
    else:
        rows = conn.execute(
            "SELECT d.* FROM device d WHERE EXISTS ("
            "  SELECT 1 FROM ingestion i WHERE i.file_id = d.file_id AND i.owner_id = ?"
            ") ORDER BY d.hostname IS NULL, d.hostname",
            (owner,),
        ).fetchall()
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
def stats(conn: Conn, admin: AdminUser) -> dict[str, Any]:
    """Fleet-wide line-cache effectiveness — the deduplication claim, measured.

    Admin-only: the numbers describe the whole estate, so serving them to a user
    who can see one device would leak the size and shape of everyone else's.
    """
    return line_cache.cache_stats(conn)
