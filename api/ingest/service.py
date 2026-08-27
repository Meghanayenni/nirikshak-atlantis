"""Ingestion orchestration.

One file at a time, each in its own transaction, each producing exactly one
audit record. A refusal is a first-class outcome rather than an exception that
aborts the batch: one unreadable file in fifty must not cost the operator the
other forty-nine.

What this module deliberately does not do: parse security fields, build a
canonical model, decide anything, or reach the network. Those boundaries are
asserted by architecture tests rather than left to good intentions.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from api.audit.chain import AuditChain
from api.ingest import archive, blobs, format_detect, line_cache, lines, packs, vendor_detect
from api.ingest.device_identity import extract_identity
from api.ingest.validate import ValidationError, check_size, decode
from api.models import Actor, ActorType, AuditAction, Subject
from api.models.ingestion import (
    DetectedDeviceIdentity,
    DetectionResult,
    IngestedFile,
    IngestionBatch,
    IngestionRejection,
    IngestionStatus,
    RejectionReason,
)
from api.models.pack import VendorPack


@dataclass(frozen=True)
class IngestionLimits:
    max_file_bytes: int
    max_batch_files: int
    max_batch_bytes: int
    max_archive_entries: int
    max_archive_uncompressed_bytes: int
    max_compression_ratio: int
    min_printable_ratio: float
    detection_min_score: float
    detection_min_margin: float


@dataclass(frozen=True)
class UploadedFile:
    """One file as received, before anything is known about it."""

    filename: str
    data: bytes


class IngestionService:
    """Ingests configuration files. Holds no state between batches."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        chain: AuditChain,
        *,
        blob_root: Path,
        limits: IngestionLimits,
        available_packs: list[VendorPack] | None = None,
        actor: Actor | None = None,
        owner_id: str | None = None,
    ) -> None:
        self._conn = conn
        self._chain = chain
        self._blob_root = blob_root
        self._limits = limits
        self._packs = available_packs if available_packs is not None else packs.load_active_packs()
        self._actor = actor or Actor(type=ActorType.SYSTEM, id="ingest")
        # Who uploaded this (decision D25). Recorded on the ingestion row rather
        # than on config_file, because the file is content-addressed: the same
        # configuration uploaded by two people is one file and two ingestions.
        # None means an unowned upload, which only an admin may then see.
        self._owner_id = owner_id

    # -- public -----------------------------------------------------------

    def ingest_batch(self, uploads: list[UploadedFile]) -> IngestionBatch:
        """Ingest every file, expanding archives, and never aborting on one bad file."""
        batch_id = uuid.uuid4().hex
        expanded, rejected = self._expand(batch_id, uploads)

        if len(expanded) > self._limits.max_batch_files:
            rejected.append(
                IngestionRejection(
                    original_filename=f"<batch {batch_id[:8]}>",
                    reason=RejectionReason.BATCH_LIMIT_EXCEEDED,
                    detail=(
                        f"{len(expanded)} files exceeds the batch limit of "
                        f"{self._limits.max_batch_files}"
                    ),
                )
            )
            expanded = []

        accepted: list[IngestedFile] = []
        for item in expanded:
            try:
                accepted.append(self._ingest_one(batch_id, item))
            except ValidationError as exc:
                rejected.append(self._reject(batch_id, item, exc))

        return IngestionBatch(batch_id=batch_id, accepted=tuple(accepted), rejected=tuple(rejected))

    # -- stages -----------------------------------------------------------

    def _expand(
        self, batch_id: str, uploads: list[UploadedFile]
    ) -> tuple[list[UploadedFile], list[IngestionRejection]]:
        """Replace archives with their members; keep plain files as they are."""
        out: list[UploadedFile] = []
        rejected: list[IngestionRejection] = []

        for upload in uploads:
            if not archive.looks_like_zip(upload.data):
                out.append(upload)
                continue
            try:
                members = archive.extract(
                    upload.data,
                    max_entries=self._limits.max_archive_entries,
                    max_total_bytes=self._limits.max_archive_uncompressed_bytes,
                    max_entry_bytes=self._limits.max_file_bytes,
                    max_ratio=self._limits.max_compression_ratio,
                )
            except ValidationError as exc:
                # Audited like any other refusal. A Zip Slip or a compression
                # bomb is exactly the kind of attempt worth keeping a record of,
                # so archive-level rejections take the same path as file-level
                # ones rather than being reported and forgotten.
                rejected.append(self._reject(batch_id, upload, exc))
                continue
            out.extend(UploadedFile(filename=m.name, data=m.data) for m in members)

        return out, rejected

    def _ingest_one(self, batch_id: str, upload: UploadedFile) -> IngestedFile:
        limits = self._limits

        check_size(len(upload.data), max_bytes=limits.max_file_bytes, filename=upload.filename)

        file_id = blobs.sha256_bytes(upload.data)
        decoded = decode(upload.data, min_printable=limits.min_printable_ratio)
        file_format = format_detect.detect(decoded.text)

        physical = lines.split_lines(decoded.text)
        records = lines.line_records(decoded.text)

        detection = vendor_detect.detect_vendor(
            self._packs,
            physical,
            filename=upload.filename,
            min_score=limits.detection_min_score,
            min_margin=limits.detection_min_margin,
        )

        pack = packs.find_pack(detection.vendor, detection.os_family, self._packs)
        identity = (
            extract_identity(
                pack,
                physical,
                file_id=file_id,
                file_path=upload.filename,
                source_type=file_format.to_source_type(),
            )
            if pack is not None
            else DetectedDeviceIdentity()
        )

        already = self._conn.execute(
            "SELECT 1 FROM config_file WHERE file_id = ?", (file_id,)
        ).fetchone()
        duplicate = already is not None

        path = blobs.store(self._blob_root, file_id, upload.data)

        ingested = IngestedFile(
            file_id=file_id,
            original_filename=upload.filename,
            size_bytes=len(upload.data),
            line_count=len(records),
            encoding=decoded.encoding,
            file_format=file_format,
            detection=detection,
            identity=identity,
            blob_path=blobs.relative(self._blob_root, path),
            ingested_at=datetime.now(UTC),
            duplicate_of_existing=duplicate,
        )

        self._persist(batch_id, ingested, records, identity, detection)

        # Audit last: a record is written only for work that actually committed.
        self._chain.append(
            actor=self._actor,
            action=AuditAction.FILE_INGESTED,
            subject=Subject(kind="file", id=file_id),
            payload=ingested.audit_payload(),
        )
        return ingested

    def _persist(
        self,
        batch_id: str,
        ingested: IngestedFile,
        records: list,
        identity: DetectedDeviceIdentity,
        detection: DetectionResult,
    ) -> None:
        import json

        now = datetime.now(UTC).isoformat()
        conn = self._conn

        conn.execute("BEGIN IMMEDIATE")
        try:
            if not ingested.duplicate_of_existing:
                conn.execute(
                    """
                    INSERT INTO config_file (
                        file_id, size_bytes, line_count, encoding, file_format, blob_path,
                        detected_vendor, detected_os_family, detection_score,
                        detection_margin, detection_reason, detection_evidence, first_seen_at
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ingested.file_id,
                        ingested.size_bytes,
                        ingested.line_count,
                        ingested.encoding,
                        str(ingested.file_format),
                        ingested.blob_path,
                        detection.vendor,
                        detection.os_family,
                        detection.score,
                        detection.margin,
                        str(detection.outcome),
                        json.dumps(
                            [
                                {
                                    "vendor": c.vendor,
                                    "os_family": c.os_family,
                                    "score": c.score,
                                    "hits": [
                                        {"pattern": h.pattern, "line": h.line_number}
                                        for h in c.hits
                                    ],
                                }
                                for c in detection.candidates
                            ]
                        ),
                        now,
                    ),
                )
                line_cache.store_lines(conn, ingested.file_id, records)

                known = identity.known_fields()
                conn.execute(
                    """
                    INSERT INTO device (
                        device_id, file_id, hostname, vendor, os_family,
                        os_version, model, serial, peer_group, identity_evidence
                    ) VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ingested.file_id,
                        ingested.file_id,
                        known.get("hostname"),
                        detection.vendor,
                        detection.os_family,
                        known.get("os_version"),
                        known.get("model"),
                        known.get("serial"),
                        None,
                        json.dumps(
                            {
                                name: [e.cite() for e in field.evidence]
                                for name, field in (
                                    ("hostname", identity.hostname),
                                    ("model", identity.model),
                                    ("os_version", identity.os_version),
                                    ("serial", identity.serial),
                                )
                                if field is not None and field.evidence
                            }
                        ),
                    ),
                )

            conn.execute(
                """
                INSERT INTO ingestion (
                    ingestion_id, batch_id, original_filename, file_id,
                    status, reason, size_bytes, received_at, owner_id
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    batch_id,
                    ingested.original_filename,
                    ingested.file_id,
                    str(ingested.status),
                    None,
                    ingested.size_bytes,
                    now,
                    self._owner_id,
                ),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def _reject(
        self, batch_id: str, upload: UploadedFile, exc: ValidationError
    ) -> IngestionRejection:
        rejection = IngestionRejection(
            original_filename=upload.filename,
            reason=exc.reason,
            detail=exc.detail,
            size_bytes=len(upload.data),
            sha256=blobs.sha256_bytes(upload.data) if upload.data else None,
        )

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                """
                INSERT INTO ingestion (
                    ingestion_id, batch_id, original_filename, file_id,
                    status, reason, size_bytes, received_at, owner_id
                ) VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    uuid.uuid4().hex,
                    batch_id,
                    upload.filename,
                    None,
                    IngestionStatus.REJECTED.value,
                    str(exc.reason),
                    len(upload.data),
                    datetime.now(UTC).isoformat(),
                    self._owner_id,
                ),
            )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

        # A refusal is recorded as FILE_REJECTED (decision D5), never as an
        # ingestion — the audit trail must not describe a refusal as a success.
        self._chain.append(
            actor=self._actor,
            action=AuditAction.FILE_REJECTED,
            subject=Subject(kind="file", id=rejection.sha256 or upload.filename),
            payload=rejection.audit_payload(),
        )
        return rejection
