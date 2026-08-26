"""End-to-end ingestion: persistence, evidence, duplicates, audit, DB separation."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from api.audit.chain import AuditChain
from api.audit.verify import verify_chain
from api.db.connection import connect
from api.db.migrate import AUDIT_MIGRATIONS, OPERATIONAL_MIGRATIONS, migrate
from api.ingest import line_cache, lines
from api.ingest.packs import load_active_packs
from api.ingest.service import IngestionLimits, IngestionService, UploadedFile
from api.models import AuditAction
from api.models.ingestion import DetectionOutcome, RejectionReason
from tests.fixtures import configs

LIMITS = IngestionLimits(
    max_file_bytes=10 * 1024 * 1024,
    max_batch_files=500,
    max_batch_bytes=200 * 1024 * 1024,
    max_archive_entries=1000,
    max_archive_uncompressed_bytes=200 * 1024 * 1024,
    max_compression_ratio=100,
    min_printable_ratio=0.90,
    detection_min_score=0.60,
    detection_min_margin=0.25,
)


@dataclass
class Rig:
    service: IngestionService
    op: sqlite3.Connection
    audit: sqlite3.Connection
    op_path: Path
    audit_path: Path
    blob_root: Path


@pytest.fixture
def rig(tmp_path: Path) -> Rig:
    op_path, audit_path = tmp_path / "nirikshak.db", tmp_path / "nirikshak-audit.db"
    blob_root = tmp_path / "uploads"

    op = connect(op_path)
    migrate(op, OPERATIONAL_MIGRATIONS)
    audit = connect(audit_path)
    migrate(audit, AUDIT_MIGRATIONS)

    service = IngestionService(
        op,
        AuditChain(audit),
        blob_root=blob_root,
        limits=LIMITS,
        available_packs=load_active_packs(use_cache=False),
    )
    return Rig(service, op, audit, op_path, audit_path, blob_root)


def up(name: str, text: str) -> UploadedFile:
    return UploadedFile(filename=name, data=text.encode("utf-8"))


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_single_file_ingests(rig: Rig) -> None:
    batch = rig.service.ingest_batch([up("rtr.cfg", configs.CISCO_IOS)])

    assert len(batch.accepted) == 1
    assert not batch.rejected

    file = batch.accepted[0]
    assert file.detection.vendor == "cisco"
    assert file.identity.known_fields()["hostname"] == "rtr-test-01"
    assert file.line_count == lines.count_lines(configs.CISCO_IOS)


def test_bulk_upload_one_bad_file_does_not_fail_the_batch(rig: Rig) -> None:
    """Acceptance criterion 2 — forty-nine good files survive one bad one."""
    uploads = [
        up(f"good-{i}.cfg", configs.CISCO_IOS.replace("rtr-test-01", f"r{i}")) for i in range(10)
    ]
    uploads.append(UploadedFile(filename="evil.cfg", data=configs.PNG_BYTES))
    uploads.append(UploadedFile(filename="empty.cfg", data=b""))

    batch = rig.service.ingest_batch(uploads)

    assert len(batch.accepted) == 10
    assert len(batch.rejected) == 2
    assert {r.reason for r in batch.rejected} == {
        RejectionReason.BINARY_CONTENT,
        RejectionReason.EMPTY,
    }
    assert batch.total == 12


def test_batch_summary_counts_unknown_vendors(rig: Rig) -> None:
    batch = rig.service.ingest_batch(
        [up("a.cfg", configs.CISCO_IOS), up("b.cfg", configs.UNSUPPORTED_VENDOR)]
    )
    assert batch.identified == 1
    assert batch.unidentified == 1
    assert "1 identified" in batch.summary()


# ---------------------------------------------------------------------------
# Evidence preservation
# ---------------------------------------------------------------------------


def test_lines_reconstruct_exactly(rig: Rig) -> None:
    """Acceptance criterion 4 — the losslessness guarantee, one layer early."""
    text = configs.CISCO_IOS
    batch = rig.service.ingest_batch([up("rtr.cfg", text)])
    file_id = batch.accepted[0].file_id

    stored = line_cache.read_lines(rig.op, file_id)
    assert [r.text for r in stored] == lines.split_lines(text)
    assert lines.reconstruct([r.text for r in stored]) == text.rstrip("\n")


def test_line_numbers_survive_mixed_endings(rig: Rig) -> None:
    batch = rig.service.ingest_batch([up("mixed.cfg", configs.MIXED_ENDINGS)])
    stored = line_cache.read_lines(rig.op, batch.accepted[0].file_id)

    assert [(r.line_number, r.text) for r in stored] == [
        (1, "line1"),
        (2, "line2"),
        (3, "line3"),
        (4, "line4"),
        (5, "line5"),
    ]


def test_vertical_tab_banner_keeps_editor_line_numbers(rig: Rig) -> None:
    """F1, end to end: line 3 must be line 3."""
    batch = rig.service.ingest_batch([up("banner.cfg", configs.BANNER_WITH_VERTICAL_TAB)])
    stored = line_cache.read_lines(rig.op, batch.accepted[0].file_id)

    assert len(stored) == 3
    assert stored[2].text == "ip ssh version 2"


def test_single_line_lookup_for_a_citation(rig: Rig) -> None:
    batch = rig.service.ingest_batch([up("rtr.cfg", configs.CISCO_IOS)])
    record = line_cache.read_line(rig.op, batch.accepted[0].file_id, 3)
    assert record is not None
    assert record.text == "hostname rtr-test-01"


def test_unicode_round_trips(rig: Rig) -> None:
    batch = rig.service.ingest_batch([up("uni.cfg", configs.UNICODE_CONFIG)])
    stored = line_cache.read_lines(rig.op, batch.accepted[0].file_id)
    assert stored[0].text == "hostname राउटर-०१"


def test_utf16_file_is_ingested(rig: Rig) -> None:
    batch = rig.service.ingest_batch([UploadedFile(filename="u16.cfg", data=configs.UTF16_CONFIG)])
    assert len(batch.accepted) == 1
    assert batch.accepted[0].encoding == "utf-16-le"


# ---------------------------------------------------------------------------
# Duplicates and the fleet cache
# ---------------------------------------------------------------------------


def test_duplicate_is_detected_and_stored_once(rig: Rig) -> None:
    """Acceptance criterion 9."""
    first = rig.service.ingest_batch([up("a.cfg", configs.CISCO_IOS)])
    second = rig.service.ingest_batch([up("a-copy.cfg", configs.CISCO_IOS)])

    assert first.accepted[0].file_id == second.accepted[0].file_id
    assert not first.accepted[0].duplicate_of_existing
    assert second.accepted[0].duplicate_of_existing

    assert rig.op.execute("SELECT COUNT(*) FROM config_file").fetchone()[0] == 1
    assert rig.op.execute("SELECT COUNT(*) FROM ingestion").fetchone()[0] == 2


def test_fleet_cache_deduplicates_shared_lines(rig: Rig) -> None:
    """The Concept Report's efficiency claim, measured rather than asserted."""
    a = configs.CISCO_IOS
    b = configs.CISCO_IOS.replace("rtr-test-01", "rtr-test-02")

    rig.service.ingest_batch([up("a.cfg", a), up("b.cfg", b)])
    stats = line_cache.cache_stats(rig.op)

    assert stats["total_line_positions"] == lines.count_lines(a) + lines.count_lines(b)
    assert stats["deduplicated"] > 0, "two near-identical configs shared no lines"
    assert stats["distinct_lines"] < stats["total_line_positions"]


# ---------------------------------------------------------------------------
# Rejections
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "data", "reason"),
    [
        ("empty.cfg", b"", RejectionReason.EMPTY),
        ("png.cfg", configs.PNG_BYTES, RejectionReason.BINARY_CONTENT),
        ("elf.cfg", configs.ELF_BYTES, RejectionReason.BINARY_CONTENT),
        ("bad.xml", configs.MALFORMED_XML.encode(), RejectionReason.MALFORMED_XML),
        ("bad.json", configs.MALFORMED_JSON.encode(), RejectionReason.MALFORMED_JSON),
    ],
)
def test_rejection_reasons(rig: Rig, name: str, data: bytes, reason: RejectionReason) -> None:
    batch = rig.service.ingest_batch([UploadedFile(filename=name, data=data)])
    assert len(batch.rejected) == 1
    assert batch.rejected[0].reason is reason
    assert batch.rejected[0].detail


def test_oversized_file_is_rejected(tmp_path: Path, rig: Rig) -> None:
    rig.service._limits = LIMITS.__class__(**{**LIMITS.__dict__, "max_file_bytes": 100})
    batch = rig.service.ingest_batch([up("big.cfg", configs.CISCO_IOS)])
    assert batch.rejected[0].reason is RejectionReason.TOO_LARGE


def test_zip_slip_is_refused(rig: Rig) -> None:
    batch = rig.service.ingest_batch([UploadedFile(filename="evil.zip", data=configs.zip_slip())])
    assert batch.rejected[0].reason is RejectionReason.ARCHIVE_UNSAFE_PATH
    assert not batch.accepted


def test_archive_rejections_are_audited(rig: Rig) -> None:
    """A Zip Slip attempt is exactly the event worth keeping a record of.

    Archive-level refusals happen during expansion, before per-file ingestion,
    and originally bypassed the audit path entirely — three audit records for
    four rejections. Found by ingesting the real corpus, not by the unit tests.
    """
    rig.service.ingest_batch(
        [
            UploadedFile(filename="evil.zip", data=configs.zip_slip()),
            UploadedFile(filename="png.cfg", data=configs.PNG_BYTES),
        ]
    )
    rows = rig.audit.execute("SELECT action, payload_json FROM audit_log ORDER BY seq").fetchall()

    assert len(rows) == 2, "every rejection must produce exactly one audit record"
    assert {r["action"] for r in rows} == {str(AuditAction.FILE_REJECTED)}
    assert any("archive_unsafe_path" in r["payload_json"] for r in rows)


def test_every_rejection_produces_exactly_one_audit_record(rig: Rig) -> None:
    uploads = [
        UploadedFile(filename="a.zip", data=configs.zip_slip()),
        UploadedFile(filename="b.cfg", data=b""),
        UploadedFile(filename="c.cfg", data=configs.ELF_BYTES),
        UploadedFile(filename="d.xml", data=configs.MALFORMED_XML.encode()),
    ]
    batch = rig.service.ingest_batch(uploads)

    audited = rig.audit.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action = ?", (str(AuditAction.FILE_REJECTED),)
    ).fetchone()[0]
    assert audited == len(batch.rejected) == 4


def test_zip_bomb_is_refused(rig: Rig) -> None:
    rig.service._limits = LIMITS.__class__(
        **{**LIMITS.__dict__, "max_archive_uncompressed_bytes": 50_000}
    )
    batch = rig.service.ingest_batch([UploadedFile(filename="bomb.zip", data=configs.zip_bomb())])
    assert batch.rejected[0].reason in (
        RejectionReason.ARCHIVE_TOO_LARGE,
        RejectionReason.ARCHIVE_COMPRESSION_BOMB,
    )


def test_valid_zip_expands(rig: Rig) -> None:
    archive = configs.make_zip(
        {
            "rtr-01.cfg": configs.CISCO_IOS.encode(),
            "sw-01.cfg": configs.ARISTA_EOS.encode(),
        }
    )
    batch = rig.service.ingest_batch([UploadedFile(filename="fleet.zip", data=archive)])

    assert len(batch.accepted) == 2
    assert {f.detection.vendor for f in batch.accepted} == {"cisco", "arista"}


# ---------------------------------------------------------------------------
# Unsupported and ambiguous vendors
# ---------------------------------------------------------------------------


def test_unsupported_vendor_ingests_but_stays_unknown(rig: Rig) -> None:
    """Acceptance criterion 7 — the file is kept; the vendor is not guessed."""
    batch = rig.service.ingest_batch([up("weird.cfg", configs.UNSUPPORTED_VENDOR)])

    file = batch.accepted[0]
    assert not file.detection.is_known
    assert file.detection.vendor is None
    assert file.identity.known_fields() == {}

    row = rig.op.execute(
        "SELECT detected_vendor, detection_reason FROM config_file WHERE file_id = ?",
        (file.file_id,),
    ).fetchone()
    assert row["detected_vendor"] is None
    assert row["detection_reason"] != str(DetectionOutcome.DETECTED)


def test_detection_evidence_is_persisted(rig: Rig) -> None:
    batch = rig.service.ingest_batch([up("rtr.cfg", configs.CISCO_IOS)])
    row = rig.op.execute(
        "SELECT detection_evidence FROM config_file WHERE file_id = ?",
        (batch.accepted[0].file_id,),
    ).fetchone()
    assert "cisco" in row["detection_evidence"]
    assert "pattern" in row["detection_evidence"]


# ---------------------------------------------------------------------------
# Audit behaviour and database separation
# ---------------------------------------------------------------------------


def test_ingestion_appends_one_audit_record_per_file(rig: Rig) -> None:
    rig.service.ingest_batch([up("a.cfg", configs.CISCO_IOS), up("b.cfg", configs.ARISTA_EOS)])

    rows = rig.audit.execute("SELECT action FROM audit_log ORDER BY seq").fetchall()
    assert [r["action"] for r in rows] == ["file_ingested", "file_ingested"]
    assert verify_chain(rig.audit).ok


def test_rejection_is_audited_as_file_rejected_not_ingested(rig: Rig) -> None:
    """Acceptance criterion 10, decision D5."""
    rig.service.ingest_batch([UploadedFile(filename="png.cfg", data=configs.PNG_BYTES)])

    rows = rig.audit.execute("SELECT action, payload_json FROM audit_log").fetchall()
    assert len(rows) == 1
    assert rows[0]["action"] == str(AuditAction.FILE_REJECTED)
    assert rows[0]["action"] != str(AuditAction.FILE_INGESTED)
    assert "binary_content" in rows[0]["payload_json"]


def test_chain_verifies_after_a_mixed_batch(rig: Rig) -> None:
    rig.service.ingest_batch(
        [
            up("a.cfg", configs.CISCO_IOS),
            UploadedFile(filename="bad.cfg", data=configs.GZIP_BYTES),
            up("b.cfg", configs.ARISTA_EOS),
        ]
    )
    report = verify_chain(rig.audit)
    assert report.ok, report.summary()
    assert report.records_checked == 3


def test_no_configuration_content_in_the_audit_database(rig: Rig) -> None:
    """Acceptance criterion 11 — the whole audit file is scanned, not just payloads."""
    rig.service.ingest_batch(
        [
            up("rtr.cfg", configs.CISCO_IOS),
            up("sw.cfg", configs.ARISTA_EOS),
            up("uni.cfg", configs.UNICODE_CONFIG),
            UploadedFile(filename="png.cfg", data=configs.PNG_BYTES),
        ]
    )
    rig.audit.commit() if hasattr(rig.audit, "commit") else None
    rig.audit.close()

    raw = rig.audit_path.read_bytes().decode("latin-1")
    for marker in (
        "ip ssh version",
        "service timestamps",
        "transport input",
        "interface GigabitEthernet",
        "line vty",
        "transceiver qsfp",
        "hostname rtr-test-01",
        "राउटर",
    ):
        assert marker not in raw, f"configuration content leaked into the audit DB: {marker!r}"


def test_configuration_content_lives_in_the_operational_database(rig: Rig) -> None:
    """The other half of the separation: the content really is somewhere."""
    rig.service.ingest_batch([up("rtr.cfg", configs.CISCO_IOS)])
    rig.op.close()

    raw = rig.op_path.read_bytes().decode("latin-1")
    assert "ip ssh version 2" in raw, "the operational store should hold the lines"


def test_blob_is_stored_verbatim(rig: Rig) -> None:
    """Evidence fidelity: the bytes on disk are the bytes uploaded."""
    from api.ingest import blobs

    data = configs.MIXED_ENDINGS.encode("utf-8")
    batch = rig.service.ingest_batch([UploadedFile(filename="mixed.cfg", data=data)])

    assert blobs.read(rig.blob_root, batch.accepted[0].file_id) == data


def test_ingestion_rows_record_status(rig: Rig) -> None:
    rig.service.ingest_batch(
        [up("a.cfg", configs.CISCO_IOS), UploadedFile(filename="b.cfg", data=b"")]
    )
    rows = rig.op.execute("SELECT status, reason FROM ingestion ORDER BY status").fetchall()
    statuses = {r["status"] for r in rows}
    assert statuses == {"ingested", "rejected"}
    rejected = [r for r in rows if r["status"] == "rejected"][0]
    assert rejected["reason"] == "empty"
