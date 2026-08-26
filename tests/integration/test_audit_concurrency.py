"""Concurrency, durability and cross-process verification.

The chain is inherently serial — each record's prev_hash depends on its
predecessor — so these tests do not ask for parallel appends. They ask that
concurrent *callers* produce one correct chain rather than a corrupted one.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from api.audit.chain import AuditChain
from api.audit.verify import verify_chain
from api.db.connection import connect
from api.db.migrate import migrate
from api.models import Actor, ActorType, AuditAction, Subject
from tests.fixtures import tamper

REPO_ROOT = Path(__file__).resolve().parents[2]
HUMAN = Actor(type=ActorType.HUMAN, id="admin@ntro")
SUBJECT = Subject(kind="audit", id="a-1")


def test_eight_writers_produce_one_contiguous_chain(tmp_path: Path) -> None:
    """Acceptance criterion 7."""
    conn = connect(tmp_path / "audit.db")
    migrate(conn)
    chain = AuditChain(conn)

    threads, per_thread = 8, 50
    errors: list[Exception] = []
    barrier = threading.Barrier(threads)

    def writer(worker: int) -> None:
        barrier.wait()  # maximise contention
        for i in range(per_thread):
            try:
                chain.append(
                    actor=HUMAN,
                    action=AuditAction.AUDIT_RUN,
                    subject=SUBJECT,
                    payload={"worker": worker, "i": i},
                )
            except Exception as exc:  # noqa: BLE001 - collected and asserted below
                errors.append(exc)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(writer, range(threads)))

    assert not errors, f"appends failed under contention: {errors[:3]}"

    expected = threads * per_thread
    seqs = [r["seq"] for r in conn.execute("SELECT seq FROM audit_log ORDER BY seq").fetchall()]
    assert len(seqs) == expected
    assert seqs == list(range(expected)), "sequence is not contiguous"
    assert len(set(seqs)) == expected, "duplicate seq values"

    report = verify_chain(conn)
    assert report.ok, report.summary()
    assert report.records_checked == expected

    head = chain.head()
    assert head is not None
    assert head.last_seq == expected - 1
    assert head.record_count == expected


def test_no_payload_is_lost_under_contention(tmp_path: Path) -> None:
    conn = connect(tmp_path / "audit.db")
    migrate(conn)
    chain = AuditChain(conn)

    def writer(worker: int) -> None:
        for i in range(20):
            chain.append(
                actor=HUMAN,
                action=AuditAction.AUDIT_RUN,
                subject=SUBJECT,
                payload={"worker": worker, "i": i},
            )

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(writer, range(4)))

    seen = {
        (json.loads(r["payload_json"])["worker"], json.loads(r["payload_json"])["i"])
        for r in conn.execute("SELECT payload_json FROM audit_log").fetchall()
    }
    assert seen == {(w, i) for w in range(4) for i in range(20)}


def test_second_connection_sees_a_verifiable_chain(tmp_path: Path) -> None:
    """WAL — a reader can verify while the same database is open for writing."""
    db = tmp_path / "audit.db"
    writer_conn = connect(db)
    migrate(writer_conn)
    tamper.build_chain(writer_conn, count=6)

    reader_conn = connect(db)
    try:
        report = verify_chain(reader_conn)
        assert report.ok, report.summary()
        assert report.records_checked == 6
    finally:
        reader_conn.close()


def test_chain_verifies_in_a_fresh_interpreter(tmp_path: Path) -> None:
    """Acceptance criterion 8 — no in-memory state is required to verify.

    Runs the standalone CLI in a separate process, which also proves criterion 9:
    verification works without importing FastAPI.
    """
    db = tmp_path / "audit.db"
    conn = connect(db)
    migrate(conn)
    tamper.build_chain(conn, count=4)
    conn.close()

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "verify_audit_chain.py"), "--db", str(db)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "OK" in result.stdout
    assert "tamper-proof" in result.stdout.lower(), "the caveat should be printed"


def test_cli_reports_failure_with_exit_code_one(tmp_path: Path) -> None:
    db = tmp_path / "audit.db"
    conn = connect(db)
    migrate(conn)
    tamper.build_chain(conn, count=4)
    tamper.modify_payload(conn, seq=1)
    conn.close()

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "verify_audit_chain.py"),
            "--db",
            str(db),
            "--json",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["first_failure_seq"] == 1
    assert payload["tamper_evident_not_tamper_proof"] is True


def test_cli_returns_two_when_unreadable(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "verify_audit_chain.py"),
            "--db",
            str(tmp_path / "nothing.db"),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=120,
    )
    assert result.returncode == 2


def test_verifier_does_not_import_fastapi() -> None:
    """Acceptance criterion 9, asserted directly on the module's imports."""
    import ast

    source = (REPO_ROOT / "api" / "audit" / "verify.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "fastapi" not in imported
    assert "starlette" not in imported


@pytest.mark.parametrize("count", [1, 25, 120])
def test_property_any_chain_length_verifies(tmp_path: Path, count: int) -> None:
    conn = connect(tmp_path / f"audit-{count}.db")
    migrate(conn)
    tamper.build_chain(conn, count=count)

    report = verify_chain(conn)
    assert report.ok, report.summary()
    assert report.records_checked == count


def test_every_stored_payload_rehashes(tmp_path: Path) -> None:
    """The stored bytes are the hashed bytes — no re-serialisation in between."""
    import hashlib

    conn = connect(tmp_path / "audit.db")
    migrate(conn)
    tamper.build_chain(conn, count=10)

    rows = conn.execute("SELECT payload_json, payload_hash FROM audit_log").fetchall()
    for row in rows:
        recomputed = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
        assert recomputed == row["payload_hash"]


def test_no_configuration_contents_in_the_database(tmp_path: Path) -> None:
    """Acceptance criterion 10 — the chain records that things happened, not what was in them."""
    conn = connect(tmp_path / "audit.db")
    migrate(conn)
    chain = AuditChain(conn)

    chain.append(
        actor=Actor(type=ActorType.SYSTEM, id="ingest"),
        action=AuditAction.FILE_INGESTED,
        subject=Subject(kind="file", id="f1"),
        payload={
            "file_id": "f1",
            "filename": "rtr-core-01.cfg",
            "sha256": "a" * 64,
            "size_bytes": 40960,
            "line_count": 812,
            "detected_vendor": "cisco",
            "detected_os": "ios",
        },
    )
    chain.append(
        actor=Actor(type=ActorType.MODEL, id="all-MiniLM-L6-v2"),
        action=AuditAction.AI_SUGGESTED,
        subject=Subject(kind="cluster", id="c-1"),
        payload={
            "cluster_id": "c-1",
            "model_id": "all-MiniLM-L6-v2",
            "example_count": 14,
            "top3": [{"rank": 1, "field": "ssh_version", "raw_score": 0.81}],
        },
    )

    blob = "\n".join(
        r["payload_json"] for r in conn.execute("SELECT payload_json FROM audit_log").fetchall()
    )
    for forbidden in (
        "ip ssh version",
        "enable secret",
        "snmp-server community",
        "username ",
        "password ",
        "-----BEGIN",
    ):
        assert forbidden not in blob, (
            f"configuration content leaked into the audit log: {forbidden!r}"
        )


def test_sqlite_module_is_available_without_orm() -> None:
    assert sqlite3.sqlite_version_info >= (3, 35), "ON CONFLICT DO UPDATE needs SQLite 3.24+"
