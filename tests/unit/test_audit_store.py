"""Store layer — SQL, querying, and the read-only HTTP surface."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.audit import store
from api.audit.chain import AuditChain
from api.db.connection import connect
from api.db.migrate import AUDIT_MIGRATIONS, migrate
from api.models import Actor, ActorType, AuditAction, Subject
from tests.fixtures import tamper

HUMAN = Actor(type=ActorType.HUMAN, id="admin@ntro", role="administrator")


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = connect(tmp_path / "audit.db")
    migrate(c, AUDIT_MIGRATIONS)
    return c


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def test_read_range_returns_records_in_seq_order(conn: sqlite3.Connection) -> None:
    tamper.build_chain(conn, count=5)
    records = store.read_range(conn)
    assert [r.record.seq for r in records] == [0, 1, 2, 3, 4]


def test_read_range_respects_bounds(conn: sqlite3.Connection) -> None:
    tamper.build_chain(conn, count=6)
    assert [r.record.seq for r in store.read_range(conn, 2, 4)] == [2, 3, 4]


def test_read_one(conn: sqlite3.Connection) -> None:
    tamper.build_chain(conn, count=3)
    stored = store.read_one(conn, 1)
    assert stored is not None
    assert stored.record.seq == 1
    assert stored.hash_algo == "sha256"
    assert store.read_one(conn, 99) is None


def test_stored_payload_json_is_the_canonical_string(conn: sqlite3.Connection) -> None:
    chain = AuditChain(conn)
    chain.append(
        actor=HUMAN,
        action=AuditAction.AUDIT_RUN,
        subject=Subject(kind="audit", id="a1"),
        payload={"b": 2, "a": 1},
    )
    raw = conn.execute("SELECT payload_json FROM audit_log WHERE seq = 0").fetchone()[0]
    assert raw == '{"a":1,"b":2}', "keys must be sorted and separators tight"


def test_empty_chain_reads(conn: sqlite3.Connection) -> None:
    assert store.read_head(conn) is None
    assert store.max_seq(conn) is None
    assert store.record_count(conn) == 0
    assert store.read_range(conn) == []


def test_missing_triggers_detection(conn: sqlite3.Connection) -> None:
    assert store.missing_triggers(conn) == []
    tamper.drop_triggers(conn)
    assert set(store.missing_triggers(conn)) == {"audit_log_no_update", "audit_log_no_delete"}


# ---------------------------------------------------------------------------
# Query filters
# ---------------------------------------------------------------------------


def test_query_filters(conn: sqlite3.Connection) -> None:
    chain = AuditChain(conn)
    chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=Subject(kind="audit", id="a1"))
    chain.append(
        actor=Actor(type=ActorType.MODEL, id="mini"),
        action=AuditAction.AI_SUGGESTED,
        subject=Subject(kind="cluster", id="c1"),
    )
    chain.append(
        actor=HUMAN,
        action=AuditAction.ADMIN_CONFIRMED,
        subject=Subject(kind="training_example", id="tex1"),
    )

    assert len(store.query(conn)) == 3
    assert len(store.query(conn, action="ai_suggested")) == 1
    assert len(store.query(conn, actor_id="admin@ntro")) == 2
    assert len(store.query(conn, subject_kind="cluster")) == 1
    assert len(store.query(conn, limit=2)) == 2
    assert len(store.query(conn, limit=2, offset=2)) == 1


def test_ai_suggestions_are_distinguishable_from_decisions(conn: sqlite3.Connection) -> None:
    """Two independent signals: the action and the actor type."""
    chain = AuditChain(conn)
    chain.append(
        actor=Actor(type=ActorType.MODEL, id="mini"),
        action=AuditAction.AI_SUGGESTED,
        subject=Subject(kind="cluster", id="c1"),
        payload={"top3": [{"rank": 1, "field": "ssh_version", "raw_score": 0.8}]},
    )
    chain.append(
        actor=HUMAN,
        action=AuditAction.ADMIN_CORRECTED,
        subject=Subject(kind="training_example", id="tex1"),
        payload={"suggested_field": "ssh_version", "corrected_field": "telnet_enabled"},
    )

    suggestions = store.query(conn, action="ai_suggested")
    decisions = store.query(conn, action="admin_corrected")

    assert len(suggestions) == 1 and suggestions[0]["actor_type"] == "model"
    assert len(decisions) == 1 and decisions[0]["actor_type"] == "human"
    assert store.query(conn, actor_id="mini", action="admin_corrected") == []


# ---------------------------------------------------------------------------
# Read-only HTTP surface
# ---------------------------------------------------------------------------


AUDITOR = ("auditor", "a-sufficiently-long-pw")
"""The chain surface requires authentication from P7 (decision D25).

An operator reading the audit log is reading a record of who did what to whose
configuration, so it is not a public surface. The assertions below are unchanged;
only the credentials are new.
"""


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    db = tmp_path / "audit.db"
    conn = connect(db)
    migrate(conn, AUDIT_MIGRATIONS)
    tamper.build_chain(conn, count=4)
    conn.close()

    from api.config import settings

    monkeypatch.setattr(settings, "audit_db_path", db)
    monkeypatch.setattr(settings, "db_path", tmp_path / "operational.db")

    from api.db import users as user_store
    from api.db.migrate import OPERATIONAL_MIGRATIONS

    op = connect(tmp_path / "operational.db")
    migrate(op, OPERATIONAL_MIGRATIONS)
    user_store.create_user(op, AUDITOR[0], AUDITOR[1])
    op.close()

    from api.main import app

    return TestClient(app)


def test_head_endpoint(client: TestClient) -> None:
    body = client.get("/audit/head", auth=AUDITOR).json()
    assert body["empty"] is False
    assert body["last_seq"] == 3
    assert body["record_count"] == 4


def test_verify_endpoint(client: TestClient) -> None:
    body = client.get("/audit/verify", auth=AUDITOR).json()
    assert body["ok"] is True
    assert body["records_checked"] == 4
    assert body["tamper_evident_not_tamper_proof"] is True


def test_records_endpoint_declares_itself_unverifiable(client: TestClient) -> None:
    """A filtered view has no links between its rows, so it carries no claim."""
    body = client.get("/audit/records?limit=2", auth=AUDITOR).json()
    assert body["verifiable"] is False
    assert "use /audit/verify" in body["reason"]
    assert body["count"] == 2


def test_no_write_route_exists(client: TestClient) -> None:
    """Records are appended by the services that act, never by an HTTP caller.

    Matched on `/audit/` with the separator, not the bare prefix. The chain's
    surface is what this protects, and `/compliance/audits` is a different
    resource that legitimately accepts POST — a prefix match without the slash
    conflates the two.
    """
    schema = client.get("/openapi.json").json()
    chain_paths = [p for p in schema["paths"] if p == "/audit" or p.startswith("/audit/")]

    assert chain_paths, "guard against this passing because the chain routes vanished"
    for path in chain_paths:
        assert set(schema["paths"][path]) <= {"get"}, f"{path} exposes {set(schema['paths'][path])}"
