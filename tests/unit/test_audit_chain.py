"""Audit chain — append, round-trip, D1 and D2 regressions, atomicity."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.audit.chain import AuditChain
from api.audit.errors import ChainIntegrityError, PayloadNotJsonNativeError
from api.audit.store import validate_json_native
from api.audit.verify import verify_chain
from api.db.connection import connect
from api.db.migrate import AUDIT_MIGRATIONS, migrate
from api.models import GENESIS_HASH, Actor, ActorType, AuditAction, Subject
from api.models.audit import canonical_timestamp
from tests.fixtures import tamper

HUMAN = Actor(type=ActorType.HUMAN, id="admin@ntro", role="administrator")
SUBJECT = Subject(kind="vendor_pack", id="acme/acme-os@1.0.0")


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = connect(tmp_path / "audit.db")
    migrate(c, AUDIT_MIGRATIONS)
    return c


@pytest.fixture
def chain(conn: sqlite3.Connection) -> AuditChain:
    return AuditChain(conn)


# ---------------------------------------------------------------------------
# Append and genesis
# ---------------------------------------------------------------------------


def test_first_record_opens_the_chain(chain: AuditChain) -> None:
    record = chain.append(
        actor=HUMAN, action=AuditAction.PACK_ACTIVATED, subject=SUBJECT, payload={"to": "1.0.0"}
    )
    assert record.seq == 0
    assert record.prev_hash == GENESIS_HASH
    assert record.is_genesis


def test_records_are_contiguous_and_linked(chain: AuditChain) -> None:
    records = [
        chain.append(
            actor=HUMAN,
            action=AuditAction.PACK_ACTIVATED,
            subject=SUBJECT,
            payload={"i": i},
        )
        for i in range(6)
    ]
    assert [r.seq for r in records] == [0, 1, 2, 3, 4, 5]
    for previous, current in zip(records, records[1:], strict=False):
        assert current.links_to(previous)


def test_head_tracks_the_tail(chain: AuditChain) -> None:
    for i in range(4):
        last = chain.append(
            actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, payload={"i": i}
        )
    head = chain.head()
    assert head is not None
    assert head.last_seq == last.seq
    assert head.last_hash == last.entry_hash
    assert head.record_count == 4


# ---------------------------------------------------------------------------
# D1 — the regression that motivated the contract fix
# ---------------------------------------------------------------------------


def test_store_read_verify_round_trip(chain: AuditChain, conn: sqlite3.Connection) -> None:
    """Acceptance criterion 3. This is the test that failed before D1 was fixed."""
    tamper.build_chain(conn, count=0)  # no-op; chain already wired
    for i in range(5):
        chain.append(
            actor=HUMAN, action=AuditAction.PACK_ACTIVATED, subject=SUBJECT, payload={"i": i}
        )

    report = verify_chain(conn)
    assert report.ok, report.summary()
    assert report.records_checked == 5


@pytest.mark.parametrize(
    "spelling",
    [
        "2026-08-26T12:00:00+00:00",
        "2026-08-26 12:00:00+00:00",
        "2026-08-26T12:00:00Z",
        "2026-08-26T17:30:00+05:30",
    ],
)
def test_equivalent_timestamp_representations_hash_identically(spelling: str) -> None:
    """D1 — one instant, one hash, however it was spelled."""
    reference = canonical_timestamp(datetime(2026, 8, 26, 12, 0, tzinfo=UTC))
    assert canonical_timestamp(spelling) == reference


def test_canonical_timestamp_form_is_fixed() -> None:
    assert (
        canonical_timestamp(datetime(2026, 8, 26, 12, 0, tzinfo=UTC))
        == "2026-08-26T12:00:00.000000Z"
    )


def test_naive_timestamp_is_refused(chain: AuditChain) -> None:
    with pytest.raises(Exception, match="timezone-aware|timezone-naive"):
        chain.append(
            actor=HUMAN,
            action=AuditAction.AUDIT_RUN,
            subject=SUBJECT,
            timestamp=datetime(2026, 8, 26, 12, 0),
        )


def test_stored_timestamp_is_canonical(chain: AuditChain, conn: sqlite3.Connection) -> None:
    """The semantic instant survives storage; the hashed string is canonical."""
    when = datetime(2026, 8, 26, 17, 30, tzinfo=UTC) + timedelta(hours=0)
    chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, timestamp=when)

    stored = conn.execute("SELECT timestamp FROM audit_log WHERE seq = 0").fetchone()[0]
    assert stored == canonical_timestamp(when)

    from api.audit.store import read_one

    loaded = read_one(conn, 0)
    assert loaded is not None
    assert loaded.record.timestamp == when


def test_records_written_in_different_offsets_still_verify(
    chain: AuditChain, conn: sqlite3.Connection
) -> None:
    from datetime import timezone

    ist = timezone(timedelta(hours=5, minutes=30))
    chain.append(
        actor=HUMAN,
        action=AuditAction.AUDIT_RUN,
        subject=SUBJECT,
        timestamp=datetime(2026, 8, 26, 17, 30, tzinfo=ist),
    )
    chain.append(
        actor=HUMAN,
        action=AuditAction.AUDIT_RUN,
        subject=SUBJECT,
        timestamp=datetime(2026, 8, 26, 12, 1, tzinfo=UTC),
    )
    assert verify_chain(conn).ok


# ---------------------------------------------------------------------------
# D2 — JSON-native payloads at the persistence boundary
# ---------------------------------------------------------------------------


def test_datetime_payload_is_rejected(chain: AuditChain) -> None:
    with pytest.raises(PayloadNotJsonNativeError, match="datetime"):
        chain.append(
            actor=HUMAN,
            action=AuditAction.AUDIT_RUN,
            subject=SUBJECT,
            payload={"when": datetime(2026, 8, 26, 12, 0, tzinfo=UTC)},
        )


def test_set_payload_is_rejected(chain: AuditChain) -> None:
    with pytest.raises(PayloadNotJsonNativeError, match="set"):
        chain.append(
            actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, payload={"x": {1, 2}}
        )


def test_custom_object_payload_is_rejected(chain: AuditChain) -> None:
    class Custom:
        pass

    with pytest.raises(PayloadNotJsonNativeError, match="Custom"):
        chain.append(
            actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, payload={"o": Custom()}
        )


def test_nested_non_native_value_is_rejected() -> None:
    with pytest.raises(PayloadNotJsonNativeError, match=r"payload\.a\.b\[1\]"):
        validate_json_native({"a": {"b": [1, {3, 4}]}})


def test_non_string_key_is_rejected() -> None:
    with pytest.raises(PayloadNotJsonNativeError, match="non-string key"):
        validate_json_native({1: "a"})


def test_nan_and_infinity_are_rejected() -> None:
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(PayloadNotJsonNativeError, match="not representable"):
            validate_json_native({"x": bad})


def test_legitimate_payloads_are_accepted_and_deterministic(chain: AuditChain) -> None:
    """Equivalent JSON payloads serialise identically regardless of key order."""
    a = chain.append(
        actor=HUMAN,
        action=AuditAction.AUDIT_RUN,
        subject=SUBJECT,
        payload={"b": 2, "a": 1, "nested": {"z": [1, 2.5, True, None], "y": "x"}},
    )
    b = chain.append(
        actor=HUMAN,
        action=AuditAction.AUDIT_RUN,
        subject=SUBJECT,
        payload={"nested": {"y": "x", "z": [1, 2.5, True, None]}, "a": 1, "b": 2},
    )
    assert a.payload_hash == b.payload_hash


def test_unicode_payload_round_trips(chain: AuditChain, conn: sqlite3.Connection) -> None:
    chain.append(
        actor=HUMAN,
        action=AuditAction.FILE_INGESTED,
        subject=Subject(kind="file", id="f1"),
        payload={"hostname": "राउटर-०१", "note": "em—dash and ✓"},
    )
    assert verify_chain(conn).ok


# ---------------------------------------------------------------------------
# Rule 1 in the chain
# ---------------------------------------------------------------------------


def test_model_actor_may_suggest(chain: AuditChain) -> None:
    record = chain.append(
        actor=Actor(type=ActorType.MODEL, id="all-MiniLM-L6-v2"),
        action=AuditAction.AI_SUGGESTED,
        subject=Subject(kind="cluster", id="c-1"),
        payload={"top3": [{"rank": 1, "field": "ssh_version", "raw_score": 0.81}]},
    )
    assert record.actor.type is ActorType.MODEL


@pytest.mark.parametrize(
    "action",
    [AuditAction.AUDIT_RUN, AuditAction.ADMIN_CONFIRMED, AuditAction.PACK_ACTIVATED],
)
def test_model_actor_cannot_do_anything_else(chain: AuditChain, action: AuditAction) -> None:
    with pytest.raises(Exception, match="models suggest, humans decide"):
        chain.append(
            actor=Actor(type=ActorType.MODEL, id="m"),
            action=action,
            subject=SUBJECT,
        )


def test_sql_check_blocks_model_verdict_without_python(conn: sqlite3.Connection) -> None:
    """Acceptance criterion 6 — the constraint holds below the contract.

    A direct INSERT bypassing Pydantic entirely must still be refused, so an
    attacker with database access cannot record a model issuing a verdict.
    """
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO audit_log (
                seq, timestamp, actor_type, actor_id, actor_role, action,
                subject_kind, subject_id, payload_json, payload_hash,
                prev_hash, entry_hash, hash_algo
            ) VALUES (0, '2026-08-26T12:00:00.000000Z', 'model', 'm', NULL,
                      'audit_run', 'audit', 'a1', '{}', ?, ?, ?, 'sha256')
            """,
            ("a" * 64, "0" * 64, "c" * 64),
        )


def test_sql_check_allows_model_suggestion(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        INSERT INTO audit_log (
            seq, timestamp, actor_type, actor_id, actor_role, action,
            subject_kind, subject_id, payload_json, payload_hash,
            prev_hash, entry_hash, hash_algo
        ) VALUES (0, '2026-08-26T12:00:00.000000Z', 'model', 'm', NULL,
                  'ai_suggested', 'cluster', 'c1', '{}', ?, ?, ?, 'sha256')
        """,
        ("a" * 64, "0" * 64, "c" * 64),
    )
    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1


# ---------------------------------------------------------------------------
# Append-only enforcement
# ---------------------------------------------------------------------------


def test_update_is_refused_by_the_database(chain: AuditChain, conn: sqlite3.Connection) -> None:
    chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("UPDATE audit_log SET actor_id = 'mallory' WHERE seq = 0")


def test_delete_is_refused_by_the_database(chain: AuditChain, conn: sqlite3.Connection) -> None:
    chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute("DELETE FROM audit_log WHERE seq = 0")


# ---------------------------------------------------------------------------
# Atomicity and reconciliation
# ---------------------------------------------------------------------------


def test_failed_append_leaves_nothing_behind(chain: AuditChain, conn: sqlite3.Connection) -> None:
    chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT)

    with pytest.raises(PayloadNotJsonNativeError):
        chain.append(
            actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, payload={"bad": {1, 2}}
        )

    assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
    head = chain.head()
    assert head is not None and head.last_seq == 0 and head.record_count == 1


def test_log_and_head_never_diverge_across_appends(
    chain: AuditChain, conn: sqlite3.Connection
) -> None:
    for i in range(10):
        chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, payload={"i": i})
        head = chain.head()
        count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        top = conn.execute("SELECT MAX(seq) FROM audit_log").fetchone()[0]
        assert head is not None
        assert head.last_seq == top
        assert head.record_count == count


def test_reconcile_reports_empty(chain: AuditChain) -> None:
    assert chain.reconcile_head() == "empty"


def test_reconcile_repairs_a_lagging_head_forward(
    chain: AuditChain, conn: sqlite3.Connection
) -> None:
    for i in range(3):
        chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, payload={"i": i})
    conn.execute("UPDATE audit_chain_head SET last_seq = 0, record_count = 1 WHERE id = 1")

    assert chain.reconcile_head() == "repaired_forward"
    head = chain.head()
    assert head is not None and head.last_seq == 2 and head.record_count == 3


def test_reconcile_refuses_to_repair_backward(chain: AuditChain, conn: sqlite3.Connection) -> None:
    """A head ahead of the log means records are missing; papering over it would
    destroy the only evidence they existed."""
    for i in range(3):
        chain.append(actor=HUMAN, action=AuditAction.AUDIT_RUN, subject=SUBJECT, payload={"i": i})
    tamper.delete_record(conn, 2)

    with pytest.raises(ChainIntegrityError, match="records are missing"):
        chain.reconcile_head()
