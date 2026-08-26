"""Tamper detection — the 14 fixtures from the approved P2 design.

Each builds a valid chain, applies exactly one mutation with the append-only
triggers temporarily dropped (the only way to simulate an attacker with database
access rather than application access), and asserts the expected outcome.

**Two of these assert that tampering is NOT detected.** Fixtures 8 and 14 are
not gaps in coverage. They encode the threat model as executable documentation:
this log is tamper-evident, not tamper-proof. If decision R17 later introduces a
keyed digest or external anchoring, fixture 14 flipping from "passes" to
"detected" is how we will know the change did what it claimed.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from api.audit.errors import FailureKind
from api.audit.verify import verify_chain
from tests.fixtures import tamper


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    c = tamper.new_db(tmp_path)
    tamper.build_chain(c, count=5)
    return c


def test_untampered_chain_verifies(conn: sqlite3.Connection) -> None:
    """The control. Everything below is measured against this."""
    report = verify_chain(conn)
    assert report.ok, report.summary()
    assert report.records_checked == 5
    assert report.head_state == "consistent"
    assert report.failures == []


# ---------------------------------------------------------------------------
# 1–4 · modification
# ---------------------------------------------------------------------------


def test_01_modified_payload(conn: sqlite3.Connection) -> None:
    tamper.modify_payload(conn, seq=2)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.MODIFIED_PAYLOAD in report.kinds
    assert report.first_failure_seq == 2


def test_02_modified_actor(conn: sqlite3.Connection) -> None:
    tamper.modify_field(conn, seq=1, column="actor_id", value="mallory")
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.MODIFIED_RECORD in report.kinds
    assert report.first_failure_seq == 1


def test_03_modified_action(conn: sqlite3.Connection) -> None:
    tamper.modify_field(conn, seq=3, column="action", value="report_generated")
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.MODIFIED_RECORD in report.kinds


def test_04_modified_timestamp(conn: sqlite3.Connection) -> None:
    """Backdating a record must be caught — and, post-D1, only real changes are."""
    tamper.modify_field(conn, seq=2, column="timestamp", value="2020-01-01T00:00:00.000000Z")
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.MODIFIED_RECORD in report.kinds
    assert report.first_failure_seq == 2


def test_04b_equivalent_timestamp_rewrite_is_not_a_false_positive(
    conn: sqlite3.Connection,
) -> None:
    """D1 regression, from the other direction.

    Rewriting the stored timestamp into a different *spelling* of the same
    instant must still verify. Before the D1 fix this raised "tampering" on data
    nobody meaningfully changed.
    """
    original = conn.execute("SELECT timestamp FROM audit_log WHERE seq = 2").fetchone()[0]
    respelled = original.replace("T", " ").replace("Z", "+00:00")
    tamper.modify_field(conn, seq=2, column="timestamp", value=respelled)

    assert verify_chain(conn).ok


# ---------------------------------------------------------------------------
# 5–8 · deletion
# ---------------------------------------------------------------------------


def test_05_deleted_middle_record(conn: sqlite3.Connection) -> None:
    tamper.delete_record(conn, seq=2)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.DELETED_RECORD in report.kinds
    assert FailureKind.BROKEN_LINK in report.kinds


def test_06_deleted_last_record(conn: sqlite3.Connection) -> None:
    """The links alone cannot see this: a truncated chain is still well-formed."""
    tamper.delete_record(conn, seq=4)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.TRUNCATED in report.kinds or FailureKind.HEAD_MISMATCH in report.kinds
    assert report.head_state in ("truncated", "count_mismatch", "hash_mismatch")


def test_07_all_records_deleted_head_intact(conn: sqlite3.Connection) -> None:
    tamper.delete_all_records(conn, also_head=False)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.TRUNCATED in report.kinds
    assert report.head_state == "truncated"


def test_08_all_records_and_head_deleted_is_NOT_detected(  # noqa: N802 - the shout is the point: this asserts a limitation
    conn: sqlite3.Connection,
) -> None:
    """INTENTIONAL NON-DETECTION — threat-model documentation.

    Deleting the log and the head together is indistinguishable from a fresh
    installation. Nothing inside the database can prove that something was once
    there; that requires an anchor outside it, which is decision R17.
    """
    tamper.delete_all_records(conn, also_head=True)
    report = verify_chain(conn)

    assert report.ok, "expected empty chain to verify — this documents the limitation"
    assert report.head_state == "empty"
    assert report.records_checked == 0


# ---------------------------------------------------------------------------
# 9–12 · reordering and forgery
# ---------------------------------------------------------------------------


def test_09_swapped_seq(conn: sqlite3.Connection) -> None:
    tamper.swap_seq(conn, 1, 3)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.BROKEN_LINK in report.kinds or FailureKind.MODIFIED_RECORD in report.kinds


def test_10_swapped_payloads(conn: sqlite3.Connection) -> None:
    tamper.swap_payloads(conn, 1, 3)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.MODIFIED_PAYLOAD in report.kinds
    modified = [f.seq for f in report.failures if f.kind is FailureKind.MODIFIED_PAYLOAD]
    assert set(modified) == {1, 3}


def test_11_rewritten_prev_hash(conn: sqlite3.Connection) -> None:
    tamper.rewrite_prev_hash(conn, seq=3)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.BROKEN_LINK in report.kinds


def test_12_forged_record_inserted_midchain(conn: sqlite3.Connection) -> None:
    """A self-consistent forgery still breaks the link its successor expects."""
    from api.models import Actor, ActorType, AuditRecord, Subject

    with tamper.database_access(conn) as c:
        c.execute("UPDATE audit_log SET seq = seq + 100 WHERE seq >= 3")
        forged = AuditRecord(
            seq=3,
            timestamp="2026-08-26T12:03:00.000000Z",
            actor=Actor(type=ActorType.HUMAN, id="mallory"),
            action="pack_activated",
            subject=Subject(kind="vendor_pack", id="evil@9.9.9"),
            payload={"injected": True},
            prev_hash="a" * 64,
        )
        c.execute(
            """
            INSERT INTO audit_log (seq, timestamp, actor_type, actor_id, actor_role,
                action, subject_kind, subject_id, payload_json, payload_hash,
                prev_hash, entry_hash, hash_algo)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'sha256')
            """,
            (
                forged.seq,
                "2026-08-26T12:03:00.000000Z",
                "human",
                "mallory",
                None,
                "pack_activated",
                "vendor_pack",
                "evil@9.9.9",
                '{"injected":true}',
                forged.payload_hash,
                forged.prev_hash,
                forged.entry_hash,
            ),
        )
        c.execute("UPDATE audit_log SET seq = seq - 100 + 1 WHERE seq >= 103")

    report = verify_chain(conn)
    assert not report.ok
    assert FailureKind.BROKEN_LINK in report.kinds


# ---------------------------------------------------------------------------
# 13 · guards removed
# ---------------------------------------------------------------------------


def test_13_dropped_triggers_are_reported(conn: sqlite3.Connection) -> None:
    """A chain that verifies but has lost its guards is one someone prepared to edit."""
    tamper.drop_triggers(conn)
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.MISSING_TRIGGER in report.kinds
    assert len([f for f in report.failures if f.kind is FailureKind.MISSING_TRIGGER]) == 2


# ---------------------------------------------------------------------------
# 14 · the limitation
# ---------------------------------------------------------------------------


def test_14_full_chain_rewrite_is_NOT_detected(  # noqa: N802 - the shout is the point: this asserts a limitation
    conn: sqlite3.Connection,
) -> None:
    """INTENTIONAL NON-DETECTION — the central threat-model limitation.

    SHA-256 takes no secret. An attacker with unrestricted database write access
    can alter a record and rebuild every subsequent link so the whole chain
    verifies. This test asserts that, so nobody can later claim the log is
    tamper-proof without this failing first.

    If R17 introduces HMAC or external anchoring, this assertion inverts — and
    that inversion is the evidence the change worked.
    """
    tamper.recompute_whole_chain(conn, at_seq=2, new_payload='{"injected":"by mallory"}')

    report = verify_chain(conn)
    assert report.ok, (
        "expected the rewritten chain to verify; if this now fails, an authenticity "
        "mechanism has been added and the threat model should be updated"
    )

    stored = conn.execute("SELECT payload_json FROM audit_log WHERE seq = 2").fetchone()[0]
    assert stored == '{"injected":"by mallory"}', "the tampering really did happen"


# ---------------------------------------------------------------------------
# range verification
# ---------------------------------------------------------------------------


def test_range_verification_is_anchored(conn: sqlite3.Connection) -> None:
    report = verify_chain(conn, start=2, end=4)
    assert report.ok
    assert report.anchored
    assert report.records_checked == 3


def test_range_verification_still_sees_a_break(conn: sqlite3.Connection) -> None:
    tamper.modify_payload(conn, seq=3)
    report = verify_chain(conn, start=3, end=4)
    assert not report.ok
    assert FailureKind.MODIFIED_PAYLOAD in report.kinds


def test_algo_mismatch_is_reported(conn: sqlite3.Connection) -> None:
    """The verifier takes its algorithm from configuration, never from the row."""
    tamper.modify_field(conn, seq=1, column="hash_algo", value="md5")
    report = verify_chain(conn)

    assert not report.ok
    assert FailureKind.ALGO_MISMATCH in report.kinds


def test_report_never_claims_tamper_proof(conn: sqlite3.Connection) -> None:
    report = verify_chain(conn)
    text = (report.summary() + str(report.to_dict())).lower()
    assert "tamper-proof" not in text and "tamperproof" not in text
    assert report.to_dict()["tamper_evident_not_tamper_proof"] is True
