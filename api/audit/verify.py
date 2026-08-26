"""Chain verification.

A pure function over a connection. No FastAPI import, no UI dependency — an
integrity check that can only be run through the interface it is meant to police
is not much of a check.

**This log is tamper-evident, not tamper-proof.** It detects record
modification, deletion, reordering, broken links and accidental corruption. It
does *not* detect an attacker with unrestricted database write access who
recomputes the complete unkeyed chain: SHA-256 takes no secret, so anyone able
to write can rebuild every link consistently. Closing that gap needs a key or an
external anchor, which is decision R17 and deliberately out of scope for P2.

Two tamper fixtures in the test suite assert exactly that non-detection. They
are not gaps in coverage; they are the threat model written as executable
documentation.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from typing import Any

from api.audit import store
from api.audit.errors import FailureKind
from api.models import GENESIS_HASH, AuditRecord
from api.models.audit import canonical_timestamp

EXPECTED_HASH_ALGO = "sha256"
"""Taken from configuration, never from the row. A record claiming a different
algorithm is reported rather than believed — otherwise a downgrade would be
self-authorising."""


@dataclass(frozen=True)
class Failure:
    seq: int | None
    kind: FailureKind
    detail: str

    def __str__(self) -> str:
        where = f"seq {self.seq}" if self.seq is not None else "chain"
        return f"[{self.kind}] {where}: {self.detail}"


@dataclass
class ChainVerificationReport:
    """The result of walking the chain. Never raises on tamper — it reports."""

    ok: bool = True
    records_checked: int = 0
    start: int = 0
    end: int | None = None
    anchored: bool = True
    head_state: str = "unknown"
    algo: str = EXPECTED_HASH_ALGO
    failures: list[Failure] = field(default_factory=list)

    def add(self, seq: int | None, kind: FailureKind, detail: str) -> None:
        self.failures.append(Failure(seq=seq, kind=kind, detail=detail))
        self.ok = False

    @property
    def first_failure_seq(self) -> int | None:
        seqs = [f.seq for f in self.failures if f.seq is not None]
        return min(seqs) if seqs else None

    @property
    def kinds(self) -> set[FailureKind]:
        return {f.kind for f in self.failures}

    def summary(self) -> str:
        if self.ok:
            scope = "whole chain" if self.start == 0 and self.end is None else "range"
            return f"OK — {self.records_checked} records verified ({scope})"
        return (
            f"FAILED — {len(self.failures)} problem(s), first at seq "
            f"{self.first_failure_seq}: " + "; ".join(str(f) for f in self.failures[:5])
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "records_checked": self.records_checked,
            "start": self.start,
            "end": self.end,
            "anchored": self.anchored,
            "head_state": self.head_state,
            "algo": self.algo,
            "tamper_evident_not_tamper_proof": True,
            "first_failure_seq": self.first_failure_seq,
            "failures": [
                {"seq": f.seq, "kind": str(f.kind), "detail": f.detail} for f in self.failures
            ],
        }


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _first_line(exc: Exception) -> str:
    """Pydantic errors are multi-line; a failure report wants one line."""
    return str(exc).strip().splitlines()[0]


def verify_chain(
    conn: sqlite3.Connection,
    *,
    start: int = 0,
    end: int | None = None,
    expected_algo: str = EXPECTED_HASH_ALGO,
) -> ChainVerificationReport:
    """Walk the chain and report every problem found.

    Verifying a range that does not begin at 0 reads the preceding record to
    anchor the first link. Without that anchor the range proves only internal
    consistency, and the report says so via `anchored`.
    """
    report = ChainVerificationReport(start=start, end=end, algo=expected_algo)

    # 6. Append-only triggers. A chain that verifies perfectly but has had its
    # guards removed is a chain someone has prepared to edit.
    for name in store.missing_triggers(conn):
        report.add(None, FailureKind.MISSING_TRIGGER, f"append-only trigger {name!r} is missing")

    try:
        rows = store.read_raw_range(conn, start, end)
    except sqlite3.Error as exc:
        report.add(None, FailureKind.UNREADABLE, str(exc))
        return report

    previous_hash: str | None = None
    previous_seq: int | None = None

    if start > 0:
        anchor = conn.execute(
            "SELECT entry_hash FROM audit_log WHERE seq = ?", (start - 1,)
        ).fetchone()
        if anchor is None:
            report.anchored = False
        else:
            previous_hash = anchor["entry_hash"]
            previous_seq = start - 1

    for row in rows:
        seq = row["seq"]
        report.records_checked += 1

        # 2. Contiguity — a gap is a deleted record.
        if previous_seq is not None and seq != previous_seq + 1:
            report.add(
                seq,
                FailureKind.DELETED_RECORD,
                f"seq jumps from {previous_seq} to {seq}; "
                f"{seq - previous_seq - 1} record(s) missing",
            )

        if row["hash_algo"] != expected_algo:
            report.add(
                seq,
                FailureKind.ALGO_MISMATCH,
                f"record claims hash_algo {row['hash_algo']!r}, verifier expects {expected_algo!r}",
            )

        # 4a. Rehash the stored payload string itself, not a re-serialised
        # object — this is what keeps verification independent of any future
        # change in Python's JSON behaviour.
        if _sha256(row["payload_json"]) != row["payload_hash"]:
            report.add(
                seq,
                FailureKind.MODIFIED_PAYLOAD,
                "stored payload no longer hashes to its recorded payload_hash",
            )

        # 3 and 4c. Genesis and linkage are checked against the raw row, not
        # against a reconstructed object. A record whose hashes were tampered
        # with fails reconstruction, and if linkage depended on that we would
        # report the damage less precisely than it actually is — one mutation
        # can legitimately be both a modified record and a broken link.
        if seq == 0 and row["prev_hash"] != GENESIS_HASH:
            report.add(
                0,
                FailureKind.BROKEN_GENESIS,
                f"first record's prev_hash is {row['prev_hash'][:16]}…, expected the genesis value",
            )

        if previous_hash is not None and row["prev_hash"] != previous_hash:
            report.add(
                seq,
                FailureKind.BROKEN_LINK,
                f"prev_hash {row['prev_hash'][:16]}… does not match predecessor's "
                f"entry_hash {previous_hash[:16]}…",
            )

        # 4b. Reconstruct through the contract, which recomputes entry_hash from
        # the seven hashed fields and raises if they disagree.
        try:
            stored = store.read_one(conn, seq)
        except Exception as exc:  # noqa: BLE001 - tampering is a finding, not a crash
            report.add(
                seq,
                FailureKind.MODIFIED_RECORD,
                f"record does not reconstruct: {_first_line(exc)}",
            )
        else:
            if stored is None:  # pragma: no cover - row was just read
                report.add(seq, FailureKind.UNREADABLE, "record vanished mid-verification")
            elif not _verify_entry_hash(stored.record):
                report.add(
                    seq,
                    FailureKind.MODIFIED_RECORD,
                    "entry_hash does not match the record's hashed fields",
                )

        previous_hash = row["entry_hash"]
        previous_seq = seq

    # 5. Head cross-check.
    report.head_state = _verify_head(conn, report, checked_full_chain=(start == 0 and end is None))
    return report


def _verify_entry_hash(record: AuditRecord) -> bool:
    return record.entry_hash == AuditRecord.compute_entry_hash(
        seq=record.seq,
        timestamp=canonical_timestamp(record.timestamp),
        actor=record.actor,
        action=record.action,
        subject=record.subject,
        payload_hash=record.payload_hash,
        prev_hash=record.prev_hash,
    )


def _verify_head(
    conn: sqlite3.Connection, report: ChainVerificationReport, *, checked_full_chain: bool
) -> str:
    head = store.read_head(conn)
    top = store.max_seq(conn)
    count = store.record_count(conn)

    if head is None and top is None:
        return "empty"

    if head is None:
        report.add(None, FailureKind.HEAD_MISMATCH, "audit_chain_head row is missing")
        return "missing"

    if top is None:
        report.add(
            None,
            FailureKind.TRUNCATED,
            f"head records {head.record_count} entries up to seq {head.last_seq}, "
            "but the log is empty",
        )
        return "truncated"

    if head.last_seq > top:
        report.add(
            None,
            FailureKind.TRUNCATED,
            f"head is ahead of the log (head seq {head.last_seq}, log seq {top}); "
            "the chain's tail has been removed",
        )
        return "truncated"

    if head.last_seq < top:
        report.add(
            None,
            FailureKind.HEAD_MISMATCH,
            f"head lags the log (head seq {head.last_seq}, log seq {top})",
        )
        return "lagging"

    tail = conn.execute("SELECT entry_hash FROM audit_log WHERE seq = ?", (top,)).fetchone()
    if tail is not None and tail["entry_hash"] != head.last_hash:
        report.add(
            None,
            FailureKind.HEAD_MISMATCH,
            "head last_hash does not match the final record's entry_hash",
        )
        return "hash_mismatch"

    if checked_full_chain and head.record_count != count:
        report.add(
            None,
            FailureKind.HEAD_MISMATCH,
            f"head records a count of {head.record_count}, log holds {count}",
        )
        return "count_mismatch"

    return "consistent"
