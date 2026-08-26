"""Audit-layer errors and the vocabulary of integrity failures."""

from __future__ import annotations

from enum import StrEnum


class AuditError(RuntimeError):
    """Base for every audit-layer failure."""


class PayloadNotJsonNativeError(AuditError, ValueError):
    """A payload carried a value JSON cannot represent (decision D2).

    Raised at the persistence boundary rather than silently stringified. A
    payload that hashes via ``str()`` makes distinct values collide — a
    ``datetime`` and its string form produce the same digest — so the audit
    layer refuses the value and asks the caller to serialise deliberately.
    """


class ChainIntegrityError(AuditError):
    """The stored chain is not internally consistent."""


class FailureKind(StrEnum):
    """What kind of damage verification found.

    These names appear in reports and in test assertions, so they are part of
    the observable contract rather than free-text diagnostics.
    """

    MODIFIED_PAYLOAD = "modified_payload"
    """Stored payload no longer hashes to its recorded payload_hash."""

    MODIFIED_RECORD = "modified_record"
    """A hashed field changed; entry_hash no longer matches the contents."""

    BROKEN_LINK = "broken_link"
    """A record's prev_hash does not match its predecessor's entry_hash."""

    DELETED_RECORD = "deleted_record"
    """A gap in the seq sequence."""

    BROKEN_GENESIS = "broken_genesis"
    """The first record does not open the chain correctly."""

    HEAD_MISMATCH = "head_mismatch"
    """audit_chain_head disagrees with the log — typically a deleted tail."""

    TRUNCATED = "truncated"
    """The head records history the log no longer contains."""

    MISSING_TRIGGER = "missing_trigger"
    """An append-only trigger has been dropped: someone prepared to edit."""

    ALGO_MISMATCH = "algo_mismatch"
    """A record claims a hash algorithm the verifier was not configured for."""

    UNREADABLE = "unreadable"
    """The chain could not be read at all."""
