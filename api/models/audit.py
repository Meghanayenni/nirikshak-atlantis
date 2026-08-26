"""Audit records — an append-only hash chain.

Every AI suggestion, human correction, pack change and audit result enters this
chain. Each record binds the hash of its payload to the hash of the record
before it, so a retroactive edit anywhere breaks verification everywhere after.

The contract is self-verifying: a record whose `payload_hash` disagrees with its
`payload` cannot be constructed. The chain-walking logic itself belongs to P2;
what lives here is the per-record invariant it will rely on.

Canonical JSON — sorted keys, tight separators, UTF-8, no NaN — is required.
Without it the chain fails to verify across Python versions for reasons that
have nothing to do with tampering, which is the worst kind of false alarm in an
integrity mechanism.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from pydantic import Field as Constraint

from api.models.enums import ActorType, AuditAction

SHA256_HEX = r"^[0-9a-f]{64}$"

GENESIS_HASH = "0" * 64
"""`prev_hash` of the first record. A chain has to start somewhere."""

CANONICAL_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
"""One fixed representation for every hashed timestamp (decision D1).

Always UTC, always a `T` separator, always six fractional digits, always a
literal `Z`. No other form is ever hashed.
"""


class NaiveTimestampError(ValueError):
    """A timestamp arrived without a timezone, so its instant is ambiguous."""


def canonical_timestamp(value: datetime | str) -> str:
    """Reduce a timestamp to the single string form used for hashing (D1).

    Before this existed, `compute_entry_hash` hashed a string timestamp exactly
    as supplied while Pydantic separately parsed it into a `datetime`. Three
    spellings of one instant — `2026-08-26T12:00:00+00:00`, SQLite's
    `2026-08-26 12:00:00+00:00`, and `2026-08-26T12:00:00Z` — therefore produced
    three different `entry_hash` values while storing the identical moment.

    That made a normal database round-trip look like tampering, which is the
    false alarm this module's docstring warns against. Everything now passes
    through here first, so the same instant always yields the same hash however
    it was spelled on the way in.
    """
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"timestamp {value!r} is not a valid ISO 8601 datetime") from exc

    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise NaiveTimestampError(
            f"timestamp {value!r} is timezone-naive; an audit record must fix the "
            "instant it attests to (D1)"
        )

    return value.astimezone(UTC).strftime(CANONICAL_TS_FORMAT)


def canonical_json(payload: Any) -> str:
    """Deterministic JSON: sorted keys, no incidental whitespace, UTF-8 safe."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    )


def hash_payload(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class Actor(BaseModel):
    """Who or what performed the action.

    `MODEL` is a legitimate actor for `ai_suggested` and nothing else — the
    audit trail is where the distinction between a proposal and a decision is
    made permanent.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    type: ActorType
    id: str = Constraint(min_length=1)
    role: str | None = None


class Subject(BaseModel):
    """What the action was performed on."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = Constraint(min_length=1, description="e.g. 'vendor_pack', 'audit', 'file'")
    id: str = Constraint(min_length=1)


MODEL_PERMITTED_ACTIONS = frozenset({AuditAction.AI_SUGGESTED})
"""The only actions a model actor may take. Enforced below."""


class AuditRecord(BaseModel):
    """One link in the hash chain."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Constraint(ge=0, description="Monotonic and gapless")
    timestamp: datetime

    actor: Actor
    action: AuditAction
    subject: Subject

    payload: dict[str, Any] = Constraint(
        default_factory=dict, description="Action-specific; secrets redacted before storage"
    )
    payload_hash: str = Constraint(pattern=SHA256_HEX)
    prev_hash: str = Constraint(pattern=SHA256_HEX)
    entry_hash: str = Constraint(pattern=SHA256_HEX)

    # -- derivation --------------------------------------------------------

    @staticmethod
    def compute_entry_hash(
        *,
        seq: int,
        timestamp: datetime | str,
        actor: Actor | dict[str, Any],
        action: AuditAction | str,
        subject: Subject | dict[str, Any],
        payload_hash: str,
        prev_hash: str,
    ) -> str:
        """Hash of everything that identifies this record, including its predecessor."""
        actor_d = actor.model_dump(mode="json") if isinstance(actor, Actor) else actor
        subject_d = subject.model_dump(mode="json") if isinstance(subject, Subject) else subject
        return hash_payload(
            {
                "seq": seq,
                "timestamp": canonical_timestamp(timestamp),
                "actor": actor_d,
                "action": str(action),
                "subject": subject_d,
                "payload_hash": payload_hash,
                "prev_hash": prev_hash,
            }
        )

    @model_validator(mode="before")
    @classmethod
    def _derive_hashes(cls, data: Any) -> Any:
        """Fill in the hashes when absent; verify them when supplied."""
        if not isinstance(data, dict):
            return data
        out = dict(data)

        payload = out.get("payload", {})
        expected_payload = hash_payload(payload)
        if out.get("payload_hash") is None:
            out["payload_hash"] = expected_payload
        elif out["payload_hash"] != expected_payload:
            raise ValueError(
                "payload_hash does not match payload — the record and the data it "
                "attests to have diverged"
            )

        # D1 — settle the timestamp before anything is hashed, and let a naive
        # or unparseable value report itself plainly rather than surfacing later
        # as a missing entry_hash.
        if out.get("timestamp") is not None:
            canonical_timestamp(out["timestamp"])

        required = ("seq", "timestamp", "actor", "action", "subject", "prev_hash")
        if all(out.get(k) is not None for k in required):
            try:
                expected_entry = cls.compute_entry_hash(
                    seq=out["seq"],
                    timestamp=out["timestamp"],
                    actor=out["actor"],
                    action=out["action"],
                    subject=out["subject"],
                    payload_hash=out["payload_hash"],
                    prev_hash=out["prev_hash"],
                )
            except (AttributeError, TypeError, ValueError):
                return out  # let field validation report the real problem

            if out.get("entry_hash") is None:
                out["entry_hash"] = expected_entry
            elif out["entry_hash"] != expected_entry:
                raise ValueError(
                    "entry_hash does not match the record contents — this is what "
                    "tampering looks like"
                )
        return out

    @field_validator("timestamp")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        """D1 — a naive timestamp does not identify an instant, so it is refused."""
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            raise NaiveTimestampError(
                "audit timestamps must be timezone-aware; use datetime.now(UTC)"
            )
        return value

    @model_validator(mode="after")
    def _check_actor(self) -> AuditRecord:
        if self.actor.type is ActorType.MODEL and self.action not in MODEL_PERMITTED_ACTIONS:
            raise ValueError(
                f"a model actor may not perform {self.action}; models suggest, "
                "humans decide, the engine evaluates (Rule 1)"
            )
        return self

    # -- verification ------------------------------------------------------

    @property
    def is_genesis(self) -> bool:
        return self.prev_hash == GENESIS_HASH

    def verify_self(self) -> bool:
        """Recompute both hashes from the record's own contents."""
        return self.payload_hash == hash_payload(self.payload) and self.entry_hash == (
            self.compute_entry_hash(
                seq=self.seq,
                timestamp=self.timestamp,
                actor=self.actor,
                action=self.action,
                subject=self.subject,
                payload_hash=self.payload_hash,
                prev_hash=self.prev_hash,
            )
        )

    def links_to(self, previous: AuditRecord) -> bool:
        """Does this record correctly follow `previous`?"""
        return self.prev_hash == previous.entry_hash and self.seq == previous.seq + 1
