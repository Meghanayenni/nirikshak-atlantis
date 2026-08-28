"""The confirmation loop, end to end.

    residue -> queue -> a human decides -> compile -> DRAFT -> VALIDATED
            -> activate -> re-parse -> the line is no longer unknown

This module is the only place those steps meet. `api/learn/` proposes and knows
nothing about storage; `api/db/` stores and knows nothing about clustering;
`api/ingest/` loads packs and knows nothing about training. Composing them is a
job, and giving it a package of its own is what let decision D44 keep
`learn -> db` forbidden — the advisory branch still cannot write anything.

**Every mutation is audited before it is useful.** A confirmation appends
`ADMIN_CONFIRMED` or `ADMIN_CORRECTED`; compiling appends `PACK_CREATED`;
activation appends `PACK_ACTIVATED`; rollback appends `PACK_ROLLED_BACK`. Those
five actions have existed in the enum since P1 and were emitted by nothing until
now.

**No configuration content enters the audit chain** (decision D4). The payloads
here carry identifiers, field names, versions, digests and counts — which line
was confirmed is answerable from the operational store, where configuration-
derived data belongs. The chain attests that a mapping was confirmed, by whom,
for which field; it does not quote the device.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from api.audit.chain import AuditChain
from api.config import settings
from api.db import training as store
from api.ingest.packs import (
    PACKS_ROOT,
    TRAINED_ROOT,
    clear_pack_cache,
    find_pack,
    load_active_packs,
)
from api.learn.cluster import cluster_id_for
from api.learn.index import ExampleIndex, build_index
from api.learn.signature import signature
from api.models.audit import Actor, Subject
from api.models.csm import UnknownLine
from api.models.enums import ActorType, AuditAction, ExampleSource, TrainingOutcome
from api.models.pack import PatternDef, VendorPack
from api.models.training import Suggestion, TrainingExample
from api.train.activation import (
    ActivationResult,
    activate,
    draft_with_pattern,
    find_version,
    rollback,
    validate,
    write_pack,
)
from api.train.compile import CompileRequest, compile_pattern
from api.train.errors import ActivationError, QueueError
from api.train.queue import TrainingQueue, build_queue


def new_example_id() -> str:
    return f"trn-{uuid.uuid4().hex[:16]}"


# ---------------------------------------------------------------------------
# The queue
# ---------------------------------------------------------------------------


def record_residue(
    conn: sqlite3.Connection,
    residue: tuple[UnknownLine, ...],
    *,
    file_id: str,
    vendor: str | None = None,
    os_family: str | None = None,
) -> int:
    """Persist one file's residue as the durable training queue (D49).

    The file's previous entries are cleared first. Re-auditing after activating a
    pack is the normal case and the residue is then genuinely different — smaller,
    if the confirmation worked — and an entry the new parse no longer produces
    must not survive to be confirmed twice.

    Signatures and cluster ids are computed here, where importing `api/learn/` is
    allowed, and handed to the storage layer as plain strings.
    """
    store.clear_unknown_lines(conn, file_id)
    if not residue:
        return 0

    signatures = {line.line_number: signature(line.raw_line_scrubbed) for line in residue}
    clusters = {number: cluster_id_for(sig) for number, sig in signatures.items()}

    return store.record_unknown_lines(
        conn,
        residue,
        signatures=signatures,
        cluster_ids=clusters,
        vendor=vendor,
        os_family=os_family,
    )


def current_index(conn: sqlite3.Connection) -> ExampleIndex:
    """Seed examples plus every mapping an administrator has confirmed.

    This is the sentence ADR 0017 asks the training screen to print, and it grows
    for exactly one reason: somebody confirmed something.
    """
    return build_index(
        load_active_packs(use_cache=False),
        confirmations=store.examples(conn, confirmed_only=True),
    )


def training_queue(
    conn: sqlite3.Connection,
    *,
    file_id: str | None = None,
    vendor: str | None = None,
) -> TrainingQueue:
    """The queue as an administrator sees it, suggestions or stated absence."""
    lines = store.unknown_lines(conn, file_id=file_id, vendor=vendor)
    return build_queue(lines, current_index(conn), airgap=settings.airgap)


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """One administrator's answer to one queue entry.

    `confirmed_by` is a username, never a service account and never a model. The
    contract enforces that it is non-empty; the router enforces that it is the
    authenticated admin who is actually asking.
    """

    cluster_id: str
    line: str
    vendor: str
    os_family: str
    outcome: TrainingOutcome
    field: str | None = None
    value_semantics: str | None = None
    suggestions_shown: tuple[Suggestion, ...] = ()


def confirm(
    conn: sqlite3.Connection,
    decision: Decision,
    *,
    confirmed_by: str,
    chain: AuditChain | None = None,
) -> TrainingExample:
    """Record what a human decided. This is where trust originates.

    The audit record is appended *before* the row is written and its sequence is
    stored on the example, so a decision in the database always points at the
    attestation that it happened. A confirmation with no audit sequence would be a
    mapping nobody can trace, and `PatternProvenance.audit_seq` exists precisely
    so a compiled pattern can name it.
    """
    audit_seq: int | None = None
    if chain is not None:
        action = (
            AuditAction.ADMIN_CORRECTED
            if decision.outcome is TrainingOutcome.CORRECTED
            else AuditAction.ADMIN_CONFIRMED
        )
        record = chain.append(
            actor=Actor(type=ActorType.HUMAN, id=confirmed_by, role="admin"),
            action=action,
            subject=Subject(kind="training_example", id=decision.cluster_id),
            payload={
                "cluster_id": decision.cluster_id,
                "vendor": decision.vendor,
                "os_family": decision.os_family,
                "field": decision.field,
                "outcome": str(decision.outcome),
                "suggestions_shown": len(decision.suggestions_shown),
                "top3_hit": bool(
                    decision.field is not None
                    and any(s.field == decision.field for s in decision.suggestions_shown)
                ),
            },
        )
        audit_seq = record.seq

    example = TrainingExample(
        example_id=new_example_id(),
        vendor=decision.vendor,
        os_family=decision.os_family,
        raw_line_scrubbed=decision.line,
        normalised_line=signature(decision.line),
        cluster_id=decision.cluster_id,
        field=decision.field,
        value_semantics=decision.value_semantics,
        suggestions_shown=decision.suggestions_shown,
        outcome=decision.outcome,
        confirmed_by=confirmed_by,
        confirmed_at=datetime.now(UTC),
        source=ExampleSource.ADMIN,
        audit_seq=audit_seq,
    )
    store.save_example(conn, example)
    return example


# ---------------------------------------------------------------------------
# Compilation and activation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DraftResult:
    """A compiled pattern and the DRAFT pack holding it, before anyone trusts it."""

    pack: VendorPack
    pattern: PatternDef
    edited: bool
    path: str = ""

    @property
    def regex(self) -> str:
        """What the administrator is shown before activation (DEVELOPER_GUIDE.md §4)."""
        return self.pattern.match.pattern


def compile_confirmation(
    conn: sqlite3.Connection,
    example: TrainingExample,
    request: CompileRequest,
    *,
    pattern_override: str | None = None,
    chain: AuditChain | None = None,
    actor_id: str = "nirikshak",
    trained_root: Path | None = None,
) -> DraftResult:
    """Turn one recorded decision into a DRAFT pack version.

    Draft only. Nothing here changes how a single device is parsed until somebody
    calls `activate_draft`, which is the entire point of the two-step lifecycle
    (D51).
    """
    base = find_pack(example.vendor, example.os_family, load_active_packs(use_cache=False))
    if base is None:
        raise ActivationError(
            f"no active pack for {example.vendor}/{example.os_family}; a confirmation "
            "extends an existing platform description and cannot create one"
        )

    pattern = compile_pattern(
        example,
        request,
        existing_ids=tuple(p.id for p in base.patterns),
        pattern_override=pattern_override,
    )
    draft = draft_with_pattern(base, pattern)

    # The draft is written to disk as DRAFT so the review step can span two
    # requests: an administrator reads the generated regex, and activates — or
    # does not — separately. A draft held only in memory would force compile and
    # activate into one call and quietly delete the review D51 exists for.
    draft_path = write_pack(draft, trained_root)

    if chain is not None:
        chain.append(
            actor=Actor(type=ActorType.HUMAN, id=actor_id, role="admin"),
            action=AuditAction.PACK_CREATED,
            subject=Subject(kind="vendor_pack", id=f"{draft.pack_id}@{draft.pack_version}"),
            payload={
                "pack_id": draft.pack_id,
                "pack_version": draft.pack_version,
                "parent_version": draft.parent_version,
                "status": str(draft.status),
                "pattern_id": pattern.id,
                "field": pattern.field,
                "pattern_source": str(pattern.source),
                "training_example_id": example.example_id,
                "confirmation_audit_seq": example.audit_seq,
                # D51 — an edited pattern is recorded as edited. The regex itself
                # is not a device fact but it IS what will read every future
                # configuration, so which one was activated must be attestable.
                "pattern_edited": pattern_override is not None,
                "pattern": pattern.match.pattern,
            },
        )

    return DraftResult(
        pack=draft,
        pattern=pattern,
        edited=pattern_override is not None,
        path=str(draft_path),
    )


def load_draft(pack_id: str, version: str, *, trained_root: Path | None = None) -> VendorPack:
    """Read back a DRAFT written by `compile_confirmation`."""
    found = find_version(
        pack_id, version, PACKS_ROOT, trained_root if trained_root is not None else TRAINED_ROOT
    )
    if found is None:
        raise ActivationError(f"no pack {pack_id} {version} exists on disk")
    return found[0]


def activate_draft(
    draft: VendorPack,
    *,
    activated_by: str,
    chain: AuditChain | None = None,
    trained_root: Path | None = None,
    builtin_root: Path | None = None,
) -> ActivationResult:
    """Validate, write, activate, and invalidate the pack cache.

    The cache clear is what makes the Concept Report's "no redeployment, no
    restart" literally true: the next file ingested is detected and parsed by the
    pack activated a moment ago, in the same process.
    """
    validated = validate(draft)
    result = activate(validated, trained_root=trained_root, builtin_root=builtin_root)
    clear_pack_cache()

    if chain is not None:
        chain.append(
            actor=Actor(type=ActorType.HUMAN, id=activated_by, role="admin"),
            action=AuditAction.PACK_ACTIVATED,
            subject=Subject(kind="vendor_pack", id=f"{result.pack_id}@{result.version}"),
            payload={
                "pack_id": result.pack_id,
                "pack_version": result.version,
                "previous_version": result.previous_version,
                "checksum": result.checksum,
                "pattern_count": len(result.pattern_ids),
            },
        )
    return result


def rollback_pack(
    pack_id: str,
    to_version: str,
    *,
    rolled_back_by: str,
    chain: AuditChain | None = None,
    trained_root: Path | None = None,
    builtin_root: Path | None = None,
) -> ActivationResult:
    """Return a platform to an earlier pack version, exactly as it was."""
    result = rollback(pack_id, to_version, trained_root=trained_root, builtin_root=builtin_root)
    clear_pack_cache()

    if chain is not None:
        chain.append(
            actor=Actor(type=ActorType.HUMAN, id=rolled_back_by, role="admin"),
            action=AuditAction.PACK_ROLLED_BACK,
            subject=Subject(kind="vendor_pack", id=f"{result.pack_id}@{result.version}"),
            payload={
                "pack_id": result.pack_id,
                "pack_version": result.version,
                "rolled_back_from": result.previous_version,
                "checksum": result.checksum,
            },
        )
    return result


__all__ = [
    "Decision",
    "DraftResult",
    "QueueError",
    "activate_draft",
    "compile_confirmation",
    "load_draft",
    "confirm",
    "current_index",
    "new_example_id",
    "record_residue",
    "rollback_pack",
    "training_queue",
]
