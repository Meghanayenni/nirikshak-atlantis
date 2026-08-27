"""Running an audit — evaluation plus its audit-chain record.

Kept apart from `engine.py` so the evaluator itself stays a pure function of
(model, rulepack). That separation is what lets every verdict test run without a
database, and it keeps the thing Rule 1 is about free of any I/O that could
become a way in.

**No configuration content reaches the audit database** (decision D4). The chain
holds identifiers, counts and hashes: which device, which rulepack, how many
findings of each verdict. Not a value, not a raw line, not an expectation. The
operational store holds configuration; the audit store holds attestations about
it, and keeping them in separate files makes that checkable by opening one.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from api.audit.chain import AuditChain
from api.comply.engine import ENGINE_VERSION, evaluate_device, new_audit_id
from api.models.audit import Subject
from api.models.csm import CanonicalSecurityModel
from api.models.enums import AuditAction, Verdict
from api.models.finding import Finding
from api.models.rule import Rulepack


def run_audit(
    csm: CanonicalSecurityModel,
    rulepack: Rulepack,
    *,
    chain: AuditChain | None = None,
    audit_id: str | None = None,
) -> tuple[str, tuple[Finding, ...]]:
    """Evaluate one device and, if a chain is supplied, record that it happened.

    Evaluation first, audit second — the ordering `api/ingest/service.py` uses,
    for the same reason: a record is written only for work that actually
    completed, so the log never attests to something that then failed.
    """
    run_id = audit_id or new_audit_id()
    evaluated_at = datetime.now(UTC)

    findings = evaluate_device(csm, rulepack, audit_id=run_id, evaluated_at=evaluated_at)

    if chain is not None:
        chain.append_system(
            AuditAction.AUDIT_RUN,
            Subject(kind="audit", id=run_id),
            payload=audit_payload(csm, rulepack, findings),
        )

    return run_id, findings


def audit_payload(
    csm: CanonicalSecurityModel,
    rulepack: Rulepack,
    findings: tuple[Finding, ...],
) -> dict[str, object]:
    """What the chain attests to: that this ran, over what, with what shape.

    Counts and identifiers only. A verdict summary is not configuration content —
    it says three checks failed, never which value was on which line. Anyone
    wanting the detail reads the findings, which live in the operational store
    where configuration-derived data belongs.
    """
    counts = Counter(f.status for f in findings)
    return {
        "device_id": csm.device.device_id,
        "engine_version": ENGINE_VERSION,
        "rulepack_id": rulepack.rulepack_id,
        "rulepack_version": rulepack.version,
        "pack_versions": dict(csm.source.pack_versions),
        "rules_evaluated": len(findings),
        "verdicts": {verdict.value: counts.get(verdict, 0) for verdict in Verdict},
    }


def summarise(findings: tuple[Finding, ...]) -> dict[str, int]:
    """Verdict counts, for a report header or a test assertion."""
    counts = Counter(f.status for f in findings)
    return {verdict.value: counts.get(verdict, 0) for verdict in Verdict}
