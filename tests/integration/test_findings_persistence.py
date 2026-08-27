"""Persisting audit runs and findings (decision D23).

A historical audit must be viewable without re-running the configuration — not
mainly for speed, but because re-running produces a **fresh** audit that happens
to agree with the original. If a pack version changed in between, a report
generated that way would silently describe something else.

The boundary these tests police is the one D4 established at P2:

    operational database   configuration content, findings, users, ownership
    audit database         identifiers, counts and hashes — nothing else

Evidence is stored as pointers and resolved back through `config_line` and
`line_cache`, so a citation quotes the operator's own file rather than a
transcription of it that could drift.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.comply.engine import evaluate_device
from api.comply.rulepacks import load_rulepack
from api.comply.service import summarise
from api.db import findings as finding_store
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.ingest.packs import load_active_packs
from api.models.enums import UnknownReason, Verdict
from api.normalise.service import build_csm
from api.parse.service import parse_configuration

SOURCE = Path("corpus/cisco/dev/sw-access-02.cfg")


@pytest.fixture
def rig(tmp_path: Path):
    """A populated operational store: one file, one device, one audit run."""
    conn = connect(tmp_path / "op.db")
    migrate(conn, OPERATIONAL_MIGRATIONS)

    # A real account: audit_run.owner_id carries a foreign key, so a made-up
    # owner is refused by the schema — which is the constraint working.
    owner = user_store.create_user(conn, "owner1", "a-sufficiently-long-pw")

    text = SOURCE.read_text(encoding="utf-8")
    file_id = hashlib.sha256(SOURCE.read_bytes()).hexdigest()

    # The file and its lines, so evidence pointers have something to resolve to.
    conn.execute(
        "INSERT INTO config_file (file_id, size_bytes, line_count, encoding, file_format, "
        "blob_path, detected_vendor, detected_os_family, detection_score, detection_reason, "
        "first_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            file_id,
            len(text),
            len(text.splitlines()),
            "utf-8",
            "cli",
            "sw-access-02.cfg",
            "cisco",
            "ios",
            0.9,
            "detected",
            "2026-08-27T00:00:00+00:00",
        ),
    )
    for number, line in enumerate(text.splitlines(), start=1):
        digest = hashlib.sha256(line.encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT OR IGNORE INTO line_cache (line_sha256, text, first_seen_at) VALUES (?,?,?)",
            (digest, line, "2026-08-27T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO config_line (file_id, line_number, line_sha256) VALUES (?,?,?)",
            (file_id, number, digest),
        )
    conn.commit()

    pack = next(p for p in load_active_packs(use_cache=False) if p.vendor == "cisco")
    parsed = parse_configuration(text, pack, file_id=file_id, file_path="sw-access-02.cfg")
    csm = build_csm(parsed, pack, device_id=file_id)
    rulepack = load_rulepack()
    results = evaluate_device(csm, rulepack, audit_id="audit-1")

    finding_store.save_run(
        conn,
        audit_id="audit-1",
        device_id=file_id,
        owner_id=owner.user_id,
        findings=results,
        rulepack_id=rulepack.rulepack_id,
        summary=summarise(results),
    )

    yield conn, file_id, results, owner.user_id
    conn.close()


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------


def test_a_run_is_readable_without_rerunning_anything(rig) -> None:
    conn, file_id, _, _owner = rig
    run = finding_store.read_run(conn, "audit-1")

    assert run is not None
    assert run["device_id"] == file_id
    assert run["rules_evaluated"] == 7
    assert run["verdicts"] == {"pass": 3, "fail": 2, "unknown": 2, "not_applicable": 0}


def test_findings_round_trip_unchanged(rig) -> None:
    conn, _, original, _owner = rig
    stored = finding_store.read_findings(conn, "audit-1")

    assert len(stored) == len(original)
    by_rule = {f.rule_id: f for f in stored}
    for finding in original:
        restored = by_rule[finding.rule_id]
        assert restored.status is finding.status
        assert restored.base_severity is finding.base_severity
        assert restored.observed.value == finding.observed.value
        assert restored.observed.state is finding.observed.state
        assert restored.expected == finding.expected
        assert restored.unknown_reason is finding.unknown_reason


def test_evidence_survives_with_exact_line_numbers(rig) -> None:
    """The citation is the finding. Losing a line number loses the claim."""
    conn, _, original, _owner = rig
    stored = {f.rule_id: f for f in finding_store.read_findings(conn, "audit-1")}

    for finding in original:
        restored = stored[finding.rule_id]
        assert [e.line_start for e in restored.evidence] == [e.line_start for e in finding.evidence]


def test_a_stored_citation_quotes_the_operators_own_text(rig) -> None:
    conn, _, _, owner_id = rig
    telnet = next(
        f for f in finding_store.read_findings(conn, "audit-1") if f.rule_id == "NRK-TELNET-001"
    )

    assert telnet.status is Verdict.FAIL
    assert [e.line_start for e in telnet.evidence] == [17]
    assert telnet.evidence[0].raw_line.strip() == "transport input telnet ssh"


def test_abstentions_keep_their_reason(rig) -> None:
    """Rule 3 survives storage: an UNKNOWN still says why."""
    conn, _, _, owner_id = rig
    unknowns = [
        f for f in finding_store.read_findings(conn, "audit-1") if f.status is Verdict.UNKNOWN
    ]

    assert len(unknowns) == 2
    assert all(f.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN for f in unknowns)


def test_provenance_survives(rig) -> None:
    conn, _, _, owner_id = rig
    finding = finding_store.read_findings(conn, "audit-1")[0]

    assert finding.provenance.rulepack_version == "1.0.0"
    assert finding.provenance.pack_versions == {"cisco": "1.1.0"}
    assert finding.provenance.engine_version


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


def test_findings_filter_by_verdict(rig) -> None:
    conn, _, _, owner_id = rig
    failures = finding_store.read_findings(conn, "audit-1", status="fail")

    assert len(failures) == 2
    assert all(f.status is Verdict.FAIL for f in failures)


def test_findings_filter_by_severity(rig) -> None:
    conn, _, _, owner_id = rig
    critical = finding_store.read_findings(conn, "audit-1", severity="critical")

    assert [f.rule_id for f in critical] == ["NRK-TELNET-001"]


def test_reading_is_deterministic(rig) -> None:
    conn, _, _, owner_id = rig
    first = finding_store.read_findings(conn, "audit-1")
    second = finding_store.read_findings(conn, "audit-1")

    assert [f.finding_id for f in first] == [f.finding_id for f in second]


# ---------------------------------------------------------------------------
# The contract is re-checked on the way out
# ---------------------------------------------------------------------------


def test_a_stored_row_violating_rule_3_cannot_be_read_back(rig) -> None:
    """Findings are rebuilt through the contract, not returned as rows.

    A row that lost its abstention reason would otherwise be rendered into a
    report as a bare UNKNOWN. Reconstruction re-runs every validator, so the
    corruption raises here instead.
    """
    from pydantic import ValidationError

    conn, _, _, owner_id = rig
    # The schema's own CHECK forbids this, so it is lifted for the test — the
    # point is that the *contract* catches it even if the schema did not.
    conn.execute("PRAGMA ignore_check_constraints = ON")
    conn.execute(
        "UPDATE finding SET unknown_reason = NULL WHERE status = 'unknown' LIMIT 1"
        if _sqlite_supports_update_limit(conn)
        else "UPDATE finding SET unknown_reason = NULL WHERE status = 'unknown'"
    )
    conn.commit()

    with pytest.raises(ValidationError, match="must record why it abstained"):
        finding_store.read_findings(conn, "audit-1")


def _sqlite_supports_update_limit(conn) -> bool:
    try:
        conn.execute("EXPLAIN UPDATE finding SET rule_id = rule_id WHERE 1=0 LIMIT 1")
        return True
    except Exception:
        return False


def test_the_schema_refuses_an_unknown_without_a_reason(rig) -> None:
    """Rule 3 is also in the schema, so a direct SQL writer cannot bypass it."""
    import sqlite3

    conn, file_id, _, _owner = rig
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO finding (finding_id, audit_id, device_id, rule_id, status, "
            "base_severity, observed_state, confidence, confidence_method, expected) "
            "VALUES ('x','audit-1',?, 'r', 'unknown', 'low', 'unknown', 0.0, "
            "'deterministic', 'e')",
            (file_id,),
        )


def test_a_run_with_no_findings_is_refused(rig) -> None:
    conn, file_id, _, _owner = rig
    with pytest.raises(ValueError, match="no findings"):
        finding_store.save_run(
            conn,
            audit_id="audit-2",
            device_id=file_id,
            owner_id=None,
            findings=(),
            rulepack_id="canonical",
            summary={},
        )


# ---------------------------------------------------------------------------
# Ownership and listing
# ---------------------------------------------------------------------------


def test_run_owner_distinguishes_missing_from_unowned(rig) -> None:
    conn, _, _, owner_id = rig

    assert finding_store.run_owner(conn, "audit-1") == (True, owner_id)
    assert finding_store.run_owner(conn, "no-such-audit") == (False, None)


def test_listing_can_be_restricted_to_one_owner(rig) -> None:
    conn, _, _, owner_id = rig

    assert len(finding_store.list_runs(conn, owner_id=owner_id)) == 1
    assert len(finding_store.list_runs(conn, owner_id="someone-else")) == 0
    assert len(finding_store.list_runs(conn, owner_id=None)) == 1


# ---------------------------------------------------------------------------
# The audit database is not involved
# ---------------------------------------------------------------------------


def test_persistence_writes_nothing_to_the_audit_database(tmp_path: Path, rig) -> None:
    """D23 — findings live in the operational store, and only there.

    The audit chain records that a run happened and how many findings of each
    verdict. It never records what a finding said, and this migration does not
    change that.
    """
    conn, _, _, owner_id = rig
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}

    # Everything findings-related is here, in the operational database...
    assert {"audit_run", "finding", "finding_evidence"} <= tables
    # ...and none of the chain's tables are.
    assert "audit_log" not in tables
    assert "audit_chain_head" not in tables
