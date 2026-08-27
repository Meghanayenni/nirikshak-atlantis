"""End-to-end compliance over the Cisco development corpus (P6).

Ingest → parse → normalise → comply, against the two files the pack was authored
from. Exact verdicts, exact citations.

The two devices disagree, which is what makes them worth auditing: `rtr-core-01`
passes everything, `sw-access-02` produces two genuine FAILs (telnet enabled, a
thirty-minute idle timeout) and two honest UNKNOWNs. A rule with its sense
backwards fails here rather than passing on uniform data.

**What this cannot demonstrate.** No platform defaults ship, so no field ever
reaches ABSENT_DEFAULT and the absence-aware `EVALUATE` branch never fires on
real data. Its tests are in `test_verdict_table.py` against synthetic fields, and
neither this module nor any report may present the corpus as evidence for it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from api.comply.engine import evaluate_device
from api.comply.rulepacks import load_rulepack
from api.comply.service import run_audit, summarise
from api.ingest.packs import load_active_packs
from api.models.enums import AuditAction, UnknownReason, Verdict
from api.normalise.service import build_csm
from api.parse.service import parse_configuration

DEV = Path("corpus/cisco/dev")


@pytest.fixture(scope="module")
def rulepack():
    return load_rulepack()


@pytest.fixture(scope="module")
def cisco():
    return next(p for p in load_active_packs(use_cache=False) if p.vendor == "cisco")


def audit(name: str, pack, rulepack):
    path = DEV / name
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(
        path.read_text(encoding="utf-8"), pack, file_id=file_id, file_path=str(path)
    )
    csm = build_csm(parsed, pack, device_id=file_id)
    return evaluate_device(csm, rulepack, audit_id="audit-test")


@pytest.fixture(scope="module")
def rtr(cisco, rulepack):
    return audit("rtr-core-01.cfg", cisco, rulepack)


@pytest.fixture(scope="module")
def sw(cisco, rulepack):
    return audit("sw-access-02.cfg", cisco, rulepack)


def by_rule(findings):
    return {f.rule_id: f for f in findings}


# ---------------------------------------------------------------------------
# The compliant device
# ---------------------------------------------------------------------------


def test_rtr_core_passes_every_rule(rtr) -> None:
    assert summarise(rtr) == {"pass": 7, "fail": 0, "unknown": 0, "not_applicable": 0}


def test_every_pass_cites_a_real_line(rtr) -> None:
    """Rule 2 at the top of the stack, resting on P4's lossless guarantee."""
    for finding in rtr:
        assert finding.status is Verdict.PASS
        assert finding.evidence, f"{finding.rule_id} passed with nothing behind it"
        assert all(e.line_start >= 1 for e in finding.evidence)


def test_the_boundary_case_passes(rtr) -> None:
    """rtr-core-01's idle timeout is exactly 600 — `lte` must include the limit."""
    finding = by_rule(rtr)["NRK-TIMEOUT-001"]

    assert finding.observed.value == 600
    assert finding.status is Verdict.PASS
    assert [e.line_start for e in finding.evidence] == [39]


# ---------------------------------------------------------------------------
# The non-compliant device — two genuine failures
# ---------------------------------------------------------------------------


def test_sw_access_verdict_distribution(sw) -> None:
    assert summarise(sw) == {"pass": 3, "fail": 2, "unknown": 2, "not_applicable": 0}


def test_telnet_enabled_fails_with_its_citation(sw) -> None:
    """The sharpest disagreement in the corpus, and the reason both files exist."""
    finding = by_rule(sw)["NRK-TELNET-001"]

    assert finding.status is Verdict.FAIL
    assert finding.observed.value is True
    assert [e.line_start for e in finding.evidence] == [17]
    assert "telnet" in finding.evidence[0].raw_line
    assert finding.is_actionable


def test_idle_timeout_fails_with_its_citation(sw) -> None:
    finding = by_rule(sw)["NRK-TIMEOUT-001"]

    assert finding.status is Verdict.FAIL
    assert finding.observed.value == 1800
    assert [e.line_start for e in finding.evidence] == [18]
    assert finding.expected == "lte 600"


@pytest.mark.parametrize("rule_id", ["NRK-SSH-001", "NRK-BANNER-001"])
def test_absent_controls_abstain_rather_than_failing(sw, rule_id) -> None:
    """The directive is missing and nothing documents what that means here.

    Reporting FAIL would be the convenient answer and the wrong one: the device
    may be secure by default, and we have not sourced the documentation that
    would say.
    """
    finding = by_rule(sw)[rule_id]

    assert finding.status is Verdict.UNKNOWN
    assert finding.unknown_reason is UnknownReason.CAPABILITY_UNKNOWN
    assert finding.status is not Verdict.FAIL
    assert finding.remediation is None


def test_no_absence_produces_a_pass(sw) -> None:
    """Rule 3 — UNKNOWN must not quietly become PASS for a nicer report."""
    for finding in sw:
        if finding.status is Verdict.PASS:
            assert finding.evidence, f"{finding.rule_id} passed with no evidence"


# ---------------------------------------------------------------------------
# Provenance, determinism, applicability
# ---------------------------------------------------------------------------


def test_findings_record_the_pack_that_read_the_line(rtr) -> None:
    for finding in rtr:
        assert finding.provenance.pack_versions == {"cisco": "1.1.0"}
        assert finding.provenance.rulepack_version == "1.0.0"
        assert finding.provenance.engine_version


def test_a_second_run_produces_identical_findings(cisco, rulepack) -> None:
    first = audit("sw-access-02.cfg", cisco, rulepack)
    second = audit("sw-access-02.cfg", cisco, rulepack)

    assert [(f.rule_id, f.status, f.observed.value) for f in first] == [
        (f.rule_id, f.status, f.observed.value) for f in second
    ]


def test_a_detection_only_device_abstains_on_everything(rulepack) -> None:
    """Arista is recognised but not parseable — every control is unreadable."""
    pack = next(p for p in load_active_packs(use_cache=False) if p.vendor == "arista")
    path = Path("corpus/arista/dev/sw-leaf-01.cfg")
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(
        path.read_text(encoding="utf-8"), pack, file_id=file_id, file_path=str(path)
    )
    csm = build_csm(parsed, pack, device_id=file_id)
    findings = evaluate_device(csm, rulepack, audit_id="audit-test")

    assert len(findings) == len(rulepack.rules)
    assert all(f.status is Verdict.UNKNOWN for f in findings)
    assert all(f.unknown_reason is UnknownReason.NO_MATCH for f in findings)
    assert all(f.needs_training for f in findings), "a parse gap routes to training"


# ---------------------------------------------------------------------------
# Audit integration — and what must not reach the audit database
# ---------------------------------------------------------------------------


def test_a_run_appends_exactly_one_audit_record(tmp_path, cisco, rulepack) -> None:
    from api.audit.chain import AuditChain
    from api.db.connection import connect
    from api.db.migrate import AUDIT_MIGRATIONS, migrate

    conn = connect(tmp_path / "audit.db")
    migrate(conn, AUDIT_MIGRATIONS)
    chain = AuditChain(conn)

    path = DEV / "sw-access-02.cfg"
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(
        path.read_text(encoding="utf-8"), cisco, file_id=file_id, file_path=str(path)
    )
    csm = build_csm(parsed, cisco, device_id=file_id)

    run_id, findings = run_audit(csm, rulepack, chain=chain)

    from api.audit import store

    assert store.record_count(conn) == 1
    # The chain's first record is seq 0, not 1 — it starts from GENESIS_HASH.
    stored = store.read_one(conn, 0)
    assert stored is not None
    assert stored.record.action is AuditAction.AUDIT_RUN
    assert stored.record.subject.id == run_id, "the chain and the findings share one id"
    assert len(findings) == 7
    conn.close()


def test_no_configuration_content_reaches_the_audit_database(tmp_path, cisco, rulepack) -> None:
    """D4 — the audit store holds identifiers, counts and hashes. Nothing else.

    A verdict summary says three checks failed. It never says which value was on
    which line: that lives in the findings, in the operational store, where
    configuration-derived data belongs.
    """
    from api.audit.chain import AuditChain
    from api.db.connection import connect
    from api.db.migrate import AUDIT_MIGRATIONS, migrate

    conn = connect(tmp_path / "audit.db")
    migrate(conn, AUDIT_MIGRATIONS)
    chain = AuditChain(conn)

    path = DEV / "sw-access-02.cfg"
    source = path.read_text(encoding="utf-8")
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(source, cisco, file_id=file_id, file_path=str(path))
    csm = build_csm(parsed, cisco, device_id=file_id)
    run_audit(csm, rulepack, chain=chain)

    blob = "\n".join(str(row) for row in conn.execute("SELECT * FROM audit_log").fetchall()).lower()

    leaked = [
        line.strip()
        for line in source.splitlines()
        if line.strip() and len(line.strip()) > 8 and line.strip().lower() in blob
    ]
    assert leaked == [], f"configuration text reached the audit database: {leaked}"

    # Spot-check the specific values a finding knows and the chain must not.
    for secret in ("transport input telnet", "exec-timeout 30 0", "192.0.2.10"):
        assert secret.lower() not in blob

    conn.close()


def test_the_audit_payload_is_counts_and_identifiers(cisco, rulepack) -> None:
    from api.comply.service import audit_payload

    path = DEV / "sw-access-02.cfg"
    file_id = hashlib.sha256(path.read_bytes()).hexdigest()
    parsed = parse_configuration(
        path.read_text(encoding="utf-8"), cisco, file_id=file_id, file_path=str(path)
    )
    csm = build_csm(parsed, cisco, device_id=file_id)
    findings = evaluate_device(csm, rulepack, audit_id="a1")
    payload = audit_payload(csm, rulepack, findings)

    assert payload["verdicts"] == {"pass": 3, "fail": 2, "unknown": 2, "not_applicable": 0}
    assert payload["rules_evaluated"] == 7
    assert set(payload) == {
        "device_id",
        "engine_version",
        "rulepack_id",
        "rulepack_version",
        "pack_versions",
        "rules_evaluated",
        "verdicts",
    }
