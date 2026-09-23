"""The Prioritise stage over HTTP, on the real corpus (P12).

Everything asserted here is a **refusal**, and that is the point of the file.
The corpus contains no access list and no interface on any device in any split,
and its largest cohort holds four devices against a floor of five. So:

  * no finding gets an exposure score;
  * no finding gets a priority rank;
  * no cohort produces a baseline;
  * no device is called an outlier.

A test suite that could not tell that state apart from a working ranking would be
the real failure, so each assertion below checks that the *reason* travelled with
the refusal.

Two defect fixes are also verified here, both discovered outside their own phase:
DEF-14 (the audit chain never recorded that an audit ran) and DEF-15 (the
detected device identity never reached the canonical model).

The PAN-OS holdout is not uploaded, opened or named.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from api.config import settings
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.main import app
from api.models.enums import Role
from api.prioritise.baseline import MIN_COHORT_SIZE

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS = REPO_ROOT / "corpus"

ALICE = ("alice", "correct-horse-battery")
ROOT = ("root", "admin-long-password-1")


def _non_holdout_files() -> list[Path]:
    """Every corpus configuration except the held-out vendor's.

    The holdout entries are skipped from the manifest without being opened —
    the same shape the P10 and P11 guards use.
    """
    manifest = yaml.safe_load((CORPUS / "MANIFEST.yaml").read_text(encoding="utf-8"))
    return [CORPUS / entry["path"] for entry in manifest["files"] if entry["split"] != "holdout"]


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")

    conn = connect(tmp_path / "nirikshak.db")
    migrate(conn, OPERATIONAL_MIGRATIONS)
    user_store.create_user(conn, ALICE[0], ALICE[1])
    user_store.create_user(conn, ROOT[0], ROOT[1], role=Role.ADMIN)
    conn.close()

    with TestClient(app) as test_client:
        yield test_client


def _upload_fleet(client: TestClient) -> list[str]:
    ids = []
    for path in _non_holdout_files():
        response = client.post(
            "/ingest/upload",
            files={"files": (path.name, path.read_bytes(), "text/plain")},
            auth=ROOT,
        )
        assert response.status_code == 200, response.text
        # Two corpus files have no active pack and so cannot be audited:
        # dc1-leaf-01.cfg is NX-OS, and core-rtr-01.conf is brace-nested JunOS
        # that the juniper detect signatures do not yet discriminate. Both are
        # still uploaded — the fleet view must account for them as skipped —
        # but auditing them would (correctly) answer 409.
        ids.extend(
            a["file_id"]
            for a in response.json()["accepted"]
            if a["detection"]["outcome"] == "detected"
        )
    return ids


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------


def test_the_fleet_view_is_admin_only(client: TestClient) -> None:
    """A peer group scoped to one user's uploads is a different, weaker claim."""
    assert client.get("/fleet/baseline").status_code == 401
    assert client.get("/fleet/baseline", auth=ALICE).status_code == 403
    assert client.get("/fleet/baseline", auth=ROOT).status_code == 200


# ---------------------------------------------------------------------------
# Peer baselines on the real corpus
# ---------------------------------------------------------------------------


def test_baselines_are_established_now_that_a_cohort_clears_the_floor(
    client: TestClient,
) -> None:
    """P15 — the first baselines this project has ever computed.

    This test replaces `test_every_cohort_is_below_the_floor_and_says_so`, which
    asserted the opposite and was correct for as long as the largest cohort held
    four Cisco devices against a floor of five. Registering the P15 corpus took
    that cohort to nine, so the floor is cleared and the machinery runs.

    **Zero outliers is a result here, not an abstention**, and the two are
    reported differently: a cohort below the floor carries an explanation and an
    outcome that is not `compared`, whereas these baselines were compared and
    found no deviation.
    """
    _upload_fleet(client)
    body = client.get("/fleet/baseline", auth=ROOT).json()

    assert body["devices"] == 17
    # dc1-leaf-01.cfg (NX-OS) and core-rtr-01.conf (brace-nested JunOS) have no
    # active pack, so they are counted as skipped rather than silently dropped.
    assert body["skipped_files"] == 2
    assert body["minimum_cohort_size"] == MIN_COHORT_SIZE
    assert body["comparable_baselines"] == 8
    assert body["outliers"] == []
    assert "baseline(s) established" in body["summary"]

    compared = [b for b in body["baselines"] if b["outcome"] == "compared"]
    assert len(compared) == body["comparable_baselines"]
    for baseline in body["baselines"]:
        assert baseline["explanation"]


def test_cohorts_are_platforms_and_are_never_mixed(client: TestClient) -> None:
    """Comparing a Cisco router against a Juniper firewall would measure vendor."""
    _upload_fleet(client)
    body = client.get("/fleet/baseline", auth=ROOT).json()

    cohorts = {c["cohort"]: c["size"] for c in body["cohorts"]}
    assert cohorts == {"arista/eos": 4, "cisco/ios": 9, "juniper/junos": 4}


def test_a_deviation_is_reported_as_an_observation_not_a_verdict(
    client: TestClient,
) -> None:
    """D22's separation, restated for drift at the API edge."""
    _upload_fleet(client)
    body = client.get("/fleet/baseline", auth=ROOT).json()

    assert body["is_verdict"] is False
    assert "not a compliance verdict" in body["note"]


# ---------------------------------------------------------------------------
# DEF-15 — identity reaches the canonical model
# ---------------------------------------------------------------------------


def test_devices_are_named_by_hostname_not_by_a_file_hash(client: TestClient) -> None:
    """DEF-15, fixed at P12.

    `build_csm` accepted a `detected_identity` from P5 onward and no production
    caller passed one, so every audited device carried hostname, model and
    os_version as None while ingestion had already read them. Peer grouping needs
    to know which device it is looking at.
    """
    _upload_fleet(client)
    body = client.get("/fleet/baseline", auth=ROOT).json()

    names = {name for cohort in body["cohorts"] for name in cohort["devices"]}
    assert "rtr-core-01" in names
    assert "sw-leaf-01" in names
    assert "srx-edge-01" in names

    # A hostname, not a truncated identifier.
    assert all(not name.startswith("0000") for name in names)


# ---------------------------------------------------------------------------
# Prioritisation on the real corpus
# ---------------------------------------------------------------------------


def test_an_audit_reports_that_it_could_not_rank(client: TestClient) -> None:
    """The Prioritise stage runs and refuses, naming the missing input."""
    file_ids = _upload_fleet(client)
    cisco = file_ids[0]

    for file_id in file_ids:
        response = client.post(f"/compliance/audits?file_id={file_id}", auth=ROOT)
        assert response.status_code == 201, response.text
        body = response.json()

        assert body["prioritisation"]["ranked"] is False
        assert body["prioritisation"]["determined"] == 0
        assert "severity alone must not determine remediation order" in (
            body["prioritisation"]["reason"].lower()
        )

    audited = client.post(f"/compliance/audits?file_id={cisco}", auth=ROOT).json()
    blockers = audited["prioritisation"]["blockers"]
    assert "no_interface_data" in blockers, blockers


def test_no_finding_carries_a_priority_or_exposure_value(client: TestClient) -> None:
    """`priority_rank` and `exposure_score` have been None since P6 and stay None.

    P12 is the phase that was supposed to fill them. It found the inputs still
    absent and left them alone rather than manufacturing a number.
    """
    file_ids = _upload_fleet(client)
    audit = client.post(f"/compliance/audits?file_id={file_ids[0]}", auth=ROOT).json()

    findings = client.get(f"/compliance/audits/{audit['audit_id']}/findings", auth=ROOT).json()[
        "findings"
    ]

    assert findings
    for finding in findings:
        assert finding.get("priority_rank") is None
        assert finding.get("exposure_score") is None


# ---------------------------------------------------------------------------
# DEF-14 — the chain records that an audit ran
# ---------------------------------------------------------------------------


def test_the_chain_records_the_audit_run(client: TestClient) -> None:
    """DEF-14, found at P11 and fixed here.

    DEVELOPER_GUIDE.md §9 requires a hash-chained trail of "AI suggestions, administrator
    corrections, vendor pack changes and audit results". Audit results were the
    one category the chain never held: `comply.service.run_audit` appended the
    record and the HTTP route never called it.
    """
    file_ids = _upload_fleet(client)
    audit = client.post(f"/compliance/audits?file_id={file_ids[0]}", auth=ROOT).json()

    records = client.get("/audit/records?limit=100", auth=ROOT).json()["records"]
    runs = [r for r in records if r["action"] == "audit_run"]

    assert len(runs) == 1
    assert runs[0]["subject"]["id"] == audit["audit_id"]
    assert runs[0]["subject"]["kind"] == "audit"
    assert client.get("/audit/verify", auth=ROOT).json()["ok"] is True


def test_the_audit_record_carries_no_configuration_content(client: TestClient) -> None:
    """Decision D4 — the audit database holds attestations, never content.

    The payload is counts, identifiers and versions. Adding the record must not
    have smuggled a value or a raw line into the chain.
    """
    file_ids = _upload_fleet(client)
    client.post(f"/compliance/audits?file_id={file_ids[0]}", auth=ROOT)

    records = client.get("/audit/records?limit=100", auth=ROOT).json()["records"]
    # The chain stores the canonical JSON string that was hashed, byte-exact.
    raw = next(r for r in records if r["action"] == "audit_run")["payload"]
    payload = json.loads(raw)

    assert set(payload) == {
        "device_id",
        "engine_version",
        "rulepack_id",
        "rulepack_version",
        "pack_versions",
        "rules_evaluated",
        "verdicts",
    }
    text = str(payload)
    assert "192.0.2" not in text
    assert "transport input" not in text
