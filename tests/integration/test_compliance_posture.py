"""Per-framework posture over HTTP, gated on a fully reviewed file (ADR 0068).

Driven through the real pipeline on a development corpus file: upload, audit,
decide every queue entry, re-audit. The gate moves through its states on stored
state alone, and a number appears only at the end.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import settings
from api.db import training as training_store
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.ingest import packs as pack_loader
from api.main import app
from api.models.auth import Role
from api.models.enums import TrainingOutcome
from api.models.training import TrainingExample
from api.train import activation as activation_module
from api.train import bootstrap
from api.train import service as train_service

EDGE = Path("corpus/cisco/dev/edge-rtr-01.cfg")
EVAL = Path("corpus/cisco/eval/edge-rtr-11.cfg")
"""An evaluation-split file — the one DEF-16's contaminated patterns came from."""
GENERIC_LINE = b"203.0.113.9 203.0.113.10\n"
"""No command vocabulary at all: its shape is `<IP> <IP>`, which the queue calls generic."""
ALICE = ("alice", "correct-horse-battery")
BOB = ("bob", "correct-horse-battery")
ROOT = ("root", "correct-horse-battery")

SCORE_KEYS = re.compile(
    r'"(headline_percent|counts|satisfied|no_violation_found|violated|undetermined|coverage)"'
)


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # Trained packs are isolated: a pack a browser demo left in packs/trained/
    # must not decide what this suite sees.
    root = tmp_path / "trained"
    monkeypatch.setattr(pack_loader, "TRAINED_ROOT", root)
    monkeypatch.setattr(activation_module, "TRAINED_ROOT", root)
    monkeypatch.setattr(train_service, "TRAINED_ROOT", root)
    monkeypatch.setattr(bootstrap, "TRAINED_ROOT", root)
    monkeypatch.setattr(pack_loader, "PACK_ROOTS", (pack_loader.PACKS_ROOT, root))
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "nirikshak-audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")

    conn = connect(tmp_path / "nirikshak.db")
    migrate(conn, OPERATIONAL_MIGRATIONS)
    user_store.create_user(conn, ALICE[0], ALICE[1])
    user_store.create_user(conn, BOB[0], BOB[1])
    user_store.create_user(conn, ROOT[0], ROOT[1], role=Role.ADMIN)
    conn.close()

    pack_loader.clear_pack_cache()
    with TestClient(app) as test_client:
        yield test_client
    pack_loader.clear_pack_cache()


def upload(api: TestClient, name: str, data: bytes) -> str:
    response = api.post("/ingest/upload", files={"files": (name, data, "text/plain")}, auth=ALICE)
    assert response.status_code == 200, response.text
    return response.json()["accepted"][0]["file_id"]


def audit(api: TestClient, file_id: str) -> str:
    response = api.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)
    assert response.status_code == 201, response.text
    return response.json()["audit_id"]


def posture(api: TestClient, file_id: str, auth=ALICE) -> dict:
    response = api.get(f"/compliance/devices/{file_id}/posture", auth=auth)
    assert response.status_code == 200, response.text
    return response.json()


def decide_everything(file_id: str, *, at: datetime, leave: int = 0) -> int:
    """Record a "not security relevant" decision for every queue entry but `leave`."""
    conn = connect(settings.db_path)
    rows = conn.execute(
        "SELECT cluster_id, MIN(text_scrubbed) AS line, vendor, os_family FROM unknown_line "
        "WHERE file_id = ? AND signature <> '' GROUP BY cluster_id ORDER BY cluster_id",
        (file_id,),
    ).fetchall()
    for n, row in enumerate(rows[leave:]):
        training_store.save_example(
            conn,
            TrainingExample(
                example_id=f"trn-test-{n}",
                vendor=row["vendor"],
                os_family=row["os_family"],
                raw_line_scrubbed=row["line"],
                cluster_id=row["cluster_id"],
                outcome=TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT,
                confirmed_by="root",
                confirmed_at=at,
            ),
        )
    conn.commit()
    conn.close()
    return len(rows)


def reviewed_and_ready(api: TestClient) -> tuple[str, dict]:
    file_id = upload(api, EDGE.name, EDGE.read_bytes())
    audit(api, file_id)
    decide_everything(file_id, at=datetime.now(UTC) - timedelta(hours=1))
    audit(api, file_id)
    body = posture(api, file_id)
    assert body["gate"]["state"] == "ready", body["gate"]
    return file_id, body


# ---------------------------------------------------------------------------
# The gate, state by state
# ---------------------------------------------------------------------------


def test_an_unaudited_device_is_not_audited(client: TestClient) -> None:
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    body = posture(client, file_id)
    assert body["gate"]["state"] == "not_audited"
    assert body["posture"] is None


def test_an_unidentified_platform_is_not_audited_and_points_at_bootstrap(
    client: TestClient,
) -> None:
    file_id = upload(client, "mystery.txt", b"frobnicate on\nwidget level 7\nwidget mode fast\n")
    assert posture(client, file_id, auth=ROOT)["gate"]["next_step"].endswith("bootstrap page.")
    body = posture(client, file_id)
    assert body["platform"]["vendor"] is None
    assert body["gate"]["state"] == "not_audited"
    assert "administrator" in body["gate"]["next_step"]


def test_an_undecided_queue_is_review_pending_with_counts_and_no_score(
    client: TestClient,
) -> None:
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    audit(client, file_id)
    total = decide_everything(file_id, at=datetime.now(UTC), leave=3)

    response = client.get(f"/compliance/devices/{file_id}/posture", auth=ALICE)
    body = response.json()
    assert body["gate"]["state"] == "review_pending"
    assert body["gate"]["message"] == (
        "Review all unrecognised lines before a compliance score is shown."
    )
    assert body["gate"]["review"] == {"reviewed": total - 3, "total": total}
    assert body["gate"]["next_step"] == "An administrator must complete the review."
    assert body["posture"] is None
    assert not SCORE_KEYS.search(response.text), "a gated response carries a score field"


def test_decisions_newer_than_the_run_require_a_rerun(client: TestClient) -> None:
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    audit(client, file_id)
    decide_everything(file_id, at=datetime.now(UTC) + timedelta(minutes=5))

    response = client.get(f"/compliance/devices/{file_id}/posture", auth=ALICE)
    body = response.json()
    assert body["gate"]["state"] == "rerun_required"
    assert body["gate"]["message"] == "Re-run the audit to include your review decisions."
    assert body["posture"] is None
    assert not SCORE_KEYS.search(response.text)


def test_a_rerun_after_the_review_is_ready(client: TestClient) -> None:
    _, body = reviewed_and_ready(client)
    assert body["posture"]["mappings_attached"] is True


def test_a_decision_on_another_platform_does_not_count(client: TestClient) -> None:
    """A decision extends one platform's pack; a same-shaped line elsewhere is not reviewed."""
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    audit(client, file_id)
    decide_everything(file_id, at=datetime.now(UTC) - timedelta(hours=1))
    conn = connect(settings.db_path)
    conn.execute("UPDATE training_example SET vendor = 'juniper', os_family = 'junos'")
    conn.commit()
    conn.close()
    assert posture(client, file_id)["gate"]["state"] == "review_pending"


def test_another_users_device_is_not_found(client: TestClient) -> None:
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    assert client.get(f"/compliance/devices/{file_id}/posture", auth=BOB).status_code == 404


# ---------------------------------------------------------------------------
# The measure, on a device that reached it
# ---------------------------------------------------------------------------


def test_a_ready_device_is_scored_per_framework(client: TestClient) -> None:
    _, body = reviewed_and_ready(client)
    frameworks = {f["framework"]: f for f in body["posture"]["frameworks"]}
    assert set(frameworks) == {"cis", "nist", "stig"}

    nist = frameworks["nist"]
    assert nist["status"] == "assessed"
    counts = nist["counts"]
    parts = ("satisfied", "no_violation_found", "violated", "undetermined")
    assert counts["assessed"] == sum(counts[k] for k in parts)
    assert "headline_percent" not in nist, "the headline is a fraction, never a percentage"
    # Every NIST mapping is partial, so nothing NIST is fully satisfied; the
    # controls whose checks all passed are "no violation found".
    assert counts["satisfied"] == 0
    assert counts["no_violation_found"] >= 1
    for control in nist["no_violation_found"]:
        assert all(r["coverage"] == "partial" and r["coverage_reason"] for r in control["rules"])
    assert nist["coverage"]["assessed"] == counts["assessed"]
    assert nist["coverage"]["catalog_total"] == 1014
    # edge-rtr-01 is IOS 15.2: the IOS XE 17 benchmarks do not describe it.
    for name in ("cis", "stig"):
        assert frameworks[name]["status"] == "not_applicable"
        assert "does not describe" in frameworks[name]["reason"]
        assert "counts" not in frameworks[name]
    assert "iso" in body["posture"]["unsourced"]


def test_the_undetermined_share_survives_the_review(client: TestClient) -> None:
    """Clearing the queue does not clear UNKNOWN: an absent directive has nothing to review."""
    _, body = reviewed_and_ready(client)
    nist = next(f for f in body["posture"]["frameworks"] if f["framework"] == "nist")
    assert nist["counts"]["undetermined"] >= 1
    reasons = {r["unknown_reason"] for c in nist["undetermined"] for r in c["rules"]}
    assert reasons and None not in reasons


def test_a_violated_control_carries_control_rule_line_and_fix_or_none(client: TestClient) -> None:
    _, body = reviewed_and_ready(client)
    nist = next(f for f in body["posture"]["frameworks"] if f["framework"] == "nist")
    assert nist["violated"], "edge-rtr-01 enables telnet and the HTTP server"

    outcomes = set()
    for control in nist["violated"]:
        assert control["control_id"] and control["edition"] == "5.2.0"
        for rule in control["rules"]:
            assert rule["verdict"] == "fail"
            assert rule["finding_id"]
            for evidence in rule["evidence"]:
                assert evidence["line_start"] >= 1 and evidence["raw_line"]
            remediation = rule["remediation"]
            outcomes.add(remediation["outcome"])
            if remediation["outcome"] == "resolved":
                assert remediation["commands"] and remediation["rollback"]
            else:
                assert remediation["commands"] == []
                assert remediation["statement"]
    # Both cases occur on this device: telnet has a vetted snippet, the cipher
    # rules do not.
    assert outcomes == {"resolved", "no_snippet"}
    http = next(r for c in nist["violated"] for r in c["rules"] if r["rule_id"] == "NRK-HTTP-001")
    assert http["evidence"][0]["raw_line"] == "ip http server"


def test_a_rulepack_mismatch_withholds_mappings_with_the_reason(client: TestClient) -> None:
    file_id, _ = reviewed_and_ready(client)
    conn = connect(settings.db_path)
    conn.execute("UPDATE audit_run SET rulepack_checksum = 'sha256:not-the-active-rules'")
    conn.commit()
    conn.close()

    body = posture(client, file_id)
    assert body["gate"]["state"] == "ready"
    assert body["posture"]["mappings_attached"] is False
    assert "re-run the audit" in body["posture"]["withheld_reason"]
    assert body["posture"]["frameworks"] == []


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


def _posture_section(html: str) -> str:
    start = html.index('<div class="sec" id="posture">')
    return html[start : html.index("<!-- SUBJECT -->", start)]


def test_a_gated_report_states_the_reason_in_place_of_a_score(client: TestClient) -> None:
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    audit_id = audit(client, file_id)
    section = _posture_section(
        client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text
    )
    assert "No compliance score" in section
    assert "Review all unrecognised lines before a compliance score is shown." in section
    assert "%" not in section
    assert 'class="pbar"' not in section


def test_a_ready_report_carries_the_posture_and_what_did_not_comply(client: TestClient) -> None:
    file_id, body = reviewed_and_ready(client)
    audit_id = body["gate"]["audit_id"]
    nist = next(f for f in body["posture"]["frameworks"] if f["framework"] == "nist")
    section = _posture_section(
        client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text
    )
    counts = nist["counts"]
    satisfied, assessed = counts["satisfied"], counts["assessed"]
    assert re.search(
        rf'{satisfied}</span> of <span class="num">{assessed}</span>\s+assessed controls fully '
        "satisfied",
        section,
    )
    assert "%" not in section
    assert "no violation found (partial check)" in section
    assert "partial check:\n        NIRIKSHAK tests only part of this control." in section
    assert "undetermined" in section
    assert "1014</span> catalog controls assessed by NIRIKSHAK" in section
    assert "Did not comply" in section
    for control in nist["violated"]:
        assert control["control_id"] in section


def test_a_report_on_an_older_run_is_not_scored(client: TestClient) -> None:
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    first = audit(client, file_id)
    decide_everything(file_id, at=datetime.now(UTC) - timedelta(hours=1))
    audit(client, file_id)
    section = _posture_section(
        client.get(f"/compliance/audits/{first}/report.html", auth=ALICE).text
    )
    assert "A newer audit of this configuration exists" in section
    assert "%" not in section


# ---------------------------------------------------------------------------
# One review count, and a generic shape that can still be reviewed
# ---------------------------------------------------------------------------


def _queue(api: TestClient, file_id: str) -> dict:
    response = api.get(f"/training/queue?file_id={file_id}", auth=ROOT)
    assert response.status_code == 200, response.text
    return response.json()


def test_the_review_tab_and_the_gate_give_one_count(client: TestClient) -> None:
    file_id = upload(client, EDGE.name, EDGE.read_bytes())
    audit(client, file_id)
    decide_everything(file_id, at=datetime.now(UTC), leave=4)

    queue = _queue(client, file_id)
    gate = posture(client, file_id)["gate"]["review"]
    assert (queue["reviewed"], queue["size"]) == (gate["reviewed"], gate["total"])
    assert sum(1 for e in queue["entries"] if e["decided"]) == gate["reviewed"]
    assert gate["total"] - gate["reviewed"] == 4


def test_a_generic_entry_can_be_dismissed_and_never_mapped(client: TestClient) -> None:
    """A device with a generic-shape line must not be stuck in review_pending."""
    file_id = upload(client, "edge-generic.cfg", EDGE.read_bytes() + GENERIC_LINE)
    audit(client, file_id)
    generic = [e for e in _queue(client, file_id)["entries"] if not e["confirmable"]]
    assert len(generic) == 1
    entry = generic[0]

    body = {
        "cluster_id": entry["cluster_id"],
        "line": entry["line"],
        "vendor": "cisco",
        "os_family": "ios",
        "file_id": file_id,
    }
    mapped = client.post(
        "/training/confirm",
        json={**body, "outcome": "corrected", "field": "ntp_servers"},
        auth=ROOT,
    )
    assert mapped.status_code == 422
    assert "too generic" in mapped.json()["detail"]

    dismissed = client.post(
        "/training/confirm",
        json={**body, "outcome": "rejected_not_security_relevant"},
        auth=ROOT,
    )
    assert dismissed.status_code == 201, dismissed.text

    # Every other entry decided earlier; the gate now reaches rerun, then ready.
    decide_everything(file_id, at=datetime.now(UTC) - timedelta(hours=1))
    assert posture(client, file_id)["gate"]["state"] == "rerun_required"
    audit(client, file_id)
    assert posture(client, file_id)["gate"]["state"] == "ready"


# ---------------------------------------------------------------------------
# DEF-16 — the measured data is never reviewed
# ---------------------------------------------------------------------------


def test_an_evaluation_file_is_reserved_not_scored(client: TestClient) -> None:
    file_id = upload(client, EVAL.name, EVAL.read_bytes())
    audit(client, file_id)
    decide_everything(file_id, at=datetime.now(UTC) - timedelta(hours=1))
    audit(client, file_id)

    response = client.get(f"/compliance/devices/{file_id}/posture", auth=ALICE)
    body = response.json()
    assert body["gate"]["state"] == "evaluation_file"
    assert body["gate"]["message"] == (
        "Reserved for measurement — scored by the evaluation harness, not reviewed."
    )
    assert body["posture"] is None
    assert not SCORE_KEYS.search(response.text)
    assert "evaluation file" in _queue(client, file_id)["reserved"]


def test_a_line_from_an_evaluation_file_cannot_be_confirmed_or_compiled(
    client: TestClient,
) -> None:
    file_id = upload(client, EVAL.name, EVAL.read_bytes())
    audit(client, file_id)
    entry = next(e for e in _queue(client, file_id)["entries"] if e["confirmable"])
    body = {
        "cluster_id": entry["cluster_id"],
        "line": entry["line"],
        "vendor": "cisco",
        "os_family": "ios",
        "outcome": "rejected_not_security_relevant",
    }
    # Named as the file under review, or known only from it: refused either way.
    for extra in ({"file_id": file_id}, {}):
        refused = client.post("/training/confirm", json={**body, **extra}, auth=ROOT)
        assert refused.status_code == 409, refused.text
        assert "DEF-16" in refused.json()["detail"]

    # A decision already on record for that line cannot be compiled either.
    conn = connect(settings.db_path)
    training_store.save_example(
        conn,
        TrainingExample(
            example_id="trn-eval-1",
            vendor="cisco",
            os_family="ios",
            raw_line_scrubbed=entry["line"],
            cluster_id=entry["cluster_id"],
            field="ntp_servers",
            outcome=TrainingOutcome.CORRECTED,
            confirmed_by="root",
            confirmed_at=datetime.now(UTC),
        ),
    )
    conn.commit()
    conn.close()
    compiled = client.post(
        "/training/compile", json={"example_id": "trn-eval-1", "value_token": 0}, auth=ROOT
    )
    assert compiled.status_code == 409
    assert "DEF-16" in compiled.json()["detail"]


def test_a_line_also_in_a_development_file_is_not_refused(client: TestClient) -> None:
    """The corpus policy's own condition: an example exclusive to measured data."""
    dev_id = upload(client, EDGE.name, EDGE.read_bytes())
    eval_id = upload(client, EVAL.name, EVAL.read_bytes())
    audit(client, dev_id)
    audit(client, eval_id)
    dev = {(e["cluster_id"], e["line"]) for e in _queue(client, dev_id)["entries"]}
    shared = next(
        e for e in _queue(client, eval_id)["entries"] if (e["cluster_id"], e["line"]) in dev
    )
    accepted = client.post(
        "/training/confirm",
        json={
            "cluster_id": shared["cluster_id"],
            "line": shared["line"],
            "vendor": "cisco",
            "os_family": "ios",
            "outcome": "rejected_not_security_relevant",
            "file_id": dev_id,
        },
        auth=ROOT,
    )
    assert accepted.status_code == 201, accepted.text
