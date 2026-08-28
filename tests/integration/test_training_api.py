"""The confirmation loop over HTTP (P11).

Two things are being tested, and the second matters more.

The first is that the loop works through the API: upload, audit, read the queue,
confirm, compile, review the regex, activate, re-audit, watch the residue fall.

The second is that **every mutation requires an administrator**. A confirmation
changes how every future device of that platform is parsed, permanently, for
everyone — it is the highest privilege in NIRIKSHAK, higher than reading any
finding. The negative assertions below are the ones that would matter on the day
somebody tried.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import settings
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.ingest import packs as pack_loader
from api.main import app
from api.models.enums import Role
from api.train import activation as activation_module
from api.train import service as train_service

ARISTA = Path("corpus/arista/dev/sw-leaf-01.cfg")

ALICE = ("alice", "correct-horse-battery")
ROOT = ("root", "admin-long-password-1")

CONFIRMED_LINE = "logging host 192.0.2.10"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "nirikshak-audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")

    # Trained packs are written to a temporary root so a test never activates a
    # pack into the working tree.
    trained = tmp_path / "trained"
    monkeypatch.setattr(pack_loader, "TRAINED_ROOT", trained)
    monkeypatch.setattr(activation_module, "TRAINED_ROOT", trained)
    monkeypatch.setattr(train_service, "TRAINED_ROOT", trained)
    monkeypatch.setattr(pack_loader, "PACK_ROOTS", (pack_loader.PACKS_ROOT, trained))

    conn = connect(tmp_path / "nirikshak.db")
    migrate(conn, OPERATIONAL_MIGRATIONS)
    user_store.create_user(conn, ALICE[0], ALICE[1])
    user_store.create_user(conn, ROOT[0], ROOT[1], role=Role.ADMIN)
    conn.close()

    pack_loader.clear_pack_cache()
    with TestClient(app) as test_client:
        yield test_client
    pack_loader.clear_pack_cache()


def _upload_and_audit(client: TestClient) -> tuple[str, int]:
    response = client.post(
        "/ingest/upload",
        files={"files": (ARISTA.name, ARISTA.read_bytes(), "text/plain")},
        auth=ALICE,
    )
    assert response.status_code == 200, response.text
    file_id = response.json()["accepted"][0]["file_id"]

    audited = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)
    assert audited.status_code == 201, audited.text
    return file_id, audited.json()["residue_lines"]


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("get", "/training/queue", None),
        ("get", "/training/examples", None),
        ("post", "/training/confirm", {}),
        ("post", "/training/compile", {}),
        ("post", "/training/activate", {}),
        ("post", "/training/rollback", {}),
    ],
)
def test_every_training_endpoint_refuses_an_anonymous_caller(
    client: TestClient, method: str, path: str, body: dict | None
) -> None:
    response = getattr(client, method)(path, json=body) if body is not None else client.get(path)
    assert response.status_code == 401


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("get", "/training/queue", None),
        ("get", "/training/examples", None),
        ("post", "/training/confirm", {}),
        ("post", "/training/compile", {}),
        ("post", "/training/activate", {}),
        ("post", "/training/rollback", {}),
    ],
)
def test_every_training_endpoint_refuses_a_non_admin(
    client: TestClient, method: str, path: str, body: dict | None
) -> None:
    """Including the read.

    The queue is fleet-wide by construction, so reading it means reading
    configuration lines from files the caller may not own.
    """
    if body is not None:
        response = getattr(client, method)(path, json=body, auth=ALICE)
    else:
        response = client.get(path, auth=ALICE)
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# The queue
# ---------------------------------------------------------------------------


def test_the_queue_reports_the_model_state_and_the_index_it_searched(
    client: TestClient,
) -> None:
    """D50 and ADR 0017 — the two sentences a person needs before deciding."""
    _upload_and_audit(client)

    body = client.get("/training/queue", auth=ROOT).json()

    assert body["size"] > 0
    assert body["index"]
    assert "available" in body["model"]
    assert body["model"]["summary"]

    entry = body["entries"][0]
    assert entry["state"] in {"ranked", "model_unavailable", "index_empty", "not_confirmable"}
    assert entry["reason"] or entry["state"] == "ranked"

    # R7 — a client must not be able to render a score as a percentage without
    # having been told, in the same payload, that it is not one.
    assert entry["is_probability"] is False
    assert "not probabilities" in entry["confidence_note"]


def test_an_unavailable_model_is_never_an_empty_suggestion_list(client: TestClient) -> None:
    """The distinction the whole of D50 rests on."""
    _upload_and_audit(client)
    body = client.get("/training/queue", auth=ROOT).json()

    for entry in body["entries"]:
        if entry["state"] == "model_unavailable":
            assert entry["suggestions"] == []
            assert entry["reason"], "an absent model must explain itself"
            break
    else:  # pragma: no cover - only on a machine with the [ai] extra installed
        pytest.skip("the embedding model is available in this environment")


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


def test_the_loop_runs_over_http_and_the_residue_falls(client: TestClient) -> None:
    """Upload, audit, confirm, compile, activate, re-audit — as P13 will drive it."""
    file_id, residue_before = _upload_and_audit(client)
    assert residue_before > 0

    queue = client.get(f"/training/queue?file_id={file_id}", auth=ROOT).json()
    entry = next(e for e in queue["entries"] if e["line"] == CONFIRMED_LINE)

    confirmed = client.post(
        "/training/confirm",
        json={
            "cluster_id": entry["cluster_id"],
            "line": CONFIRMED_LINE,
            "vendor": "arista",
            "os_family": "eos",
            "outcome": "corrected",
            "field": "logging_hosts",
        },
        auth=ROOT,
    )
    assert confirmed.status_code == 201, confirmed.text
    assert confirmed.json()["confirmed_by"] == "root"
    assert confirmed.json()["audit_seq"] is not None

    compiled = client.post(
        "/training/compile",
        json={
            "example_id": confirmed.json()["example_id"],
            "value_token": 2,
            "cast": "list",
        },
        auth=ROOT,
    )
    assert compiled.status_code == 201, compiled.text
    draft = compiled.json()

    # The DRAFT step exists so a person can read this before anything happens.
    assert draft["status"] == "draft"
    assert draft["pattern"] == r"^logging\s+host\s+(\S+)$"
    assert draft["edited"] is False

    activated = client.post(
        "/training/activate",
        json={"pack_id": draft["pack_id"], "pack_version": draft["pack_version"]},
        auth=ROOT,
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["previous_version"] == "1.0.1"
    assert activated.json()["checksum"].startswith("sha256:")

    # No restart: the next audit in this same process uses the new pack.
    reaudited = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)
    assert reaudited.status_code == 201, reaudited.text
    assert reaudited.json()["residue_lines"] < residue_before


def test_an_edited_pattern_is_revalidated_and_recorded_as_edited(client: TestClient) -> None:
    """DEVELOPER_GUIDE.md §4 — editing is required, and re-validation is not optional."""
    file_id, _ = _upload_and_audit(client)
    queue = client.get(f"/training/queue?file_id={file_id}", auth=ROOT).json()
    entry = next(e for e in queue["entries"] if e["line"] == CONFIRMED_LINE)

    example_id = client.post(
        "/training/confirm",
        json={
            "cluster_id": entry["cluster_id"],
            "line": CONFIRMED_LINE,
            "vendor": "arista",
            "os_family": "eos",
            "outcome": "corrected",
            "field": "logging_hosts",
        },
        auth=ROOT,
    ).json()["example_id"]

    # An edit that no longer matches the confirmed line is refused.
    rejected = client.post(
        "/training/compile",
        json={
            "example_id": example_id,
            "value_token": 2,
            "cast": "list",
            "pattern_override": r"^ntp\s+server\s+(\S+)$",
        },
        auth=ROOT,
    )
    assert rejected.status_code == 422
    assert "does not match the line" in rejected.json()["detail"]

    # An unanchored edit is refused.
    unanchored = client.post(
        "/training/compile",
        json={
            "example_id": example_id,
            "value_token": 2,
            "cast": "list",
            "pattern_override": r"logging\s+host\s+(\S+)$",
        },
        auth=ROOT,
    )
    assert unanchored.status_code == 422
    assert "anchored" in unanchored.json()["detail"]

    # A valid edit is accepted and marked as edited.
    accepted = client.post(
        "/training/compile",
        json={
            "example_id": example_id,
            "value_token": 2,
            "cast": "list",
            "pattern_override": r"^logging\s+host\s+(\S+)\s*$",
        },
        auth=ROOT,
    )
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["edited"] is True


def test_rollback_returns_the_platform_to_the_previous_pack(client: TestClient) -> None:
    file_id, residue_before = _upload_and_audit(client)
    queue = client.get(f"/training/queue?file_id={file_id}", auth=ROOT).json()
    entry = next(e for e in queue["entries"] if e["line"] == CONFIRMED_LINE)

    example_id = client.post(
        "/training/confirm",
        json={
            "cluster_id": entry["cluster_id"],
            "line": CONFIRMED_LINE,
            "vendor": "arista",
            "os_family": "eos",
            "outcome": "corrected",
            "field": "logging_hosts",
        },
        auth=ROOT,
    ).json()["example_id"]

    draft = client.post(
        "/training/compile",
        json={"example_id": example_id, "value_token": 2, "cast": "list"},
        auth=ROOT,
    ).json()
    client.post(
        "/training/activate",
        json={"pack_id": draft["pack_id"], "pack_version": draft["pack_version"]},
        auth=ROOT,
    )

    rolled = client.post(
        "/training/rollback",
        json={"pack_id": "arista/eos", "to_version": "1.0.1"},
        auth=ROOT,
    )
    assert rolled.status_code == 200, rolled.text
    assert rolled.json()["rolled_back_from"] == "1.0.2"

    # The previous behaviour returns exactly, because nothing was modified.
    reaudited = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)
    assert reaudited.json()["residue_lines"] == residue_before


def test_a_confirmation_is_attributed_to_the_authenticated_admin(client: TestClient) -> None:
    """Never to a name supplied in the body.

    `confirmed_by` is the field that says who is accountable for a mapping. A
    caller able to set it could attribute their confirmation to a colleague.
    """
    file_id, _ = _upload_and_audit(client)
    queue = client.get(f"/training/queue?file_id={file_id}", auth=ROOT).json()
    entry = queue["entries"][0]

    spoofed = client.post(
        "/training/confirm",
        json={
            "cluster_id": entry["cluster_id"],
            "line": entry["line"],
            "vendor": "arista",
            "os_family": "eos",
            "outcome": "rejected_not_security_relevant",
            "confirmed_by": "somebody-else",
        },
        auth=ROOT,
    )
    assert spoofed.status_code == 422  # extra="forbid" — the field is not accepted


def test_recorded_decisions_are_listed_without_an_accuracy_claim(client: TestClient) -> None:
    """Gap 7 closes through use, and P11 does not decide it has closed.

    The endpoint reports the population. It does not compute top-3 accuracy from
    it, because that metric stays NOT MEASURED until somebody decides there is a
    population worth measuring — and that is not this router's call.
    """
    file_id, _ = _upload_and_audit(client)
    queue = client.get(f"/training/queue?file_id={file_id}", auth=ROOT).json()
    entry = next(e for e in queue["entries"] if e["line"] == CONFIRMED_LINE)

    client.post(
        "/training/confirm",
        json={
            "cluster_id": entry["cluster_id"],
            "line": CONFIRMED_LINE,
            "vendor": "arista",
            "os_family": "eos",
            "outcome": "corrected",
            "field": "logging_hosts",
        },
        auth=ROOT,
    )

    body = client.get("/training/examples", auth=ROOT).json()
    assert body["count"] == 1
    assert body["examples"][0]["field"] == "logging_hosts"
    assert body["examples"][0]["confirmed_by"] == "root"
    assert "top3_accuracy" not in body
    assert "accuracy" not in body
