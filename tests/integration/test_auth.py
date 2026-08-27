"""Authentication and authorisation over the API (decision D25).

The Concept Report promises that *"access to raw files is role-separated from
access to findings"*. Before P7 there was no authentication anywhere: every
route, including configuration upload, was open. These tests are what make the
promise true rather than stated.

Two roles, and the difference between them is the whole model:

    user    sees only what they uploaded and audited
    admin   sees the fleet, and manages accounts

The sharpest assertions here are the negative ones. A tool that shows one
operator another operator's network topology is worse than one that shows
nothing, and cross-tenant leakage is the failure that would not be noticed until
it mattered.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import settings
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.main import app
from api.models.enums import Role

CISCO = Path("corpus/cisco/dev/rtr-core-01.cfg")
ARISTA = Path("corpus/arista/dev/sw-leaf-01.cfg")

ALICE = ("alice", "correct-horse-battery")
BOB = ("bob", "another-long-password")
ROOT = ("root", "admin-long-password-1")


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "nirikshak-audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")

    conn = connect(tmp_path / "nirikshak.db")
    migrate(conn, OPERATIONAL_MIGRATIONS)
    user_store.create_user(conn, ALICE[0], ALICE[1])
    user_store.create_user(conn, BOB[0], BOB[1])
    user_store.create_user(conn, ROOT[0], ROOT[1], role=Role.ADMIN)
    conn.close()

    with TestClient(app) as test_client:
        yield test_client


def upload(client: TestClient, who: tuple[str, str], path: Path = CISCO) -> str:
    response = client.post(
        "/ingest/upload",
        files={"files": (path.name, path.read_bytes(), "text/plain")},
        auth=who,
    )
    assert response.status_code == 200, response.text
    return response.json()["accepted"][0]["file_id"]


def audit(client: TestClient, who: tuple[str, str], file_id: str) -> str:
    response = client.post(f"/compliance/audits?file_id={file_id}", auth=who)
    assert response.status_code == 201, response.text
    return response.json()["audit_id"]


# ---------------------------------------------------------------------------
# Nothing is reachable without credentials
# ---------------------------------------------------------------------------

PROTECTED = [
    ("post", "/ingest/upload"),
    ("get", "/ingest/files"),
    ("get", "/ingest/devices"),
    ("get", "/ingest/stats"),
    ("get", "/audit/head"),
    ("get", "/audit/records"),
    ("get", "/audit/verify"),
    ("get", "/compliance/audits"),
    ("get", "/users/me"),
    ("get", "/users"),
]


@pytest.mark.parametrize("method,path", PROTECTED, ids=[f"{m}-{p}" for m, p in PROTECTED])
def test_every_route_requires_authentication(client: TestClient, method: str, path: str) -> None:
    response = getattr(client, method)(path)

    assert response.status_code == 401, f"{path} was reachable anonymously"
    assert "WWW-Authenticate" in response.headers


def test_health_stays_public(client: TestClient) -> None:
    """A liveness probe that needs credentials is not a liveness probe."""
    assert client.get("/health").status_code == 200


def test_health_leaks_no_secret(client: TestClient) -> None:
    body = client.get("/health").json()
    blob = str(body).lower()

    for forbidden in ("password", "hash", "scrypt", "secret", "token"):
        assert forbidden not in blob


# ---------------------------------------------------------------------------
# Bad credentials are indistinguishable from unknown accounts
# ---------------------------------------------------------------------------


def test_a_wrong_password_is_rejected(client: TestClient) -> None:
    assert client.get("/users/me", auth=(ALICE[0], "wrong")).status_code == 401


def test_an_unknown_username_is_rejected(client: TestClient) -> None:
    assert client.get("/users/me", auth=("nobody", "whatever-long-pw")).status_code == 401


def test_the_two_failures_are_indistinguishable(client: TestClient) -> None:
    """Otherwise an unauthenticated caller can enumerate accounts."""
    wrong_password = client.get("/users/me", auth=(ALICE[0], "wrong-but-long"))
    no_such_user = client.get("/users/me", auth=("ghost", "wrong-but-long"))

    assert wrong_password.status_code == no_such_user.status_code
    assert wrong_password.json() == no_such_user.json()


def test_a_disabled_account_cannot_authenticate(client: TestClient) -> None:
    users = client.get("/users", auth=ROOT).json()["users"]
    alice_id = next(u["user_id"] for u in users if u["username"] == ALICE[0])

    assert client.post(f"/users/{alice_id}/disable", auth=ROOT).status_code == 200
    assert client.get("/users/me", auth=ALICE).status_code == 401


# ---------------------------------------------------------------------------
# Cross-user access is rejected
# ---------------------------------------------------------------------------


def test_a_user_cannot_see_another_users_files(client: TestClient) -> None:
    upload(client, ALICE)

    assert client.get("/ingest/files", auth=BOB).json()["count"] == 0
    assert client.get("/ingest/files", auth=ALICE).json()["count"] == 1


def test_a_user_cannot_read_another_users_configuration_lines(client: TestClient) -> None:
    """Raw configuration is the most sensitive thing this API serves."""
    file_id = upload(client, ALICE)

    assert client.get(f"/ingest/files/{file_id}/lines", auth=BOB).status_code == 404
    assert client.get(f"/ingest/files/{file_id}/lines", auth=ALICE).status_code == 200


def test_a_user_cannot_see_another_users_devices(client: TestClient) -> None:
    upload(client, ALICE)

    assert client.get("/ingest/devices", auth=BOB).json()["count"] == 0
    assert client.get("/ingest/devices", auth=ALICE).json()["count"] == 1


def test_a_user_cannot_audit_another_users_file(client: TestClient) -> None:
    file_id = upload(client, ALICE)

    assert client.post(f"/compliance/audits?file_id={file_id}", auth=BOB).status_code == 404


def test_a_user_cannot_read_another_users_audit(client: TestClient) -> None:
    audit_id = audit(client, ALICE, upload(client, ALICE))

    assert client.get(f"/compliance/audits/{audit_id}", auth=BOB).status_code == 404


def test_a_user_cannot_read_another_users_findings(client: TestClient) -> None:
    """The findings are the security verdicts. This is the leak that would matter."""
    audit_id = audit(client, ALICE, upload(client, ALICE))

    assert client.get(f"/compliance/audits/{audit_id}/findings", auth=BOB).status_code == 404
    assert client.get(f"/compliance/audits/{audit_id}/findings", auth=ALICE).status_code == 200


def test_a_user_cannot_list_another_users_audits(client: TestClient) -> None:
    audit(client, ALICE, upload(client, ALICE))

    assert client.get("/compliance/audits", auth=BOB).json()["count"] == 0
    assert client.get("/compliance/audits", auth=ALICE).json()["count"] == 1


def test_a_forbidden_resource_answers_404_not_403(client: TestClient) -> None:
    """403 would confirm the id exists, which lets someone walk the id space."""
    audit_id = audit(client, ALICE, upload(client, ALICE))

    real_but_not_yours = client.get(f"/compliance/audits/{audit_id}", auth=BOB)
    does_not_exist = client.get("/compliance/audits/0" * 8, auth=BOB)

    assert real_but_not_yours.status_code == 404
    assert real_but_not_yours.status_code == does_not_exist.status_code


# ---------------------------------------------------------------------------
# Admin sees the fleet
# ---------------------------------------------------------------------------


def test_an_admin_sees_every_users_files(client: TestClient) -> None:
    upload(client, ALICE, CISCO)
    upload(client, BOB, ARISTA)

    assert client.get("/ingest/files", auth=ROOT).json()["count"] == 2


def test_an_admin_can_read_any_audit(client: TestClient) -> None:
    audit_id = audit(client, ALICE, upload(client, ALICE))

    assert client.get(f"/compliance/audits/{audit_id}", auth=ROOT).status_code == 200
    assert client.get(f"/compliance/audits/{audit_id}/findings", auth=ROOT).status_code == 200


def test_fleet_statistics_are_admin_only(client: TestClient) -> None:
    """The numbers describe the whole estate, so a user must not see them."""
    assert client.get("/ingest/stats", auth=ALICE).status_code == 403
    assert client.get("/ingest/stats", auth=ROOT).status_code == 200


# ---------------------------------------------------------------------------
# Admin-only management
# ---------------------------------------------------------------------------


def test_a_user_cannot_create_accounts(client: TestClient) -> None:
    response = client.post(
        "/users", json={"username": "mallory", "password": "a-long-password-x"}, auth=ALICE
    )

    assert response.status_code == 403


def test_a_user_cannot_list_accounts(client: TestClient) -> None:
    assert client.get("/users", auth=ALICE).status_code == 403


def test_a_user_cannot_disable_an_account(client: TestClient) -> None:
    users = client.get("/users", auth=ROOT).json()["users"]
    bob_id = next(u["user_id"] for u in users if u["username"] == BOB[0])

    assert client.post(f"/users/{bob_id}/disable", auth=ALICE).status_code == 403


def test_an_admin_can_create_an_account(client: TestClient) -> None:
    response = client.post(
        "/users", json={"username": "carol", "password": "carol-long-password"}, auth=ROOT
    )

    assert response.status_code == 201
    assert response.json()["username"] == "carol"
    assert response.json()["role"] == "user"


def test_an_admin_cannot_disable_themselves(client: TestClient) -> None:
    """Locking out the last admin has no recovery short of the database."""
    me = client.get("/users/me", auth=ROOT).json()

    assert client.post(f"/users/{me['user_id']}/disable", auth=ROOT).status_code == 409


def test_a_duplicate_username_is_refused(client: TestClient) -> None:
    response = client.post(
        "/users", json={"username": ALICE[0], "password": "yet-another-password"}, auth=ROOT
    )

    assert response.status_code == 409


def test_a_short_password_is_refused(client: TestClient) -> None:
    response = client.post("/users", json={"username": "dave", "password": "short"}, auth=ROOT)

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# No credential material escapes
# ---------------------------------------------------------------------------


def test_no_response_ever_contains_a_password_hash(client: TestClient) -> None:
    responses = [
        client.get("/users/me", auth=ALICE),
        client.get("/users", auth=ROOT),
        client.post(
            "/users", json={"username": "erin", "password": "erin-long-password"}, auth=ROOT
        ),
    ]

    for response in responses:
        blob = response.text.lower()
        assert "scrypt" not in blob
        assert "password_hash" not in blob
        assert "password" not in blob


def test_the_user_contract_has_no_credential_field() -> None:
    """Structural, not incidental: there is nowhere for a hash to be attached."""
    from api.models.auth import User

    forbidden = {"password", "password_hash", "hash", "secret", "salt", "token"}
    assert not (forbidden & set(User.model_fields))
