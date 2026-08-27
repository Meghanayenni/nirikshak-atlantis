"""Smoke test: the application boots, migrates, and reports its settings."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import settings
from api.main import app


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A client whose database lives in a temp directory.

    `TestClient` only runs the lifespan handler when used as a context manager,
    which is what applies the migrations — and pointing the settings at tmp_path
    keeps the suite from creating a database in the repository root.
    """
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "nirikshak-audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")
    with TestClient(app) as test_client:
        yield test_client


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["phase"] == "P4"

    # Rule 3 — the abstention threshold must be present and be a real
    # probability, not a placeholder.
    assert 0.0 < body["confidence_threshold"] <= 1.0

    # D6 — both Rule 3 floors are reported. Naming only one would imply a single
    # threshold governs every confidence population, which it does not.
    assert 0.0 < body["platform_default_min_confidence"] <= 1.0

    # Rule 6 — airgap must be an explicit boolean, never absent or ambiguous.
    assert isinstance(body["airgap"], bool)


def test_startup_applies_migrations(client: TestClient) -> None:
    """The lifespan handler brings the schema up before anything is served."""
    assert client.get("/health").json()["schema_version"] >= 1


def test_audit_endpoints_are_mounted(client: TestClient) -> None:
    assert client.get("/audit/head").json()["empty"] is True
    assert client.get("/audit/verify").json()["ok"] is True
