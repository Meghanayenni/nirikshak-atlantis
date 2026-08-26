"""Smoke test: the application boots and reports its safety-relevant settings."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["phase"] == "P0"

    # Rule 3 — the abstention threshold must be present and be a real
    # probability, not a placeholder.
    assert 0.0 < body["confidence_threshold"] <= 1.0

    # Rule 6 — airgap must be an explicit boolean, never absent or ambiguous.
    assert isinstance(body["airgap"], bool)
