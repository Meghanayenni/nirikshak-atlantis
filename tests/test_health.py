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
    assert body["phase"] == "P12"

    # Rule 3 — the abstention threshold must be present and be a real
    # probability, not a placeholder.
    assert 0.0 < body["confidence_threshold"] <= 1.0

    # D6 — both Rule 3 floors are reported. Naming only one would imply a single
    # threshold governs every confidence population, which it does not.
    assert 0.0 < body["platform_default_min_confidence"] <= 1.0

    # D13 — the assigned platform-default confidence and the admissibility floor
    # are different numbers, and the readout must not conflate them.
    assert 0.0 < body["platform_default_confidence"] <= 1.0
    assert body["platform_default_confidence"] > body["platform_default_min_confidence"]

    # Rule 6 — airgap must be an explicit boolean, never absent or ambiguous.
    assert isinstance(body["airgap"], bool)

    # P8 / ADR 0006 — whether a PDF can be produced here is probed, not assumed,
    # and reported so an operator can tell "unavailable on this machine" from
    # "reporting is broken". HTML reporting needs none of it.
    pdf = body["pdf_reporting"]
    assert isinstance(pdf["available"], bool)
    assert isinstance(pdf["weasyprint_installed"], bool)
    assert isinstance(pdf["missing_libraries"], list)
    assert pdf["available"] == (pdf["weasyprint_installed"] and not pdf["missing_libraries"])

    # Rule 4 — an empty snippet library is the honest state while no vendor
    # documentation has been sourced, and the readout says so rather than
    # leaving an operator to infer it from findings that carry no commands.
    assert body["remediation_library"]["snippets"] >= 0
    assert body["remediation_library"]["version"]


def test_startup_applies_migrations(client: TestClient) -> None:
    """The lifespan handler brings the schema up before anything is served."""
    assert client.get("/health").json()["schema_version"] >= 1


def test_audit_endpoints_are_mounted(client: TestClient) -> None:
    """Mounted, and protected from P7 onward (decision D25)."""
    from api.db import users as user_store
    from api.db.connection import connect

    conn = connect(settings.db_path)
    user_store.create_user(conn, "probe", "a-sufficiently-long-pw")
    conn.close()
    who = ("probe", "a-sufficiently-long-pw")

    assert client.get("/audit/head", auth=who).json()["empty"] is True
    assert client.get("/audit/verify", auth=who).json()["ok"] is True


def test_audit_endpoints_reject_anonymous_callers(client: TestClient) -> None:
    """The chain records who touched whose configuration. Not a public surface."""
    assert client.get("/audit/head").status_code == 401
    assert client.get("/audit/verify").status_code == 401


def test_health_reports_the_similarity_model(client: TestClient) -> None:
    """ADR 0018 — /health reports model availability from P11 onward.

    Deferred at P10 on the grounds that the model had no operator-facing
    consequence until a training queue was put in front of a person. P11 is that
    phase, so the readout arrives with the thing that gives it meaning.

    On this machine the `[ai]` extra is deliberately uninstalled, so the honest
    answer is `available: false` with the reason attached. The assertions below
    therefore check the SHAPE and the calibration statement rather than the
    value, which is environment-dependent and must stay so.
    """
    body = client.get("/health").json()
    model = body["similarity_model"]

    assert model["model"] == "sentence-transformers/all-MiniLM-L6-v2"
    assert isinstance(model["available"], bool)
    assert isinstance(model["package_installed"], bool)
    assert isinstance(model["weights_present"], bool)
    assert model["summary"]

    # R7 and D42 — no calibrator is fitted, and the readout says so rather than
    # letting a caller assume a score means a probability.
    assert model["calibrated"] is False
    assert "UNCALIBRATED_SIMILARITY" in model["note"]


def test_health_never_claims_a_calibrated_model(client: TestClient) -> None:
    """A fitted calibrator would be a claim about how often we are right.

    None is fitted, and nothing in the health readout may imply otherwise while
    the labelled population that would justify one does not exist
    (SOURCING_BACKLOG gap 7).
    """
    from api.learn.calibration import active_calibrator

    assert active_calibrator() is None
    assert client.get("/health").json()["similarity_model"]["calibrated"] is False
