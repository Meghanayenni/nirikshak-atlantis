"""Evaluating against user-selected benchmarks, and refusing the ones we cannot.

Problem Statement 26155 asks for evaluation against user-selected benchmarks.
The selector's hard requirement is the one in its own sentence: **a framework
with no sourced mapping is absent from the list, not present and empty.**

An empty result reads as "your fleet is compliant". "We have never read this
benchmark" is a different statement, and a selector that rendered them the same
would turn a sourcing gap into a compliance claim — which is the failure ADR
0035 was written to avoid in the first place, reappearing one layer up.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.comply.frameworks import UnsourcedFrameworkError, resolve_selection, sourced_frameworks
from api.comply.rulepacks import load_rulepack
from api.config import settings
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.main import app
from api.models.enums import Framework

CISCO = Path("corpus/cisco/dev/sw-access-02.cfg")
ALICE = ("alice", "correct-horse-battery")


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """A per-test deployment, as the other integration suites each stand one up.

    Not imported from a sibling module: every integration suite here owns its
    fixture, and reaching into another test file to borrow one would make the
    two collide at collection time for no benefit.
    """
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "nirikshak-audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")

    conn = connect(tmp_path / "nirikshak.db")
    migrate(conn, OPERATIONAL_MIGRATIONS)
    user_store.create_user(conn, ALICE[0], ALICE[1])
    conn.close()

    with TestClient(app) as test_client:
        yield test_client


def upload_cisco(api: TestClient) -> str:
    upload = api.post(
        "/ingest/upload",
        files={"files": (CISCO.name, CISCO.read_bytes(), "text/plain")},
        auth=ALICE,
    )
    assert upload.status_code == 200, upload.text
    return upload.json()["accepted"][0]["file_id"]


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def test_an_empty_selection_means_no_filter() -> None:
    """Distinct from a selection that matched nothing, which is unreachable."""
    assert resolve_selection([]) == frozenset()

    rulepack = load_rulepack()
    assert len(rulepack.applicable_to("cisco", "ios", frameworks=frozenset())) == len(
        rulepack.applicable_to("cisco", "ios")
    )


def test_a_sourced_framework_resolves() -> None:
    assert resolve_selection(["nist"]) == frozenset({Framework.NIST})
    assert resolve_selection(["NIST", " nist "]) == frozenset({Framework.NIST})


@pytest.mark.parametrize("name", ["cis", "stig", "iso"])
def test_a_framework_with_no_catalog_is_refused(name: str) -> None:
    """Not answered with zero findings. Refused, with the reason."""
    with pytest.raises(UnsourcedFrameworkError, match="no catalog has been sourced"):
        resolve_selection([name])


def test_an_unknown_name_is_refused_differently() -> None:
    """A typo and a sourcing gap send the caller to different places."""
    with pytest.raises(UnsourcedFrameworkError, match="not a framework this system knows"):
        resolve_selection(["nist-800-53"])


def test_the_selector_offers_only_what_has_a_catalog() -> None:
    assert sourced_frameworks() == frozenset({Framework.NIST})


# ---------------------------------------------------------------------------
# Over the API
# ---------------------------------------------------------------------------


def test_the_frameworks_endpoint_lists_the_catalog_behind_each_option(
    client: TestClient,
) -> None:
    """An option names the document and the bytes it was read from."""
    body = client.get("/compliance/audits/frameworks").json()

    assert [f["framework"] for f in body["frameworks"]] == ["nist"]
    entry = body["frameworks"][0]
    assert len(entry["catalog_sha256"]) == 64
    assert entry["edition"]
    assert entry["controls_indexed"] > 0
    assert "does not publish mappings" in body["note"]


def test_the_frameworks_endpoint_omits_frameworks_with_no_catalog(
    client: TestClient,
) -> None:
    """The requirement, stated as its own test because it is the whole point."""
    offered = {
        f["framework"] for f in client.get("/compliance/audits/frameworks").json()["frameworks"]
    }

    assert "cis" not in offered
    assert "stig" not in offered
    assert "iso" not in offered


def test_auditing_against_a_sourced_framework_scopes_and_records_it(
    client: TestClient,
) -> None:
    file_id = upload_cisco(client)
    body = client.post(f"/compliance/audits?file_id={file_id}&framework=nist", auth=ALICE).json()

    assert body["framework_selection"] == ["nist"]
    assert body["rules_evaluated"] == 7, "every rule maps to NIST, so nothing is excluded"


def test_auditing_without_a_framework_records_no_selection(client: TestClient) -> None:
    """`None`, not `[]`. A run scoped to nothing and a run not scoped are different."""
    file_id = upload_cisco(client)
    body = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()

    assert body["framework_selection"] is None


def test_auditing_against_an_unsourced_framework_is_a_400(client: TestClient) -> None:
    """Not a 200 with zero findings, which is the dangerous answer."""
    file_id = upload_cisco(client)
    response = client.post(f"/compliance/audits?file_id={file_id}&framework=iso", auth=ALICE)

    assert response.status_code == 400
    assert "no catalog has been sourced" in response.json()["detail"]


def test_the_selection_survives_into_the_report(client: TestClient) -> None:
    """The run records its scope, so a re-read report does not have to guess.

    Without the stored column, seven findings and three would look the same to a
    later reader: a narrowed benchmark and a device that produced fewer results
    are different facts.
    """
    file_id = upload_cisco(client)
    audit_id = client.post(
        f"/compliance/audits?file_id={file_id}&framework=nist", auth=ALICE
    ).json()["audit_id"]

    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert "Benchmark scope" in html
    assert "NIST" in html
    assert "only rules mapping to these were evaluated" in html
