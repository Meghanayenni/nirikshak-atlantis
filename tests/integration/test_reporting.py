"""Reporting end to end, over the real API (P8).

Upload a real corpus configuration, audit it, and ask for the report. Everything
in between is the actual pipeline: ingestion, detection, parsing, normalisation,
evaluation, persistence, remediation resolution and rendering.

What these assert is mostly what the document **does not** say. The report is
where a refusal made deep in the system either survives or quietly evaporates,
and the ways it evaporates are specific: an empty framework list becomes a column
of blanks, an unresolved snippet becomes an empty panel that looks like a
rendering fault, a severity list appears under an exposure-ranked heading.

The PDF endpoint is exercised too. On this machine it must return 503 naming the
missing GTK libraries - never the HTML document with a different content type.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import settings
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.main import app
from api.models.enums import Role
from api.remediate.resolver import NO_REMEDIATION_STATEMENT
from api.report.pdf import availability

CISCO = Path("corpus/cisco/dev/sw-access-02.cfg")
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


def audited(client: TestClient, who=ALICE, path: Path = CISCO) -> str:
    """Upload and audit one configuration; return the audit id."""
    upload = client.post(
        "/ingest/upload",
        files={"files": (path.name, path.read_bytes(), "text/plain")},
        auth=who,
    )
    assert upload.status_code == 200, upload.text
    file_id = upload.json()["accepted"][0]["file_id"]

    run = client.post(f"/compliance/audits?file_id={file_id}", auth=who)
    assert run.status_code == 201, run.text
    return run.json()["audit_id"]


# ---------------------------------------------------------------------------
# The HTML report
# ---------------------------------------------------------------------------


def test_a_report_renders_for_a_real_configuration(client: TestClient) -> None:
    audit_id = audited(client)
    response = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE)

    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/html")
    assert "NIRIKSHAK" in response.text
    assert "compliance report" in response.text


def test_the_report_cites_lines_from_the_operators_own_file(client: TestClient) -> None:
    """Rule 2 — evidence resolves back to the exact stored bytes.

    The citation is the finding. A report that says a control failed without
    showing where is not evidence of anything.
    """
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    source = CISCO.read_text(encoding="utf-8").splitlines()
    cited = [line.strip() for line in source if line.strip() and line.strip() in html]
    assert cited, "the report cites no line from the configuration it audited"


def test_every_failure_says_no_vetted_remediation_is_available(client: TestClient) -> None:
    """D27 — the library is empty, and the document says so in that exact sentence."""
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    findings = client.get(f"/compliance/audits/{audit_id}/findings?status=fail", auth=ALICE)
    failures = findings.json()["findings"]

    assert failures, "this fixture should produce at least one FAIL"
    assert NO_REMEDIATION_STATEMENT in html
    for failure in failures:
        assert failure["remediation"]["outcome"] == "no_snippet"
        assert failure["remediation"]["statement"] == NO_REMEDIATION_STATEMENT
        assert failure["remediation"]["commands"] == []


def test_the_report_offers_no_command_from_an_empty_library(client: TestClient) -> None:
    """Rule 4 — no command block is rendered when nothing resolved.

    Asserted on the command block rather than on command text, because the two
    are different things and only one of them is a violation. Configuration
    syntax *does* appear in this document: every cited evidence line is verbatim
    text from the operator's own file, and Rule 2 requires it be shown. What must
    never appear is a command NIRIKSHAK is offering, and `class="cmd"` is
    rendered only when the resolver returned a vetted snippet.
    """
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert 'class="cmd"' not in html, "a command block rendered from an empty library"
    assert 'class="none"' in html, "the no-remediation block did not render"

    plan = client.get(f"/compliance/audits/{audit_id}/remediation", auth=ALICE).json()
    assert all(step["snippet"] is None for step in plan["steps"])


def test_the_report_claims_no_framework_coverage(client: TestClient) -> None:
    """D16 — no CIS, NIST, DISA STIG or ISO/IEC 27001 identifier ships."""
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    import re

    identifiers = re.findall(r"\b(CIS[\s-]\d+\.\d+|AC-\d+|IA-\d+|AU-\d+|V-\d{5,})\b", html)
    assert identifiers == [], f"the report carries framework identifiers: {identifiers}"
    assert "no claim of coverage" in html.lower()


def test_the_report_names_the_snippet_library_it_resolved_against(client: TestClient) -> None:
    """D26 — remediation is resolved at render time, so it is report provenance."""
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert "Snippet library" in html
    assert "empty" in html


def test_the_report_does_not_present_its_subject_as_a_device(client: TestClient) -> None:
    """DEF-3 — `device_id` is the uploaded file's content hash."""
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert "Configuration file" in html
    assert "not the device it came from" in html


def test_a_detection_only_platform_reports_honestly(client: TestClient) -> None:
    """Arista has no parsing pack, so nearly everything abstains.

    A visually empty report is the correct output here. What must not happen is
    the abstentions being rendered as passes, or the document implying the device
    was assessed.
    """
    audit_id = audited(client, path=ARISTA)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert "UNKNOWN" in html
    assert "abstained" in html.lower()


# ---------------------------------------------------------------------------
# The remediation plan
# ---------------------------------------------------------------------------


def test_the_plan_lists_every_failure_even_with_nothing_to_apply(client: TestClient) -> None:
    """Omitting the unfixable would understate the work by all of it."""
    audit_id = audited(client)
    plan = client.get(f"/compliance/audits/{audit_id}/remediation", auth=ALICE)

    assert plan.status_code == 200, plan.text
    body = plan.json()

    assert body["failing_findings"] > 0
    assert body["resolved"] == 0
    assert body["snippet_library_version"] == "empty"
    for step in body["steps"]:
        assert step["snippet"] is None
        assert step["apply_order"] is None
        assert step["statement"] == NO_REMEDIATION_STATEMENT


def test_the_plan_says_nirikshak_does_not_apply_anything(client: TestClient) -> None:
    """R1 — the system recommends; a human operates."""
    audit_id = audited(client)
    body = client.get(f"/compliance/audits/{audit_id}/remediation", auth=ALICE).json()

    assert "does not apply these commands" in body["note"]


# ---------------------------------------------------------------------------
# The PDF path (ADR 0006)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(availability().available, reason="GTK is installed in this environment")
def test_the_pdf_endpoint_refuses_rather_than_substituting_html(client: TestClient) -> None:
    """The decision D1 approved: fail, name the runtime, never fall back."""
    audit_id = audited(client)
    response = client.get(f"/compliance/audits/{audit_id}/report.pdf", auth=ALICE)

    assert response.status_code == 503
    detail = response.json()["detail"]

    assert "libpango-1.0-0" in detail
    assert "docs/adr/0006-weasyprint-gtk-probe.md" in detail
    assert "<html" not in response.text.lower()
    assert not response.headers["content-type"].startswith("application/pdf")


@pytest.mark.skipif(availability().available, reason="GTK is installed in this environment")
def test_the_refusal_does_not_leak_the_configuration(client: TestClient) -> None:
    """A 503 body is an error message, not a place to put an operator's file."""
    audit_id = audited(client)
    detail = client.get(f"/compliance/audits/{audit_id}/report.pdf", auth=ALICE).json()["detail"]

    for line in CISCO.read_text(encoding="utf-8").splitlines():
        if len(line.strip()) > 12:
            assert line.strip() not in detail


def test_health_reports_the_pdf_state(client: TestClient) -> None:
    """So an operator can tell "PDF unavailable here" from "reporting is broken"."""
    body = client.get("/health").json()

    assert "pdf_reporting" in body
    assert body["pdf_reporting"]["available"] is availability().available
    assert body["remediation_library"]["snippets"] == 0
    assert body["remediation_library"]["version"] == "empty"


# ---------------------------------------------------------------------------
# Access control (decision D25 still holds for the new routes)
# ---------------------------------------------------------------------------


def test_a_report_requires_authentication(client: TestClient) -> None:
    audit_id = audited(client)

    for suffix in ("report.html", "report.pdf", "remediation"):
        assert client.get(f"/compliance/audits/{audit_id}/{suffix}").status_code == 401


def test_another_users_report_is_not_found_rather_than_forbidden(client: TestClient) -> None:
    """403 would confirm the id exists and let someone walk the id space."""
    audit_id = audited(client, who=ALICE)

    for suffix in ("report.html", "report.pdf", "remediation"):
        response = client.get(f"/compliance/audits/{audit_id}/{suffix}", auth=BOB)
        assert response.status_code == 404, f"{suffix} answered {response.status_code}"


def test_an_admin_may_report_on_any_run(client: TestClient) -> None:
    audit_id = audited(client, who=ALICE)
    response = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ROOT)

    assert response.status_code == 200


def test_an_unknown_audit_is_not_found(client: TestClient) -> None:
    response = client.get("/compliance/audits/does-not-exist/report.html", auth=ALICE)
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# The audit chain (decision D4)
# ---------------------------------------------------------------------------


def test_generating_a_report_is_recorded_in_the_chain(client: TestClient) -> None:
    audit_id = audited(client)
    client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE)

    records = client.get("/audit/records", auth=ALICE).json()
    actions = [r["action"] for r in records["records"]]

    assert "report_generated" in actions


def test_the_chain_record_holds_no_configuration_content(client: TestClient) -> None:
    """The boundary D4 established, restated at the newest writer.

    The audit database holds identifiers, counts and hashes. A report entry that
    carried a finding's value or a cited line would put configuration content in
    the one store that must never hold any.
    """
    audit_id = audited(client)
    client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE)

    records = client.get("/audit/records", auth=ALICE).json()["records"]
    report_records = [r for r in records if r["action"] == "report_generated"]
    assert report_records

    payload = json.loads(report_records[0]["payload"])
    blob = str(payload)

    for line in CISCO.read_text(encoding="utf-8").splitlines():
        if len(line.strip()) > 12:
            assert line.strip() not in blob

    assert payload["audit_id"] == audit_id
    assert payload["format"] == "html"
    assert payload["snippet_library_version"] == "empty"
    assert payload["remediation_resolved"] == 0


def test_the_chain_record_does_not_call_the_subject_a_device(client: TestClient) -> None:
    """DEF-3 — the field is named for what it holds."""
    audit_id = audited(client)
    client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE)

    records = client.get("/audit/records", auth=ALICE).json()["records"]
    payload = json.loads(next(r for r in records if r["action"] == "report_generated")["payload"])

    assert "config_file_id" in payload
    assert "device_id" not in payload


def test_the_chain_still_verifies_after_a_report(client: TestClient) -> None:
    """A new writer must not break the tamper-evident chain."""
    audit_id = audited(client)
    client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE)

    verification = client.get("/audit/verify", auth=ALICE).json()
    assert verification["ok"] is True
