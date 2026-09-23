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


def _library_commands() -> set[str]:
    """Every command string that exists anywhere under `snippets/`.

    Rollback lines included: a rollback is a command an operator will paste into
    a device, so Rule 4 governs it exactly as it governs the forward change.

    Read straight off disk rather than through the resolver, so the assertion
    below is checking the API against the files an operator can open, not against
    the same code path that produced the answer.
    """
    from api.remediate.library import load_library

    return {
        line
        for snippet in load_library().snippets
        for line in (*snippet.commands, *snippet.rollback)
    }


def test_no_command_in_a_report_was_generated(client: TestClient) -> None:
    """Rule 4, asserted at the API boundary.

    Was `test_every_failure_says_no_vetted_remediation_is_available`, which held
    while the library was empty: nothing could be generated because nothing could
    be returned. Now that commands do reach the report, the weaker property has
    to be replaced by the one it was standing in for — every command string the
    API emits appears verbatim in a file under `snippets/`.

    That is the whole of Rule 4 stated as a test: resolution, never generation.
    """
    audit_id = audited(client)
    findings = client.get(f"/compliance/audits/{audit_id}/findings?status=fail", auth=ALICE)
    failures = findings.json()["findings"]
    assert failures, "this fixture should produce at least one FAIL"

    vetted = _library_commands()
    emitted: list[str] = []
    for failure in failures:
        remediation = failure["remediation"]
        emitted.extend(remediation["commands"])
        emitted.extend(remediation["rollback"])

        if remediation["outcome"] == "resolved":
            assert remediation["commands"], "a resolved outcome with no commands"
            assert remediation["vetted_by"], "a command with no named vetter"
            assert remediation["reference"], "a command citing no document"
        else:
            assert remediation["outcome"] == "no_snippet"
            assert remediation["statement"] == NO_REMEDIATION_STATEMENT
            assert remediation["commands"] == []

    assert emitted, "the Cisco fixture should resolve at least one command"
    invented = sorted(set(emitted) - vetted)
    assert invented == [], f"commands not present in snippets/: {invented}"


def test_a_rule_with_no_snippet_still_says_so(client: TestClient) -> None:
    """The abstention path is live, not vestigial.

    `NRK-SSH-001` has no Arista snippet — EOS exposes no SSH protocol-version
    setting, so there was nothing to vet. The sentence an operator reads there is
    fixed text and is asserted here rather than only in a unit test, because this
    is the one path where a populated library could start quietly inventing a
    command to fill a gap.
    """
    from api.remediate.library import load_library
    from api.remediate.resolver import resolve

    resolution = resolve(
        load_library(),
        rule_id="NRK-SSH-001",
        vendor="arista",
        os_family="eos",
        actionable=True,
    )
    assert resolution.outcome.value == "no_snippet"
    assert resolution.snippet is None
    assert resolution.statement == NO_REMEDIATION_STATEMENT


def test_the_report_renders_a_command_only_with_its_rollback(client: TestClient) -> None:
    """§10 — "never the command alone".

    Was `test_the_report_offers_no_command_from_an_empty_library`, which asserted
    that `class="cmd"` never rendered. It renders now, so the guard moves to the
    thing that actually protects the operator: a command block never appears
    without the rollback and the vetting attribution beside it. A command with no
    way back, offered on NIRIKSHAK's authority, is the failure that assertion was
    always aiming at.
    """
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert 'class="cmd"' in html, "no command block rendered from a populated library"

    plan = client.get(f"/compliance/audits/{audit_id}/remediation", auth=ALICE).json()
    resolved = [step for step in plan["steps"] if step["snippet"] is not None]
    assert resolved, "the Cisco fixture should resolve at least one snippet"

    for step in resolved:
        snippet = step["snippet"]
        assert snippet["commands"], "a snippet step with no commands"
        assert snippet["rollback"], "a command offered with no way back"
        assert snippet["vetted_by"], "a command with no named vetter"
        assert snippet["reference"], "a command citing no document"


def test_the_report_shows_mapped_controls_and_refuses_to_certify(client: TestClient) -> None:
    """NIST identifiers render; the claim they support is bounded in the same document.

    This replaces `test_the_report_claims_no_framework_coverage`, which asserted
    that **no** identifier ships and was correct for as long as none did (D16).
    The gate moved rather than opened: identifiers may appear, and the document
    must say in the same breath that a catalog publishes controls rather than
    mappings, and that this is evidence about a configuration rather than a
    certification.
    """
    import re

    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    nist = re.findall(r"\b(?:AC|AU|CM|SC)-\d{2}(?:\(\d{2}\))?\b", html)
    assert nist, "the report shows no mapped control identifiers"

    lowered = html.lower()
    assert "not taken from a published crosswalk" in lowered
    assert "not a certification of compliance" in lowered

    unsourced = re.findall(r"\b(CIS[\s-]\d+\.\d+|V-\d{5,}|ISO\s*A\.\d+\.\d+)\b", html)
    assert unsourced == [], (
        f"the report carries identifiers for a framework with no catalog: {unsourced}"
    )


def test_the_report_names_the_benchmark_scope_of_the_run(client: TestClient) -> None:
    """A narrowed scope and a device with fewer findings must not read the same."""
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert "Benchmark scope" in html
    assert "no benchmark filter" in html, (
        "this fixture audits without a framework filter, and the report should "
        "say so rather than leaving the reader to infer it"
    )


def test_the_report_names_the_snippet_library_it_resolved_against(client: TestClient) -> None:
    """D26 — remediation is resolved at render time, so it is report provenance.

    The version is a digest over the library's own bytes. Naming it is what lets
    a reader of an old report answer "which commands was this document offering?"
    after the library has moved on.
    """
    from api.remediate.library import load_library

    library = load_library()
    audit_id = audited(client)
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text

    assert "Snippet library" in html
    assert library.version in html, "the report does not name the library it resolved against"
    assert library.version != "empty", "this test no longer proves anything"


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
    """Omitting the unfixable would understate the work by all of it.

    The invariant is unchanged; only the arithmetic moved. A step exists for
    every failing finding whether or not a snippet resolved for it, and `resolved`
    counts the subset that did. A plan that silently dropped the steps it has no
    command for would tell an operator their device needs less work than it does.
    """
    audit_id = audited(client)
    plan = client.get(f"/compliance/audits/{audit_id}/remediation", auth=ALICE)

    assert plan.status_code == 200, plan.text
    body = plan.json()

    assert body["failing_findings"] > 0
    assert len(body["steps"]) == body["failing_findings"], "a failing finding has no step"
    assert 0 <= body["resolved"] <= body["failing_findings"]
    assert body["snippet_library_version"] != "empty"

    resolved = [step for step in body["steps"] if step["snippet"] is not None]
    assert len(resolved) == body["resolved"]

    for step in body["steps"]:
        if step["snippet"] is None:
            # Nothing to apply, so no position in an application order.
            assert step["apply_order"] is None
            assert step["statement"] == NO_REMEDIATION_STATEMENT
        else:
            assert step["apply_order"] is not None, "a resolved step with no position"

    # The lockout rule, on real snippets: whatever can strand the operator is
    # sequenced after everything that cannot.
    ordered = sorted(resolved, key=lambda step: step["apply_order"])
    risks = [step["snippet"]["lockout_risk"] for step in ordered]
    rank = {"none": 0, "low": 1, "high": 2}
    assert risks == sorted(risks, key=lambda r: rank[r]), (
        f"a high-lockout-risk change is not applied last: {risks}"
    )


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
    from api.remediate.library import load_library

    library = load_library()
    body = client.get("/health").json()

    assert "pdf_reporting" in body
    assert body["pdf_reporting"]["available"] is availability().available

    # The library's own count and digest, so "no remediation available" can be
    # told apart from "the library failed to load".
    assert body["remediation_library"]["snippets"] == len(library.snippets)
    assert body["remediation_library"]["version"] == library.version
    assert body["remediation_library"]["snippets"] > 0


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

    Now that remediation resolves, the same boundary is checked against the other
    direction: a chain payload must not carry the *commands* either. They are not
    the operator's data, but they are report content, and the chain attests that
    a report was generated rather than reproducing what it said.
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

    for command in _library_commands():
        if len(command) > 12:
            assert command not in blob, f"the chain payload quotes a command: {command!r}"

    assert payload["audit_id"] == audit_id
    assert payload["format"] == "html"
    assert payload["snippet_library_version"] != "empty"
    assert payload["remediation_resolved"] > 0


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


@pytest.mark.skipif(not availability().available, reason="GTK is absent in this environment")
def test_the_pdf_endpoint_returns_a_pdf_when_the_runtime_is_present(
    client: TestClient,
) -> None:
    """The positive half, which had no test at all until P17.

    Every PDF test in this repository covered the *refusal* and skipped when GTK
    was present — so on a machine with the runtime installed, the endpoint that
    Problem Statement 26155 names as a deliverable was exercised by nothing. The
    capability worked and no test said so, which is the same blind spot as a
    capability that quietly stopped working.

    `Dockerfile` exists so this branch runs for a reviewer regardless of what is
    installed on their host.
    """
    audit_id = audited(client)
    response = client.get(f"/compliance/audits/{audit_id}/report.pdf", auth=ALICE)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.content.startswith(b"%PDF-"), "a .pdf response must contain a PDF"
    assert len(response.content) > 1000, "a report of one page is still not 200 bytes"
