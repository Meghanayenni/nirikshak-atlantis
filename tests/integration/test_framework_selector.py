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


@pytest.mark.parametrize("name", ["iso"])
def test_a_framework_with_no_catalog_is_refused(name: str) -> None:
    """Not answered with zero findings. Refused, with the reason."""
    with pytest.raises(UnsourcedFrameworkError, match="no catalog has been sourced"):
        resolve_selection([name])


def test_an_unknown_name_is_refused_differently() -> None:
    """A typo and a sourcing gap send the caller to different places."""
    with pytest.raises(UnsourcedFrameworkError, match="not a framework this system knows"):
        resolve_selection(["nist-800-53"])


def test_the_selector_offers_only_what_has_a_catalog() -> None:
    assert sourced_frameworks() == frozenset({Framework.NIST, Framework.STIG, Framework.CIS})


# ---------------------------------------------------------------------------
# Over the API
# ---------------------------------------------------------------------------


def test_the_frameworks_endpoint_lists_the_catalog_behind_each_option(
    client: TestClient,
) -> None:
    """An option names the document and the bytes it was read from."""
    body = client.get("/compliance/audits/frameworks").json()

    assert [f["framework"] for f in body["frameworks"]] == ["cis", "nist", "stig"]
    for entry in body["frameworks"]:
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


# ---------------------------------------------------------------------------
# A platform benchmark's identifiers hold only on its platform (ADR 0052)
# ---------------------------------------------------------------------------

IOS_XE_17 = Path("corpus/cisco/dev/rtr-core-01.cfg")
JUNOS = Path("corpus/juniper/dev/edge-rtr-02.conf")


def _upload(api: TestClient, path: Path) -> str:
    upload = api.post(
        "/ingest/upload",
        files={"files": (path.name, path.read_bytes(), "text/plain")},
        auth=ALICE,
    )
    assert upload.status_code == 200, upload.text
    return upload.json()["accepted"][0]["file_id"]


def _mapped(body: dict) -> set[str]:
    return {m["framework"] for f in body["findings"] for m in f["frameworks"]}


def test_an_ios_xe_17_device_carries_stig_and_cis_identifiers(client: TestClient) -> None:
    file_id = _upload(client, IOS_XE_17)
    body = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()
    findings = client.get(f"/compliance/audits/{body['audit_id']}/findings", auth=ALICE).json()

    assert _mapped(findings) == {"nist", "stig", "cis"}

    html = client.get(f"/compliance/audits/{body['audit_id']}/report.html", auth=ALICE).text
    assert "CISC-ND-000470" in html
    assert "ISO: no ISO catalog has been sourced" in html


def test_a_junos_device_carries_nist_only_and_the_report_says_why(client: TestClient) -> None:
    """Not "no catalog sourced" — the STIG and CIS were read and do not describe JunOS."""
    file_id = _upload(client, JUNOS)
    body = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()
    findings = client.get(f"/compliance/audits/{body['audit_id']}/findings", auth=ALICE).json()

    assert _mapped(findings) <= {"nist"}
    html = client.get(f"/compliance/audits/{body['audit_id']}/report.html", auth=ALICE).text
    assert "CISC-ND-" not in html
    assert "which the edition does not describe" in html
    assert "no STIG catalog has been sourced" not in html


# ---------------------------------------------------------------------------
# Framework choice changes the verdict (ADR 0054)
# ---------------------------------------------------------------------------


def _ios_xe_17_with_http_server() -> tuple[str, bytes]:
    """`edge-rtr-01.cfg` with its version line rewritten to an IOS XE 17 release.

    **Constructed, and said so.** No corpus file is both inside the STIG's and
    CIS's scope (cisco/ios, 17.x) and enables `ip http server`: the two 17.x
    files both carry `no ip http server`, and the three that enable it are IOS
    15.x. The contrast cannot be shown on the corpus as it stands, and adding a
    corpus file to make it showable is out of scope. The configuration body is
    the development file byte for byte; only the release differs.
    """
    text = Path("corpus/cisco/dev/edge-rtr-01.cfg").read_text(encoding="utf-8")
    assert "\nversion 15.2\n" in text, "fixture drifted"
    return "edge-rtr-01-as-17.cfg", text.replace("\nversion 15.2\n", "\nversion 17.9\n").encode()


def _upload_bytes(api: TestClient, name: str, data: bytes) -> str:
    upload = api.post("/ingest/upload", files={"files": (name, data, "text/plain")}, auth=ALICE)
    assert upload.status_code == 200, upload.text
    return upload.json()["accepted"][0]["file_id"]


def _http(api: TestClient, audit_id: str) -> list[dict]:
    body = api.get(f"/compliance/audits/{audit_id}/findings", auth=ALICE).json()
    return [f for f in body["findings"] if f["rule_id"] == "NRK-HTTP-001"]


def test_the_same_device_fails_under_stig_and_is_not_assessed_under_cis(
    client: TestClient,
) -> None:
    """The clearest demonstration the project has that framework choice changes the verdict.

    The STIG says `ip http server` must not be configured: FAIL, citing
    CISC-ND-000470 and the line. CIS constrains the server and never requires
    it off: the rule is not assessed, and the reason is the one the rule
    records — not a missing row, not an UNKNOWN.
    """
    file_id = _upload_bytes(client, *_ios_xe_17_with_http_server())

    stig = client.post(f"/compliance/audits?file_id={file_id}&framework=stig", auth=ALICE)
    assert stig.status_code == 201, stig.text
    [finding] = _http(client, stig.json()["audit_id"])
    assert finding["status"] == "fail"
    assert ("stig", "CISC-ND-000470") in {
        (m["framework"], m["control_id"]) for m in finding["frameworks"]
    }
    assert finding["evidence"][0]["raw_line"].strip() == "ip http server"
    assert "NRK-HTTP-001" not in {n["rule_id"] for n in stig.json()["not_assessed"]}

    cis = client.post(f"/compliance/audits?file_id={file_id}&framework=cis", auth=ALICE)
    assert cis.status_code == 201, cis.text
    assert _http(client, cis.json()["audit_id"]) == [], "no finding, not an UNKNOWN one"
    [left_out] = [n for n in cis.json()["not_assessed"] if n["rule_id"] == "NRK-HTTP-001"]
    assert "1.1.5" in left_out["reason"] and "CISC-ND-000470" in left_out["reason"]

    html = client.get(f"/compliance/audits/{cis.json()['audit_id']}/report.html", auth=ALICE).text
    assert "Not assessed under this scope" in html
    assert "NRK-HTTP-001" in html


def test_the_stig_leaves_out_the_four_rules_it_is_stricter_than(client: TestClient) -> None:
    file_id = _upload_bytes(client, *_ios_xe_17_with_http_server())
    body = client.post(f"/compliance/audits?file_id={file_id}&framework=stig", auth=ALICE).json()

    assert {n["rule_id"] for n in body["not_assessed"]} == {
        "NRK-TIMEOUT-001",
        "NRK-LOGGING-001",
        "NRK-NTP-001",
        "NRK-BANNER-001",
    }
    assert body["rules_evaluated"] == 3


@pytest.mark.parametrize(
    ("path", "framework", "said"),
    [
        (JUNOS, "stig", "juniper/junos"),
        (JUNOS, "cis", "juniper/junos"),
        (CISCO, "cis", "release 15.2"),
        (CISCO, "stig", "release 15.2"),
    ],
)
def test_a_benchmark_that_does_not_describe_the_device_is_refused(
    client: TestClient, path: Path, framework: str, said: str
) -> None:
    """409 with the reason — never a run with zero findings, which reads as compliance."""
    file_id = _upload(client, path)
    response = client.post(
        f"/compliance/audits?file_id={file_id}&framework={framework}", auth=ALICE
    )
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert "none of the selected frameworks describes this device" in detail
    assert said in detail


def test_a_mixed_selection_applies_what_it_can_and_names_what_it_cannot(
    client: TestClient,
) -> None:
    file_id = _upload(client, JUNOS)
    body = client.post(
        f"/compliance/audits?file_id={file_id}&framework=nist&framework=stig", auth=ALICE
    ).json()

    assert body["framework_selection"] == ["nist", "stig"]
    assert list(body["frameworks_not_describing_device"]) == ["stig"]
    assert body["rules_evaluated"] == 7

    html = client.get(f"/compliance/audits/{body['audit_id']}/report.html", auth=ALICE).text
    assert "STIG</span> selected and not applied" in html


def test_iso_is_still_absent_from_the_selector_and_refused(client: TestClient) -> None:
    offered = {
        f["framework"] for f in client.get("/compliance/audits/frameworks").json()["frameworks"]
    }
    assert offered == {"nist", "stig", "cis"}
    file_id = _upload(client, IOS_XE_17)
    response = client.post(f"/compliance/audits?file_id={file_id}&framework=iso", auth=ALICE)
    assert response.status_code == 400


def test_the_three_selections_on_one_configuration(client: TestClient) -> None:
    """The table in ADR 0054, asserted rather than written down."""
    file_id = _upload_bytes(client, *_ios_xe_17_with_http_server())

    def run(query: str) -> dict:
        response = client.post(f"/compliance/audits?file_id={file_id}{query}", auth=ALICE)
        assert response.status_code == 201, response.text
        return response.json()

    none, stig, cis = run(""), run("&framework=stig"), run("&framework=cis")
    assert (none["rules_evaluated"], stig["rules_evaluated"], cis["rules_evaluated"]) == (7, 3, 6)
    assert none["not_assessed"] == []
    assert [n["rule_id"] for n in cis["not_assessed"]] == ["NRK-HTTP-001"]

    [unfiltered] = _http(client, none["audit_id"])
    assert unfiltered["status"] == "fail"
    assert {(m["framework"], m["control_id"]) for m in unfiltered["frameworks"]} == {
        ("nist", "CM-07"),
        ("nist", "AC-17(02)"),
        ("stig", "CISC-ND-000470"),
    }


@pytest.mark.parametrize("framework", ["stig", "cis"])
def test_the_corpus_ios_xe_17_router_is_described_by_both(
    client: TestClient, framework: str
) -> None:
    file_id = _upload(client, IOS_XE_17)
    response = client.post(
        f"/compliance/audits?file_id={file_id}&framework={framework}", auth=ALICE
    )
    assert response.status_code == 201
    assert response.json()["frameworks_not_describing_device"] == {}


# ---------------------------------------------------------------------------
# Mappings are re-attached by content, not by label (ADR 0056)
# ---------------------------------------------------------------------------


def test_a_run_records_the_checksum_of_the_rules_that_decided_it(client: TestClient) -> None:
    file_id = _upload(client, IOS_XE_17)
    audit_id = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()["audit_id"]
    run = client.get(f"/compliance/audits/{audit_id}", auth=ALICE).json()

    assert run["rulepack_checksum"] == load_rulepack().checksum
    assert run["rulepack_version"] == load_rulepack().version


def test_same_version_different_content_shows_no_identifiers(
    client: TestClient, tmp_path: Path
) -> None:
    """The case D125 permitted and D96 could not detect.

    The run's version equals the active one; its recorded content does not (here,
    NULL — what every run before migration 0005 holds). Under the old version
    comparison this report showed today's control identifiers beside a verdict
    that different rules decided. It must show none, on both surfaces.
    """
    file_id = _upload(client, IOS_XE_17)
    audit_id = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()["audit_id"]

    conn = connect(tmp_path / "nirikshak.db")
    conn.execute("UPDATE audit_run SET rulepack_checksum = NULL WHERE audit_id = ?", (audit_id,))
    conn.commit()
    conn.close()

    run = client.get(f"/compliance/audits/{audit_id}", auth=ALICE).json()
    assert run["rulepack_version"] == load_rulepack().version, "the label still matches"

    findings = client.get(f"/compliance/audits/{audit_id}/findings", auth=ALICE).json()
    assert all(f["frameworks"] == [] for f in findings["findings"])
    html = client.get(f"/compliance/audits/{audit_id}/report.html", auth=ALICE).text
    assert "CISC-ND-" not in html and "AC-17(02)" not in html
    assert "content not recorded" in html


# ---------------------------------------------------------------------------
# What the interface reads (ADR 0057, ADR 0058) — the API decides, the UI shows
# ---------------------------------------------------------------------------


def _findings(api: TestClient, audit_id: str) -> dict:
    return api.get(f"/compliance/audits/{audit_id}/findings", auth=ALICE).json()


def test_every_mapping_carries_its_edition_and_whose_judgement_it_is(client: TestClient) -> None:
    file_id = _upload(client, IOS_XE_17)
    audit_id = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()["audit_id"]
    body = _findings(client, audit_id)

    assert body["framework_view"]["attached"] is True
    refs = [m for f in body["findings"] for m in f["frameworks"]]
    assert refs
    for ref in refs:
        assert ref["edition"] and ref["citation"]
        assert ref["mapping_provenance"] == "project_asserted"
    stig = next(m for m in refs if m["control_id"] == "CISC-ND-000470")
    assert stig["edition"] == "V3R7 (2026-04-01)"


def test_a_declined_mapping_travels_with_its_reason(client: TestClient) -> None:
    """The clearest evidence that mappings were checked rather than assembled."""
    file_id = _upload(client, IOS_XE_17)
    audit_id = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()["audit_id"]
    timeout = next(
        f for f in _findings(client, audit_id)["findings"] if f["rule_id"] == "NRK-TIMEOUT-001"
    )
    [declined] = timeout["declined"]
    assert declined["framework"] == "stig"
    assert "CISC-ND-000720" in declined["reason"] and "five minutes" in declined["reason"]


def test_a_decline_is_not_shown_where_the_framework_does_not_apply(client: TestClient) -> None:
    """On JunOS the STIG says nothing, so its declines say nothing either; the absence says why."""
    file_id = _upload(client, JUNOS)
    audit_id = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()["audit_id"]
    body = _findings(client, audit_id)

    assert all(f["declined"] == [] for f in body["findings"])
    assert "does not describe" in body["framework_view"]["absent"]["stig"]
    assert "no ISO catalog has been sourced" in body["framework_view"]["absent"]["iso"]


def test_withheld_mappings_say_why_instead_of_saying_none_exist(
    client: TestClient, tmp_path: Path
) -> None:
    file_id = _upload(client, IOS_XE_17)
    audit_id = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE).json()["audit_id"]
    conn = connect(tmp_path / "nirikshak.db")
    conn.execute("UPDATE audit_run SET rulepack_checksum = NULL WHERE audit_id = ?", (audit_id,))
    conn.commit()
    conn.close()

    view = _findings(client, audit_id)["framework_view"]
    assert view["attached"] is False
    assert "re-run the audit" in view["withheld_reason"]


def test_the_findings_view_carries_the_selections_scope(client: TestClient) -> None:
    file_id = _upload_bytes(client, *_ios_xe_17_with_http_server())
    audit_id = client.post(
        f"/compliance/audits?file_id={file_id}&framework=cis", auth=ALICE
    ).json()["audit_id"]
    view = _findings(client, audit_id)["framework_view"]

    assert view["selection"] == ["cis"]
    assert [n["rule_id"] for n in view["not_assessed"]] == ["NRK-HTTP-001"]


@pytest.mark.parametrize(
    ("path", "describes"),
    [
        (IOS_XE_17, {"nist": True, "stig": True, "cis": True}),
        (JUNOS, {"nist": True, "stig": False, "cis": False}),
        (CISCO, {"nist": True, "stig": False, "cis": False}),
    ],
)
def test_the_selector_options_are_decided_by_the_api(
    client: TestClient, path: Path, describes: dict
) -> None:
    file_id = _upload(client, path)
    body = client.get(f"/compliance/audits/frameworks/device/{file_id}", auth=ALICE).json()

    assert {f["framework"]: f["describes_device"] for f in body["frameworks"]} == describes
    for option in body["frameworks"]:
        assert (option["reason"] is None) is option["describes_device"]
    assert "iso" not in {f["framework"] for f in body["frameworks"]}
