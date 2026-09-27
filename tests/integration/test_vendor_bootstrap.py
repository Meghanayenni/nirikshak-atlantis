"""Bootstrapping a platform no pack knows, from one of its files (ADR 0067).

The demo fixture is `corpus/mikrotik/dev/edge-mt-01.rsc`: MikroTik RouterOS,
which no pack describes, written from MikroTik's own documentation. Every test
runs against a temporary trained root, so nothing is ever activated into the
working tree.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from api.config import settings
from api.db import users as user_store
from api.db.connection import connect
from api.db.migrate import OPERATIONAL_MIGRATIONS, migrate
from api.ingest import lines
from api.ingest import packs as pack_loader
from api.ingest.pack_activation import ActivationRecord
from api.main import app
from api.models.auth import Role
from api.models.enums import SyntaxMode
from api.train import activation as activation_module
from api.train import bootstrap
from api.train import service as train_service

ALICE = ("alice", "correct-horse-battery")
ROOT = ("root", "admin-long-password-1")

CORPUS = Path("corpus")
ROUTEROS = CORPUS / "mikrotik/dev/edge-mt-01.rsc"
FINGERPRINTS = ["/ip firewall filter", "/ip service", "/system ntp client"]


@pytest.fixture
def trained(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "trained"
    monkeypatch.setattr(pack_loader, "TRAINED_ROOT", root)
    monkeypatch.setattr(activation_module, "TRAINED_ROOT", root)
    monkeypatch.setattr(train_service, "TRAINED_ROOT", root)
    monkeypatch.setattr(bootstrap, "TRAINED_ROOT", root)
    monkeypatch.setattr(pack_loader, "PACK_ROOTS", (pack_loader.PACKS_ROOT, root))
    return root


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, trained: Path) -> TestClient:
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "nirikshak-audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")

    conn = connect(tmp_path / "nirikshak.db")
    migrate(conn, OPERATIONAL_MIGRATIONS)
    user_store.create_user(conn, ALICE[0], ALICE[1])
    user_store.create_user(conn, ROOT[0], ROOT[1], role=Role.ADMIN)
    conn.close()

    pack_loader.clear_pack_cache()
    with TestClient(app) as test_client:
        yield test_client
    pack_loader.clear_pack_cache()


def _upload(client: TestClient, name: str, data: bytes) -> dict:
    response = client.post(
        "/ingest/upload", files={"files": (name, data, "text/plain")}, auth=ALICE
    )
    assert response.status_code == 200, response.text
    return response.json()["accepted"][0]


def _device(client: TestClient, file_id: str) -> dict:
    devices = client.get("/ingest/devices", auth=ALICE).json()["devices"]
    return next(d for d in devices if d["device_id"] == file_id)


def _bootstrap(client: TestClient, file_id: str, **overrides) -> object:
    body = {
        "file_id": file_id,
        "vendor": "mikrotik",
        "os_family": "routeros",
        "syntax_mode": "indent",
        "fingerprints": FINGERPRINTS,
    }
    body.update(overrides)
    return client.post("/training/bootstrap", json=body, auth=ROOT)


# ---------------------------------------------------------------------------
# What is derived, and from what
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "mode"),
    [
        ("juniper/dev/core-rtr-01.conf", SyntaxMode.BRACE),
        ("juniper/dev/edge-rtr-02.conf", SyntaxMode.SET_PATH),
        ("cisco/dev/rtr-core-01.cfg", SyntaxMode.INDENT),
        ("mikrotik/dev/edge-mt-01.rsc", SyntaxMode.INDENT),
    ],
)
def test_the_syntax_mode_is_derived_from_corpus_files_of_known_mode(
    path: str, mode: SyntaxMode
) -> None:
    text = (CORPUS / path).read_text(encoding="utf-8")
    physical = lines.split_lines(text)
    comment = bootstrap.comment_style(physical).prefix

    found = bootstrap.derive_syntax(text, physical, comment)

    assert found.mode is mode
    assert found.evidence, "a mode is reported with the counts that decided it"


def test_xml_is_derived_from_a_parse_not_a_guess() -> None:
    """The corpus's only XML is the sealed PAN-OS holdout, so a constructed file.

    Derived, and refused for bootstrap: the parser declares XML and does not
    implement it, so a pack in that mode would raise on every audit.
    """
    text = "<config>\n  <system><hostname>x</hostname></system>\n</config>\n"
    found = bootstrap.derive_syntax(text, lines.split_lines(text), None)

    assert found.mode is SyntaxMode.XML
    assert found.evidence == ("the file parses as XML",)
    assert found.parseable is False


def test_fingerprints_exclude_every_stem_an_active_pack_uses() -> None:
    """A stem from any active pack's examples or detection is never offered."""
    text = (
        "hostname fixture-01\n"  # IOS identity example starts `hostname `
        "set system host-name fixture-01\n"  # a JunOS detection signature
        "ip ssh version 2\n"  # an IOS pattern example
        "widget frobnicate enable\n"  # nobody's
        "widget frobnicate enable\n"
    )
    candidates, excluded = bootstrap.fingerprint_candidates(
        lines.split_lines(text), pack_loader.load_active_packs(use_cache=False), None
    )

    assert [c.stem for c in candidates] == ["widget frobnicate enable"]
    assert candidates[0].occurrences == 2
    assert candidates[0].pattern == "^widget frobnicate enable$"
    assert excluded == 3


def test_a_fingerprint_is_a_literal_stem_and_never_a_value() -> None:
    assert bootstrap.stem_of("add address=192.0.2.10") == "add"
    assert bootstrap.stem_of("/ip neighbor discovery-settings") == (
        "/ip neighbor discovery-settings"
    )
    assert bootstrap.stem_of("interface GigabitEthernet0/0/1") == "interface"


def test_no_vendor_name_is_proposed_anywhere(client: TestClient) -> None:
    """The principle, checked on the response: the file's structure, never whose."""
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    body = client.get(f"/training/bootstrap/{file_id}", auth=ROOT).json()

    assert "never proposes a vendor or platform name" in body["principle"]
    serialised = str(body).lower()
    for name in ("mikrotik", "routeros", "huawei", "cisco", "juniper", "arista"):
        assert name not in serialised


# ---------------------------------------------------------------------------
# The assessment an administrator sees
# ---------------------------------------------------------------------------


def test_an_unrecognised_file_is_eligible_and_says_what_it_shows(client: TestClient) -> None:
    uploaded = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())
    assert uploaded["detection"]["outcome"] == "no_signature_matched"
    assert uploaded["bootstrap"] == f"/training/bootstrap/{uploaded['file_id']}"

    body = client.get(f"/training/bootstrap/{uploaded['file_id']}", auth=ROOT).json()

    assert body["eligible"] is True
    assert body["syntax"]["derived"] == "indent"
    assert body["comments"]["prefix"] == "#"
    assert body["structure"]["section_path_lines"] == 12
    assert body["structure"]["indented_lines"] == 0
    assert len(body["fingerprints"]["candidates"]) == 8
    assert body["split_check"] == "not an evaluation or held-out corpus file"


def test_the_audit_refusal_names_the_way_forward(client: TestClient) -> None:
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    refused = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)

    assert refused.status_code == 409
    assert f"/training/bootstrap/{file_id}" in refused.json()["detail"]


# ---------------------------------------------------------------------------
# Refusals
# ---------------------------------------------------------------------------


def test_non_admins_cannot_bootstrap_or_discard(client: TestClient) -> None:
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]

    assert client.get(f"/training/bootstrap/{file_id}", auth=ALICE).status_code == 403
    assert _bootstrap(client, file_id).status_code == 201  # as root, for the delete
    body = {"file_id": file_id, "vendor": "x-y", "os_family": "z", "syntax_mode": "indent"}
    assert client.post("/training/bootstrap", json=body, auth=ALICE).status_code == 403
    assert client.post("/training/bootstrap", json=body).status_code == 401
    assert client.delete("/training/bootstrap/mikrotik/routeros", auth=ALICE).status_code == 403


def test_an_existing_platform_cannot_be_bootstrapped_again(client: TestClient) -> None:
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    refused = _bootstrap(client, file_id, vendor="cisco", os_family="ios")

    assert refused.status_code == 409
    assert "cisco/ios already has a pack" in refused.json()["detail"]


def test_a_file_in_the_evaluation_split_is_refused(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Matched by sha256 against the manifest, exactly as the corpus records it."""
    uploaded = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())
    manifest = tmp_path / "MANIFEST.yaml"
    manifest.write_text(
        yaml.safe_dump(
            {"files": [{"path": "x/eval/f.rsc", "split": "eval", "sha256": uploaded["file_id"]}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "corpus_manifest", manifest)

    body = client.get(f"/training/bootstrap/{uploaded['file_id']}", auth=ROOT).json()
    assert body["eligible"] is False
    assert "eval split" in body["reason"]
    assert _bootstrap(client, uploaded["file_id"]).status_code == 409


def test_the_real_manifest_protects_every_evaluation_and_holdout_file() -> None:
    guard = bootstrap.corpus_guard(settings.corpus_manifest)
    manifest = yaml.safe_load(settings.corpus_manifest.read_text(encoding="utf-8"))
    protected = {e["sha256"] for e in manifest["files"] if e["split"] in ("eval", "holdout")}

    assert guard.present
    assert set(guard.protected) == protected
    assert guard.held_out_vendor == manifest["held_out_vendor"]


def test_the_held_out_vendor_cannot_be_named(client: TestClient) -> None:
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    held_out = bootstrap.corpus_guard(settings.corpus_manifest).held_out_vendor
    refused = _bootstrap(client, file_id, vendor=held_out)

    assert refused.status_code == 409
    assert "held-out vendor" in refused.json()["detail"]


@pytest.mark.parametrize(
    ("overrides", "status"),
    [
        ({"vendor": "Bad Name"}, 422),
        ({"fingerprints": ["/ip service"]}, 422),  # one is too few
        ({"fingerprints": ["/ip service", "not a candidate"]}, 422),
        ({"syntax_mode": "xml"}, 422),
    ],
)
def test_a_malformed_request_is_refused(client: TestClient, overrides: dict, status: int) -> None:
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    assert _bootstrap(client, file_id, **overrides).status_code == status


def test_fingerprints_that_would_move_an_identified_file_are_refused(
    client: TestClient, trained: Path
) -> None:
    """Pasted lines are the administrator's own, so the dry run is their guard.

    Two lines from rtr-core-01 make a file IOS does not claim; as the only
    fingerprints they would make rtr-core-01 ambiguous. Refused, nothing written.
    """
    ios = CORPUS / "cisco/dev/rtr-core-01.cfg"
    _upload(client, ios.name, ios.read_bytes())
    borrowed = "service password-encryption\nno ip http server\n"
    file_id = _upload(client, "borrowed.cfg", borrowed.encode())["file_id"]

    refused = _bootstrap(
        client,
        file_id,
        fingerprints=[],
        pasted_lines=["service password-encryption", "no ip http server"],
    )

    assert refused.status_code == 409, refused.text
    assert "rtr-core-01.cfg (cisco/ios -> None)" in refused.json()["detail"]
    assert not trained.exists() or not any(trained.rglob("*.yaml"))


# ---------------------------------------------------------------------------
# After bootstrap: detection, then the unchanged training loop
# ---------------------------------------------------------------------------


def test_after_bootstrap_the_file_detects_against_the_new_pack(
    client: TestClient, trained: Path
) -> None:
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    created = _bootstrap(client, file_id)
    assert created.status_code == 201, created.text
    body = created.json()

    assert body["pack_id"] == "mikrotik/routeros"
    assert body["pack_version"] == "1.0.0"
    assert body["syntax_mode"] == "indent"
    assert body["comment_prefixes"] == ["#"]
    assert body["detection"]["outcome"] == "detected"
    assert body["detection"]["score"] == pytest.approx(1.0, abs=1e-5)
    assert [d["pattern"] for d in body["detect"]] == [
        "^/ip firewall filter$",
        "^/ip service$",
        "^/system ntp client$",
    ]

    written = trained / "mikrotik_routeros" / "1.0.0.yaml"
    assert written.is_file()
    assert ActivationRecord.load(trained).version_for("mikrotik/routeros") == "1.0.0"

    device = _device(client, file_id)
    assert (device["vendor"], device["os_family"]) == ("mikrotik", "routeros")

    # A second upload of the same platform is now detected on arrival.
    again = _upload(client, "copy.rsc", ROUTEROS.read_bytes() + b"# a second copy\n")
    assert again["detection"]["vendor"] == "mikrotik"


def test_after_bootstrap_the_training_loop_runs_unchanged(client: TestClient) -> None:
    """Audit -> queue -> confirm -> compile -> activate -> re-audit, on the new pack."""
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    assert _bootstrap(client, file_id).status_code == 201

    audited = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)
    assert audited.status_code == 201, audited.text
    residue_before = audited.json()["residue_lines"]
    assert residue_before == 35, "every content line is unknown to a pack with no patterns"

    queue = client.get(f"/training/queue?file_id={file_id}", auth=ROOT).json()
    entry = next(e for e in queue["entries"] if e["line"] == "set telnet disabled=yes")

    confirmed = client.post(
        "/training/confirm",
        json={
            "cluster_id": entry["cluster_id"],
            "line": "set telnet disabled=yes",
            "vendor": "mikrotik",
            "os_family": "routeros",
            "outcome": "corrected",
            "field": "telnet_enabled",
        },
        auth=ROOT,
    )
    assert confirmed.status_code == 201, confirmed.text

    compiled = client.post(
        "/training/compile",
        json={
            "example_id": confirmed.json()["example_id"],
            "literal_value": "false",
            "cast": "bool",
        },
        auth=ROOT,
    )
    assert compiled.status_code == 201, compiled.text
    draft = compiled.json()
    assert (draft["pack_id"], draft["pack_version"]) == ("mikrotik/routeros", "1.0.1")

    activated = client.post(
        "/training/activate",
        json={"pack_id": draft["pack_id"], "pack_version": draft["pack_version"]},
        auth=ROOT,
    )
    assert activated.status_code == 200, activated.text
    assert activated.json()["previous_version"] == "1.0.0"

    reaudited = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)
    assert reaudited.status_code == 201, reaudited.text
    assert reaudited.json()["residue_lines"] == residue_before - 1

    findings = client.get(
        f"/compliance/audits/{reaudited.json()['audit_id']}/findings", auth=ALICE
    ).json()["findings"]
    telnet = next(f for f in findings if f["rule_id"] == "NRK-TELNET-001")
    assert telnet["status"] == "pass"
    assert telnet["evidence"][0]["raw_line"].strip() == "set telnet disabled=yes"


# ---------------------------------------------------------------------------
# Discard and start over
# ---------------------------------------------------------------------------


def test_discard_leaves_no_pack_no_record_and_an_undetected_file(
    client: TestClient, trained: Path
) -> None:
    file_id = _upload(client, ROUTEROS.name, ROUTEROS.read_bytes())["file_id"]
    assert _bootstrap(client, file_id).status_code == 201
    audited = client.post(f"/compliance/audits?file_id={file_id}", auth=ALICE)
    assert audited.status_code == 201

    discarded = client.delete("/training/bootstrap/mikrotik/routeros", auth=ROOT)
    assert discarded.status_code == 200, discarded.text
    assert discarded.json()["versions_removed"] == ["1.0.0"]
    assert discarded.json()["files_reset"] == [file_id]

    assert not any(trained.rglob("*.yaml")) or [p.name for p in trained.rglob("*.yaml")] == [
        "activation.yaml"
    ]
    assert not (trained / "mikrotik_routeros").exists()
    assert ActivationRecord.load(trained).version_for("mikrotik/routeros") is None
    assert all(p.pack_id != "mikrotik/routeros" for p in pack_loader.load_active_packs())

    device = _device(client, file_id)
    assert device["vendor"] is None
    assert client.get(f"/training/queue?file_id={file_id}", auth=ROOT).json()["entries"] == []
    assert client.get(f"/training/bootstrap/{file_id}", auth=ROOT).json()["eligible"] is True


def test_discard_refuses_a_shipped_platform(client: TestClient) -> None:
    refused = client.delete("/training/bootstrap/cisco/ios", auth=ROOT)
    assert refused.status_code == 409
    assert client.delete("/training/bootstrap/nobody/here", auth=ROOT).status_code == 404
