"""Can an administrator teach the system a mapping it never asked about?

The confirmation loop was built around residue: a line the parser did not
recognise reaches the queue, a person decides what it means, and the mapping is
compiled. This asks the question the interface needs answered before it offers a
"create" button — whether that loop also works when the *administrator* is the
one who raises the line, for syntax no uploaded file has produced yet.

Three properties, and the interface may only offer create/edit/delete if all
three hold:

  1. **Create without residue.** `POST /training/confirm` accepts a line the
     queue never held. The queue is where lines usually come from, not a gate on
     where they may come from.
  2. **Immediate effect.** Activation clears the pack cache, so the next parse in
     the same process uses the new pattern. No restart, no redeployment - which
     is the Concept Report's claim, tested here against an admin-authored
     mapping rather than a residue-derived one.
  3. **Reversible the same way.** Editing is withdraw-then-recompile, and both
     halves take effect in the same process.

If any of these were false the interface would have to send the administrator
somewhere else, or tell them to restart the service, and a screen that offered
an edit which silently did not apply until a restart would be worse than one
that offered nothing.
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

ALICE = ("alice", "correct-horse-battery")
ROOT = ("root", "admin-long-password-1")

CISCO = Path("corpus/cisco/dev/sw-access-02.cfg")

# Syntax no corpus file contains and no queue has ever produced. The point of
# the test is that it arrives from the administrator, not from a parse.
AUTHORED_LINE = "service tcp-keepalives-in 900"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(settings, "db_path", tmp_path / "nirikshak.db")
    monkeypatch.setattr(settings, "audit_db_path", tmp_path / "nirikshak-audit.db")
    monkeypatch.setattr(settings, "blob_root", tmp_path / "uploads")

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


def _active(client: TestClient, pack_id: str) -> dict:
    packs = client.get("/training/packs", auth=ROOT).json()["packs"]
    return next(p for p in packs if p["pack_id"] == pack_id and p["is_active"])


def _author(client: TestClient, line: str = AUTHORED_LINE, *, value_token: int = 2) -> dict:
    """Confirm, compile and activate a mapping the administrator raised."""
    confirmed = client.post(
        "/training/confirm",
        json={
            # A cluster id the queue never issued. Nothing looks it up; it is the
            # administrator's own label for what they are describing.
            "cluster_id": "authored-by-admin",
            "line": line,
            "vendor": "cisco",
            "os_family": "ios",
            "outcome": "corrected",
            "field": "idle_timeout_seconds",
        },
        auth=ROOT,
    )
    assert confirmed.status_code == 201, confirmed.text

    draft = client.post(
        "/training/compile",
        json={
            "example_id": confirmed.json()["example_id"],
            "value_token": value_token,
            "cast": "int",
        },
        auth=ROOT,
    )
    assert draft.status_code == 201, draft.text

    activated = client.post(
        "/training/activate",
        json={
            "pack_id": draft.json()["pack_id"],
            "pack_version": draft.json()["pack_version"],
        },
        auth=ROOT,
    )
    assert activated.status_code == 200, activated.text
    return {**draft.json(), "example_id": confirmed.json()["example_id"]}


def test_a_mapping_can_be_created_for_a_line_the_queue_never_held(client: TestClient) -> None:
    """Property 1 - the queue is a source of lines, not a gate on them.

    An administrator who knows a platform will meet syntax before a device does.
    Requiring an upload first would mean the system can only learn what it has
    already failed on.
    """
    before = _active(client, "cisco/ios")

    queue = client.get("/training/queue", auth=ROOT).json()
    assert all(entry["line"] != AUTHORED_LINE for entry in queue["entries"]), (
        "this line must not be in the queue, or the test proves nothing"
    )

    authored = _author(client)

    after = _active(client, "cisco/ios")
    assert after["pack_version"] != before["pack_version"]
    assert after["pattern_count"] == before["pattern_count"] + 1

    added = next(p for p in after["patterns"] if p["id"] == authored["pattern_id"])
    assert added["source"] == "admin_trained"
    assert added["withdrawable"] is True
    assert AUTHORED_LINE in added["examples"], "the pattern must retain the confirmed line"


def test_the_new_mapping_reads_a_configuration_in_the_same_process(client: TestClient) -> None:
    """Property 2 - no restart, no redeployment.

    Asserted against a real upload rather than against the pack file, because
    what matters is not that a YAML changed but that the very next audit reads a
    configuration differently than the previous one did.
    """
    # A real corpus file, so vendor detection has enough to work with, plus the
    # authored line appended. A two-line synthetic file is not identified as any
    # platform and the audit correctly refuses it — which is a different, already
    # tested behaviour and not what this test is about.
    body = CISCO.read_bytes() + b"\n" + AUTHORED_LINE.encode() + b"\n"

    before = client.post(
        "/ingest/upload", files={"files": ("before.cfg", body)}, auth=ALICE
    )
    assert before.status_code == 200, before.text
    before_id = before.json()["accepted"][0]["file_id"]

    first_run = client.post(f"/compliance/audits?file_id={before_id}", auth=ALICE)
    assert first_run.status_code == 201, first_run.text
    residue_before = first_run.json()["residue_lines"]

    # The line is unread, so it is residue: the parser has no pattern for it.
    assert residue_before > 0

    _author(client)

    # Same process, no restart. Re-auditing the same bytes must now read one more
    # line than it did a moment ago.
    second_run = client.post(f"/compliance/audits?file_id={before_id}", auth=ALICE)
    assert second_run.status_code == 201, second_run.text
    residue_after = second_run.json()["residue_lines"]

    assert residue_after == residue_before - 1, (
        f"the authored pattern did not take effect in this process: "
        f"{residue_before} unread lines before, {residue_after} after"
    )

    active = _active(client, "cisco/ios")
    assert any(AUTHORED_LINE in p["examples"] for p in active["patterns"])


def test_editing_is_withdraw_then_recompile_and_both_take_effect(client: TestClient) -> None:
    """Property 3 - an edit is two audited halves, not an in-place rewrite.

    A pattern is never mutated where it stands. The old version keeps the old
    mapping, the new version carries the corrected one, and the administrator's
    original decision survives both - so "what did this system believe in March"
    stays answerable after the belief changes.
    """
    first = _author(client, value_token=2)
    original_pattern_id = first["pattern_id"]
    original_regex = first["pattern"]

    withdrawn = client.post(
        "/training/withdraw",
        json={
            "pack_id": first["pack_id"],
            "pattern_id": original_pattern_id,
            "reason": "captured the wrong token",
        },
        auth=ROOT,
    )
    assert withdrawn.status_code == 200, withdrawn.text

    gone = _active(client, "cisco/ios")
    assert all(p["id"] != original_pattern_id for p in gone["patterns"])

    # Recompile the SAME recorded decision with a different capture. The example
    # is still there to compile from, which is why withdrawal must not delete it.
    recompiled = client.post(
        "/training/compile",
        json={"example_id": first["example_id"], "value_token": 1, "cast": "str"},
        auth=ROOT,
    )
    assert recompiled.status_code == 201, recompiled.text
    assert recompiled.json()["pattern"] != original_regex

    reactivated = client.post(
        "/training/activate",
        json={
            "pack_id": recompiled.json()["pack_id"],
            "pack_version": recompiled.json()["pack_version"],
        },
        auth=ROOT,
    )
    assert reactivated.status_code == 200, reactivated.text

    live = _active(client, "cisco/ios")
    edited = next(p for p in live["patterns"] if p["id"] == recompiled.json()["pattern_id"])
    assert edited["pattern"] == recompiled.json()["pattern"]
    assert edited["pattern"] != original_regex

    # Every version is still on disk, so the history of what was believed when
    # remains readable.
    everything = client.get("/training/packs", auth=ROOT).json()["packs"]
    versions = [p["pack_version"] for p in everything if p["pack_id"] == "cisco/ios"]
    assert len(versions) == len(set(versions))
    assert len(versions) >= 4, f"expected the full lineage on disk, got {versions}"


def test_an_unreadable_pattern_is_refused_before_it_can_be_activated(client: TestClient) -> None:
    """The edit path does not become a hole in §4.

    `pattern_override` lets an administrator correct a generated regex, and the
    compiler re-validates it rather than trusting it. `.*` is refused by name:
    a pattern that matches anything is not a pattern, and one an administrator
    cannot read is one they cannot verify.
    """
    confirmed = client.post(
        "/training/confirm",
        json={
            "cluster_id": "authored-by-admin",
            "line": AUTHORED_LINE,
            "vendor": "cisco",
            "os_family": "ios",
            "outcome": "corrected",
            "field": "idle_timeout_seconds",
        },
        auth=ROOT,
    ).json()

    refused = client.post(
        "/training/compile",
        json={
            "example_id": confirmed["example_id"],
            "value_token": 2,
            "cast": "int",
            "pattern_override": "^service .*$",
        },
        auth=ROOT,
    )
    assert refused.status_code == 422, refused.text
    assert "matches anything" in refused.json()["detail"]
