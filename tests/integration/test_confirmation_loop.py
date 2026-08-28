"""The confirmation loop, end to end, on a real corpus file (P11).

This is the acceptance test for the phase, and it runs the deterministic path in
full:

    Arista dev configuration
      -> residue
      -> queue / cluster
      -> a human TrainingExample
      -> compile
      -> DRAFT
      -> validation / self_check
      -> explicit admin activation
      -> trained pack loaded
      -> re-parse the same configuration
      -> residue strictly decreases
      -> the new field carries ADMIN_TRAINED provenance and ADMIN_CONFIRMED method
      -> the audit chain verifies

Arista is the right subject: its pack is detection-and-identity only, so every
configuration line is residue and there is something real to shrink. It is also
a development-split file, so nothing here reads an evaluation or held-out one.

**The PAN-OS holdout is not opened.** It has no active pack and no XML parser, so
it cannot enter this path at all; no test below names, reads or hashes it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from api.audit.chain import AuditChain
from api.audit.verify import verify_chain
from api.db.migrate import AUDIT_MIGRATIONS, OPERATIONAL_MIGRATIONS, migrate
from api.ingest.packs import PACKS_ROOT, load_pack
from api.learn.embedding import ModelAvailability
from api.learn.index import build_index
from api.models.enums import (
    CastType,
    ConfidenceMethod,
    FieldState,
    PatternSource,
    TrainingOutcome,
)
from api.normalise.service import build_csm
from api.parse.service import parse_configuration
from api.train import service
from api.train.compile import CompileRequest
from api.train.queue import SuggestionState, build_queue

REPO_ROOT = Path(__file__).resolve().parents[2]
ARISTA_DEV = REPO_ROOT / "corpus" / "arista" / "dev" / "sw-leaf-01.cfg"
FILE_ID = "a" * 64

CONFIRMED_LINE = "logging host 192.0.2.10"
"""The line an administrator confirms.

Present in `corpus/arista/dev/sw-leaf-01.cfg`, which is a DEVELOPMENT file — the
same standard every seed example is held to. The Arista pack declares no parsing
pattern, so this line is genuinely unknown before the confirmation and genuinely
read after it.
"""


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    path = tmp_path / "operational.db"
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    migrate(connection, OPERATIONAL_MIGRATIONS)
    connection.execute(
        "INSERT INTO config_file (file_id, size_bytes, line_count, encoding, file_format, "
        "blob_path, detected_vendor, detected_os_family, detection_score, detection_reason, "
        "first_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            FILE_ID,
            1,
            1,
            "utf-8",
            "cli",
            "sw-leaf-01.cfg",
            "arista",
            "eos",
            0.9,
            "detected",
            "2026-08-28T00:00:00+00:00",
        ),
    )
    connection.commit()
    return connection


@pytest.fixture()
def chain(tmp_path: Path) -> AuditChain:
    connection = sqlite3.connect(tmp_path / "audit.db")
    connection.row_factory = sqlite3.Row
    migrate(connection, AUDIT_MIGRATIONS)
    return AuditChain(connection)


def _parse(pack, text: str):
    return parse_configuration(text, pack, file_id=FILE_ID, file_path="sw-leaf-01.cfg")


def _arista_pack():
    return load_pack(PACKS_ROOT / "arista_eos" / "1.0.1.yaml")


# ---------------------------------------------------------------------------
# The round trip
# ---------------------------------------------------------------------------


def test_the_full_confirmation_loop_shrinks_the_queue_and_reads_the_field(
    conn: sqlite3.Connection, chain: AuditChain, tmp_path: Path, monkeypatch
) -> None:
    """One confirmation, one activation, one line that stops being unknown."""
    trained_root = tmp_path / "trained"
    monkeypatch.setattr(service, "TRAINED_ROOT", trained_root)

    text = ARISTA_DEV.read_text(encoding="utf-8")
    pack = _arista_pack()

    # --- before: the line is residue -------------------------------------
    before = build_csm(_parse(pack, text), pack, device_id=FILE_ID)
    residue_before = before.residue_count

    assert residue_before > 0, "the Arista pack parses nothing, so there must be residue"
    assert CONFIRMED_LINE in [line.raw_line_scrubbed for line in before.residue]
    assert before.get("logging_hosts") is None or (
        before.get("logging_hosts").state is not FieldState.PRESENT
    )

    service.record_residue(conn, before.residue, file_id=FILE_ID, vendor="arista", os_family="eos")
    conn.commit()

    # --- the queue offers it as one decision ------------------------------
    queue = service.training_queue(conn, file_id=FILE_ID)
    entry = next(e for e in queue.entries if e.exemplar_text == CONFIRMED_LINE)
    assert entry.cluster.is_confirmable

    # --- a human decides ---------------------------------------------------
    decision = service.Decision(
        cluster_id=entry.cluster_id,
        line=CONFIRMED_LINE,
        vendor="arista",
        os_family="eos",
        outcome=TrainingOutcome.CORRECTED,
        field="logging_hosts",
        value_semantics="token 2 is the syslog host",
        suggestions_shown=entry.outcome.suggestions,
    )
    example = service.confirm(conn, decision, confirmed_by="alice", chain=chain)
    conn.commit()

    assert example.confirmed_by == "alice"
    assert example.audit_seq is not None

    # --- compile to a DRAFT, which changes nothing yet ---------------------
    draft = service.compile_confirmation(
        conn,
        example,
        CompileRequest(value_token=2, cast=CastType.LIST),
        chain=chain,
        actor_id="alice",
        trained_root=trained_root,
    )

    assert draft.pack.pack_version == "1.0.2"
    assert draft.regex == r"^logging\s+host\s+(\S+)$"
    assert not draft.edited

    still_unknown = build_csm(_parse(_arista_pack(), text), _arista_pack(), device_id=FILE_ID)
    assert still_unknown.residue_count == residue_before, (
        "a DRAFT must change nothing; only activation does"
    )

    # --- explicit admin activation ----------------------------------------
    result = service.activate_draft(
        draft.pack, activated_by="alice", chain=chain, trained_root=trained_root
    )
    assert result.version == "1.0.2"
    assert result.previous_version == "1.0.1"

    # --- the trained pack is loaded and re-parses the same file ------------
    trained = load_pack(Path(result.path))
    after = build_csm(_parse(trained, text), trained, device_id=FILE_ID)

    # 1. residue strictly decreases
    assert after.residue_count < residue_before

    # 2. the field is now read, with evidence
    field = after.get("logging_hosts")
    assert field is not None
    assert field.state is FieldState.PRESENT
    assert field.value == ["192.0.2.10"]
    assert field.evidence, "Rule 2 — no evidence, no claim"
    assert field.evidence[0].raw_line.strip() == CONFIRMED_LINE

    # 3. provenance says a human taught it (DEF-10 / D48)
    assert field.provenance is not None
    assert field.provenance.source is PatternSource.ADMIN_TRAINED
    assert field.provenance.pack_version == "1.0.2"
    assert field.confidence_method is ConfidenceMethod.ADMIN_CONFIRMED
    assert field.confidence == 1.0

    # 4. the audit chain still verifies
    report = verify_chain(chain._conn)
    assert report.ok, report.failures

    actions = [r.record.action.value for r in _records(chain)]
    assert "admin_corrected" in actions
    assert "pack_created" in actions
    assert "pack_activated" in actions


def _records(chain: AuditChain):
    from api.audit import store

    return store.read_range(chain._conn)


def test_a_builtin_field_still_reports_as_builtin(tmp_path: Path) -> None:
    """DEF-10's regression guard: the two provenances stay distinguishable.

    The fix must not have made everything look admin-trained. A Cisco field read
    by a hand-written pattern is still `BUILTIN` / `DETERMINISTIC`, and that is
    what an operator needs in order to tell a shipped mapping from a learned one.
    """
    cisco = load_pack(PACKS_ROOT / "cisco_ios" / "1.1.0.yaml")
    text = (REPO_ROOT / "corpus" / "cisco" / "dev" / "rtr-core-01.cfg").read_text(encoding="utf-8")

    csm = build_csm(
        parse_configuration(text, cisco, file_id="c" * 64, file_path="rtr-core-01.cfg"),
        cisco,
        device_id="c" * 64,
    )

    present = [f for f in csm.fields.values() if f.state is FieldState.PRESENT]
    assert present, "the Cisco pack reads fields; this test is meaningless otherwise"
    for field in present:
        assert field.provenance is not None
        assert field.provenance.source is PatternSource.BUILTIN
        assert field.confidence_method is ConfidenceMethod.DETERMINISTIC


def test_the_confirmed_example_enters_the_similarity_index(
    conn: sqlite3.Connection, chain: AuditChain
) -> None:
    """The Concept Report's "simultaneously added to the similarity index".

    This is also how SOURCING_BACKLOG gap 7 closes — through use, one confirmation
    at a time, rather than through a labelling exercise.
    """
    seed_only = build_index([_arista_pack()])
    assert seed_only.is_empty  # the Arista pack declares no patterns

    decision = service.Decision(
        cluster_id="cl-test",
        line=CONFIRMED_LINE,
        vendor="arista",
        os_family="eos",
        outcome=TrainingOutcome.CORRECTED,
        field="logging_hosts",
    )
    service.confirm(conn, decision, confirmed_by="alice", chain=chain)
    conn.commit()

    grown = service.current_index(conn)
    assert CONFIRMED_LINE in grown.texts()
    assert "logging_hosts" in grown.fields


def test_a_rejection_teaches_the_index_nothing(conn: sqlite3.Connection, chain: AuditChain) -> None:
    """ "Not security relevant" is a decision worth keeping and not a label.

    Indexing it would let the layer propose a field for a line a human explicitly
    said had none.
    """
    decision = service.Decision(
        cluster_id="cl-reject",
        line="transceiver qsfp default-mode 4x10G",
        vendor="arista",
        os_family="eos",
        outcome=TrainingOutcome.REJECTED_NOT_SECURITY_RELEVANT,
        field=None,
    )
    service.confirm(conn, decision, confirmed_by="alice", chain=chain)
    conn.commit()

    assert "transceiver qsfp default-mode 4x10G" not in service.current_index(conn).texts()


# ---------------------------------------------------------------------------
# D50 — the model-absent acceptance test
# ---------------------------------------------------------------------------


def test_the_queue_works_with_no_model_and_says_so(conn: sqlite3.Connection) -> None:
    """The state this repository actually runs in (ADR 0018).

    The `[ai]` extra is deliberately uninstalled, so no suggestion can be
    produced. The queue must still be useful — clusters, frequencies, file
    breadth — and must say why there are no suggestions rather than returning an
    empty list, which would read as "the model looked and found nothing".
    """
    pack = _arista_pack()
    text = ARISTA_DEV.read_text(encoding="utf-8")
    csm = build_csm(_parse(pack, text), pack, device_id=FILE_ID)
    service.record_residue(conn, csm.residue, file_id=FILE_ID, vendor="arista", os_family="eos")
    conn.commit()

    absent = ModelAvailability(package_installed=False, weights_present=False, airgap=False)
    queue = build_queue(tuple(csm.residue), build_index([pack]), model_state=absent)

    assert queue.size > 0, "the queue must still be useful without a model"

    confirmable = queue.confirmable
    assert confirmable, "clusters are still offered for confirmation"

    for entry in confirmable:
        assert entry.outcome.state is SuggestionState.MODEL_UNAVAILABLE
        assert entry.outcome.suggestions == ()
        # The whole point: a reason, never a bare empty list.
        assert entry.outcome.reason
        assert "unavailable" in entry.outcome.reason.lower()

    assert "no suggestions" in queue.describe()


def test_clusters_are_ranked_by_frequency_then_file_breadth(conn: sqlite3.Connection) -> None:
    """One shape across thirty devices is one decision worth thirty."""
    pack = _arista_pack()
    text = ARISTA_DEV.read_text(encoding="utf-8")
    csm = build_csm(_parse(pack, text), pack, device_id=FILE_ID)

    queue = build_queue(
        tuple(csm.residue),
        build_index([pack]),
        model_state=ModelAvailability(package_installed=False, weights_present=False, airgap=False),
    )
    sizes = [e.cluster.size for e in queue.entries]
    assert sizes == sorted(sizes, reverse=True)


def test_the_queue_never_fabricates_a_score(conn: sqlite3.Connection) -> None:
    """No stand-in embedding, no hash trick, no placeholder number (ADR 0018).

    A silently degraded suggestion is worse than no suggestion, because the
    confirmation it produces enters a vendor pack permanently.
    """
    pack = _arista_pack()
    csm = build_csm(_parse(pack, ARISTA_DEV.read_text(encoding="utf-8")), pack, device_id=FILE_ID)
    queue = build_queue(
        tuple(csm.residue),
        build_index([pack]),
        model_state=ModelAvailability(package_installed=False, weights_present=False, airgap=False),
    )
    for entry in queue.entries:
        assert entry.outcome.suggestions == ()


# ---------------------------------------------------------------------------
# The queue is persisted and durable (D49)
# ---------------------------------------------------------------------------


def test_the_queue_survives_the_process_and_shrinks_on_re_record(
    conn: sqlite3.Connection,
) -> None:
    """Durable ids, and no stale entry left behind after a pack improves.

    Without clearing, a line the new pack now reads would linger in the queue
    forever — the re-parse simply would not mention it — and the loop would look
    ineffective while it was working.
    """
    from api.db import training as store

    pack = _arista_pack()
    text = ARISTA_DEV.read_text(encoding="utf-8")
    csm = build_csm(_parse(pack, text), pack, device_id=FILE_ID)

    service.record_residue(conn, csm.residue, file_id=FILE_ID, vendor="arista", os_family="eos")
    conn.commit()
    first = store.queue_size(conn, file_id=FILE_ID)
    assert first == csm.residue_count

    reread = store.unknown_lines(conn, file_id=FILE_ID)
    assert len(reread) == first
    assert all(line.file_id == FILE_ID for line in reread)

    # Re-recording a smaller residue replaces rather than accumulates.
    service.record_residue(conn, csm.residue[:2], file_id=FILE_ID, vendor="arista")
    conn.commit()
    assert store.queue_size(conn, file_id=FILE_ID) == 2


def test_only_scrubbed_text_is_persisted(conn: sqlite3.Connection) -> None:
    """Rule 6 / D12 — what is stored is what may reach a model and a person."""
    pack = _arista_pack()
    csm = build_csm(_parse(pack, ARISTA_DEV.read_text(encoding="utf-8")), pack, device_id=FILE_ID)
    service.record_residue(conn, csm.residue, file_id=FILE_ID, vendor="arista")
    conn.commit()

    stored = {row["text_scrubbed"] for row in conn.execute("SELECT * FROM unknown_line")}
    expected = {line.raw_line_scrubbed for line in csm.residue}
    assert stored == expected
