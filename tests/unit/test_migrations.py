"""Migration runner — forward-only, atomic, checksum-verified."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from api.db.connection import connect, table_exists, trigger_exists
from api.db.migrate import (
    AUDIT_MIGRATIONS,
    MigrationError,
    applied_migrations,
    current_version,
    discover,
    migrate,
    split_statements,
    verify_applied,
)


def test_discovers_the_initial_migration() -> None:
    found = discover(AUDIT_MIGRATIONS)
    assert found, "no migrations discovered"
    assert found[0].version == 1
    assert found[0].name == "initial"
    assert len(found[0].checksum) == 64


def test_statement_splitter_keeps_trigger_bodies_intact() -> None:
    """Splitting on ';' would cut a trigger in half; complete_statement does not."""
    sql = discover(AUDIT_MIGRATIONS)[0].sql
    statements = split_statements(sql)

    triggers = [s for s in statements if s.upper().startswith("CREATE TRIGGER")]
    assert len(triggers) == 2
    for trigger in triggers:
        assert "RAISE(ABORT" in trigger
        assert trigger.rstrip().upper().endswith("END;")


def test_migrate_creates_the_full_schema(tmp_path: Path) -> None:
    conn = connect(tmp_path / "a.db")
    applied = migrate(conn, AUDIT_MIGRATIONS)

    assert [m.version for m in applied] == [1]
    for table in ("schema_migrations", "audit_log", "audit_chain_head"):
        assert table_exists(conn, table), f"missing table {table}"
    for trigger in ("audit_log_no_update", "audit_log_no_delete"):
        assert trigger_exists(conn, trigger), f"missing trigger {trigger}"
    assert current_version(conn) == 1


def test_migrate_is_idempotent(tmp_path: Path) -> None:
    conn = connect(tmp_path / "a.db")
    migrate(conn, AUDIT_MIGRATIONS)
    assert migrate(conn, AUDIT_MIGRATIONS) == [], "re-running applied a migration twice"
    assert len(applied_migrations(conn)) == 1


def test_edited_applied_migration_refuses_to_proceed(tmp_path: Path) -> None:
    """Silent schema drift beneath an integrity mechanism is worse than downtime."""
    conn = connect(tmp_path / "a.db")
    migrate(conn, AUDIT_MIGRATIONS)

    conn.execute("UPDATE schema_migrations SET checksum = ? WHERE version = 1", ("f" * 64,))

    with pytest.raises(MigrationError, match="has changed since it was applied"):
        verify_applied(conn, AUDIT_MIGRATIONS)
    with pytest.raises(MigrationError, match="has changed since it was applied"):
        migrate(conn, AUDIT_MIGRATIONS)


def test_missing_migration_file_is_reported(tmp_path: Path) -> None:
    conn = connect(tmp_path / "a.db")
    migrate(conn, AUDIT_MIGRATIONS)
    conn.execute(
        "INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?,?,?,?)",
        (99, "ghost", "a" * 64, "2026-01-01T00:00:00Z"),
    )
    with pytest.raises(MigrationError, match="file is missing"):
        verify_applied(conn, AUDIT_MIGRATIONS)


def test_failed_migration_rolls_back_whole(tmp_path: Path) -> None:
    """Atomicity — a broken migration must leave no partial schema behind.

    This is what `executescript` would have cost us: it issues an implicit
    COMMIT before running, so a later failure would leave earlier statements
    permanently applied.
    """
    directory = tmp_path / "migrations"
    directory.mkdir()
    (directory / "0001_partial.sql").write_text(
        "CREATE TABLE good (x INTEGER);\nCREATE TABLE bad (;\n", encoding="utf-8"
    )

    conn = connect(tmp_path / "b.db")
    conn.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
        "checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )

    with pytest.raises(MigrationError):
        migrate(conn, directory)

    assert not table_exists(conn, "good"), "partial schema survived a failed migration"
    assert applied_migrations(conn) == {}


def test_badly_named_migration_is_rejected(tmp_path: Path) -> None:
    directory = tmp_path / "migrations"
    directory.mkdir()
    (directory / "initial.sql").write_text("CREATE TABLE t (x INTEGER);", encoding="utf-8")

    with pytest.raises(MigrationError, match="does not match"):
        discover(directory)


def test_migrations_are_applied_in_version_order(tmp_path: Path) -> None:
    directory = tmp_path / "migrations"
    directory.mkdir()
    (directory / "0002_second.sql").write_text("CREATE TABLE b (x INTEGER);", encoding="utf-8")
    (directory / "0001_first.sql").write_text("CREATE TABLE a (x INTEGER);", encoding="utf-8")

    conn = connect(tmp_path / "c.db")
    conn.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
        "checksum TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    applied = migrate(conn, directory)
    assert [m.version for m in applied] == [1, 2]


def test_wal_and_durability_pragmas_are_set(tmp_path: Path) -> None:
    conn = connect(tmp_path / "a.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    # synchronous FULL == 2
    assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2


def test_connection_uses_manual_transactions(tmp_path: Path) -> None:
    """isolation_level=None, so the append path can issue BEGIN IMMEDIATE itself."""
    conn = connect(tmp_path / "a.db")
    assert conn.isolation_level is None
    assert isinstance(conn, sqlite3.Connection)
