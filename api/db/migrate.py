"""Forward-only SQL migrations.

Plain numbered `.sql` files applied in order, each inside one transaction, with
the SHA-256 of the file recorded as applied. No Alembic, no ORM — the approved
stack is SQLite plus the standard library, and this is about sixty lines.

**Forward-only, by design.** An audit log that can be rolled back is not an
audit log. A mistake is corrected by a new forward migration, which is itself
recorded, rather than by rewinding history.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from api.db.connection import immediate_transaction, table_exists

MIGRATIONS_ROOT = Path(__file__).resolve().parent / "migrations"

AUDIT_MIGRATIONS = MIGRATIONS_ROOT / "audit"
"""Schema for nirikshak-audit.db — the hash chain and nothing else."""

OPERATIONAL_MIGRATIONS = MIGRATIONS_ROOT / "operational"
"""Schema for nirikshak.db — ingested files, lines, devices.

Decision D4 keeps these apart so "the audit database contains no configuration
content" is provable by opening the file, rather than resting on payload
discipline. The directory is a required argument everywhere below: a default
that silently meant one of two databases would be a latent bug.
"""
FILENAME_RE = re.compile(r"^(\d{4})_([A-Za-z0-9_\-]+)\.sql$")


class MigrationError(RuntimeError):
    """A migration could not be applied, or the recorded history disagrees."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    sql: str
    checksum: str


def split_statements(script: str) -> list[str]:
    """Split a migration into individual statements.

    `Connection.executescript` cannot be used here: it issues an implicit COMMIT
    before running, which would silently end the enclosing transaction and cost
    migrations their atomicity — verified, not assumed.

    Splitting on `;` is equally wrong, because a trigger body contains
    semicolons of its own. `sqlite3.complete_statement` understands
    `BEGIN … END`, so statements are accumulated until it reports one complete.
    """
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        stripped = line.strip()
        if (not stripped or stripped.startswith("--")) and not buffer.strip():
            continue
        buffer += line
        if sqlite3.complete_statement(buffer):
            if buffer.strip():
                statements.append(buffer.strip())
            buffer = ""
    if buffer.strip():
        raise MigrationError(f"migration ends with an incomplete statement: {buffer[:80]!r}")
    return statements


def discover(directory: Path) -> list[Migration]:
    """Read every migration file, ordered by version."""
    found: list[Migration] = []
    for path in sorted(directory.glob("*.sql")):
        match = FILENAME_RE.match(path.name)
        if not match:
            raise MigrationError(
                f"migration {path.name!r} does not match NNNN_name.sql — ordering "
                "must be unambiguous"
            )
        sql = path.read_text(encoding="utf-8")
        found.append(
            Migration(
                version=int(match.group(1)),
                name=match.group(2),
                path=path,
                sql=sql,
                checksum=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            )
        )

    versions = [m.version for m in found]
    if len(versions) != len(set(versions)):
        raise MigrationError(f"duplicate migration versions: {versions}")
    return found


def applied_migrations(conn: sqlite3.Connection) -> dict[int, tuple[str, str]]:
    """version -> (name, checksum) for everything already applied."""
    if not table_exists(conn, "schema_migrations"):
        return {}
    rows = conn.execute("SELECT version, name, checksum FROM schema_migrations").fetchall()
    return {row["version"]: (row["name"], row["checksum"]) for row in rows}


def verify_applied(conn: sqlite3.Connection, directory: Path) -> None:
    """Confirm no already-applied migration file has been edited since.

    Silent schema drift beneath an integrity mechanism is worse than refusing to
    start: every hash in the chain was computed against assumptions this schema
    encodes, and a quietly altered migration means those assumptions are no
    longer knowable.
    """
    on_disk = {m.version: m for m in discover(directory)}
    for version, (name, checksum) in sorted(applied_migrations(conn).items()):
        migration = on_disk.get(version)
        if migration is None:
            raise MigrationError(
                f"migration {version:04d}_{name} is recorded as applied but its file is missing"
            )
        if migration.checksum != checksum:
            raise MigrationError(
                f"migration {migration.path.name} has changed since it was applied "
                f"(recorded {checksum[:16]}…, on disk {migration.checksum[:16]}…). "
                "Refusing to start on a schema that disagrees with its own history."
            )


def migrate(conn: sqlite3.Connection, directory: Path) -> list[Migration]:
    """Apply every unapplied migration in order. Returns those applied now."""
    verify_applied(conn, directory)

    already = set(applied_migrations(conn))
    pending = [m for m in discover(directory) if m.version not in already]

    applied_now: list[Migration] = []
    for migration in pending:
        try:
            with immediate_transaction(conn):
                for statement in split_statements(migration.sql):
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name, checksum, applied_at) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        migration.version,
                        migration.name,
                        migration.checksum,
                        datetime.now(UTC).isoformat(),
                    ),
                )
        except sqlite3.Error as exc:
            raise MigrationError(f"migration {migration.path.name} failed: {exc}") from exc
        applied_now.append(migration)

    return applied_now


def current_version(conn: sqlite3.Connection) -> int:
    applied = applied_migrations(conn)
    return max(applied) if applied else 0
