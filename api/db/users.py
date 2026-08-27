"""User storage and authentication (decision D25).

Lives in `api/db/` rather than inside a feature package on purpose. The
compliance engine's import whitelist admits only `api.models` and `api.audit`,
and that whitelist is the strongest statement of the Rule 1 boundary in the
codebase — so persistence lives outside every layer that whitelist protects, and
routers wire the two together.

**Nothing here returns a password hash.** `authenticate` reads one, compares it
and discards it; every other function returns a `User`, which by contract has no
credential field at all. That is what keeps a hash out of a log line, an API
response or an audit payload.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime

from api.models.auth import User
from api.models.enums import Role
from api.security.passwords import hash_password, verify_password


class UserExistsError(ValueError):
    """That username is taken."""


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password: str,
    *,
    role: Role = Role.USER,
) -> User:
    """Create an account. The plaintext is hashed here and never stored.

    `User` is constructed before the insert so its username pattern is enforced
    by the contract rather than by the database alone — a rejected username never
    reaches SQL.
    """
    user = User(
        user_id=uuid.uuid4().hex,
        username=username,
        role=role,
        created_at=datetime.now(UTC),
    )
    digest = hash_password(password)

    try:
        conn.execute(
            """
            INSERT INTO app_user (user_id, username, password_hash, role, disabled, created_at)
            VALUES (?, ?, ?, ?, 0, ?)
            """,
            (user.user_id, user.username, digest, user.role.value, user.created_at.isoformat()),
        )
    except sqlite3.IntegrityError as exc:
        raise UserExistsError(f"username {username!r} is already taken") from exc

    conn.commit()
    return user


def authenticate(conn: sqlite3.Connection, username: str, password: str) -> User | None:
    """Return the user when the password matches, `None` otherwise.

    One `None` for every failure — unknown username, wrong password, disabled
    account. Distinguishing them would tell an unauthenticated caller which
    usernames exist.

    A missing user still costs a hash computation, so the response time does not
    reveal whether the account exists.
    """
    row = conn.execute(
        "SELECT user_id, username, password_hash, role, disabled, created_at "
        "FROM app_user WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None:
        # Compare against a throwaway hash so a missing account and a wrong
        # password take comparable time.
        verify_password(password, _DUMMY_HASH)
        return None

    if not verify_password(password, row["password_hash"]):
        return None
    if row["disabled"]:
        return None

    return _to_user(row)


def get_user(conn: sqlite3.Connection, user_id: str) -> User | None:
    row = conn.execute(
        "SELECT user_id, username, role, disabled, created_at FROM app_user WHERE user_id = ?",
        (user_id,),
    ).fetchone()
    return _to_user(row) if row else None


def list_users(conn: sqlite3.Connection) -> list[User]:
    """Every account. An admin-only view — the router enforces that, not this."""
    rows = conn.execute(
        "SELECT user_id, username, role, disabled, created_at FROM app_user ORDER BY username"
    ).fetchall()
    return [_to_user(row) for row in rows]


def set_disabled(conn: sqlite3.Connection, user_id: str, disabled: bool) -> None:
    conn.execute(
        "UPDATE app_user SET disabled = ? WHERE user_id = ?", (1 if disabled else 0, user_id)
    )
    conn.commit()


def user_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM app_user").fetchone()[0])


def _to_user(row: sqlite3.Row) -> User:
    return User(
        user_id=row["user_id"],
        username=row["username"],
        role=Role(row["role"]),
        disabled=bool(row["disabled"]),
        created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
    )


_DUMMY_HASH = hash_password("x" * 16)
"""A real hash of a value nobody knows, used only to equalise timing.

Computed once at import so the cost is paid at startup rather than on every
failed login, which would otherwise be a denial-of-service lever.
"""
