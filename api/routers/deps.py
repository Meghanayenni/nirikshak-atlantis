"""Shared route dependencies: the database connection, and who is asking.

Authentication is HTTP Basic over the user store (decision D25). Deliberately
small — the brief was a foundation the eventual UI can rely on, not an identity
platform. Sessions, refresh tokens and password reset are all absent on purpose;
each is a real feature with its own failure modes, and none is needed to make the
API safe to expose.

Three dependencies, and the difference between them is the whole authorisation
model:

    current_user   any authenticated, enabled account
    admin_user     an account whose role is admin
    require_access an ownership check for one specific resource

`WWW-Authenticate` is returned on failure so a browser and an HTTP client behave
predictably, and every failure is the same 401 — an unauthenticated caller learns
nothing about which usernames exist.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from api.config import settings
from api.db import users as user_store
from api.db.connection import connect, table_exists
from api.models.auth import User

basic = HTTPBasic(auto_error=False)

UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="authentication required",
    headers={"WWW-Authenticate": 'Basic realm="nirikshak"'},
)
"""One error for every authentication failure.

Missing header, unknown username, wrong password and disabled account all return
this. Separating them would let an unauthenticated caller enumerate accounts.
"""

FORBIDDEN = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="this resource belongs to another user",
)


def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect(settings.db_path)
    try:
        if not table_exists(conn, "config_file"):
            raise HTTPException(status_code=503, detail="operational store is not initialised")
        yield conn
    finally:
        conn.close()


Conn = Annotated[sqlite3.Connection, Depends(get_conn)]


def current_user(
    conn: Conn,
    credentials: Annotated[HTTPBasicCredentials | None, Depends(basic)] = None,
) -> User:
    """The authenticated caller, or 401.

    No anonymous fallback and no "default user". A route that takes this
    dependency cannot be reached without credentials, which is what makes the
    protection structural rather than a check someone has to remember to write.
    """
    if credentials is None:
        raise UNAUTHENTICATED
    if not table_exists(conn, "app_user"):
        raise HTTPException(status_code=503, detail="identity store is not initialised")

    user = user_store.authenticate(conn, credentials.username, credentials.password)
    if user is None:
        raise UNAUTHENTICATED
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def admin_user(user: CurrentUser) -> User:
    """An admin, or 403.

    403 rather than 401 here: the caller *is* authenticated, and telling them so
    is not a leak — they already know their own credentials worked.
    """
    if not user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this operation requires the admin role",
        )
    return user


AdminUser = Annotated[User, Depends(admin_user)]


def require_access(user: User, *, exists: bool, owner_id: str | None) -> None:
    """Authorise one resource, or raise.

    **A resource the caller may not see is reported as 404, not 403.** Answering
    403 would confirm that the id exists, which lets someone walk the id space
    and learn how many audits another user has run. The one exception is an admin,
    who may see everything, so the distinction cannot leak anything to them.
    """
    if not exists or not user.may_access(owner_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")


def owner_filter(user: User) -> str | None:
    """The owner id a listing should restrict to — `None` meaning unrestricted.

    Exactly one call site decides this, so "admins see the fleet" is one line
    rather than a condition repeated in every listing route.
    """
    return None if user.is_admin else user.user_id
