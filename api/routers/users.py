"""Account management — admin-only, and minimal (decision D25).

There is **no public registration**. Accounts are created by an admin, which
suits a tool deployed inside one operator's network and removes an entire class
of abuse from an unauthenticated surface.

The first admin is created out-of-band by `scripts/create_admin.py`, so there is
no bootstrap endpoint that has to be remembered and disabled — a step that gets
forgotten is a step that becomes a backdoor.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict
from pydantic import Field as Constraint

from api.db import users as user_store
from api.models.auth import USERNAME_PATTERN
from api.models.enums import Role
from api.routers.deps import AdminUser, Conn, CurrentUser
from api.security.passwords import MIN_PASSWORD_LENGTH, PasswordError

router = APIRouter(prefix="/users", tags=["users"])


class CreateUserRequest(BaseModel):
    """Deliberately not a `User`: that contract carries no password, on purpose."""

    model_config = ConfigDict(extra="forbid")

    username: str = Constraint(pattern=USERNAME_PATTERN)
    password: str = Constraint(min_length=MIN_PASSWORD_LENGTH)
    role: Role = Role.USER


def _public(user: Any) -> dict[str, Any]:
    """What an account looks like over the wire.

    Built field by field rather than dumping the model, so a credential could not
    be added to `User` later and start appearing in responses by accident.
    """
    return {
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role.value,
        "disabled": user.disabled,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


@router.get("/me")
def whoami(user: CurrentUser) -> dict[str, Any]:
    """Who the caller is. The one route any authenticated user may reach."""
    return _public(user)


@router.post("", status_code=201)
def create(conn: Conn, admin: AdminUser, request: CreateUserRequest) -> dict[str, Any]:
    try:
        created = user_store.create_user(
            conn, request.username, request.password, role=request.role
        )
    except user_store.UserExistsError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except PasswordError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    return _public(created)


@router.get("")
def list_all(conn: Conn, admin: AdminUser) -> dict[str, Any]:
    users = user_store.list_users(conn)
    return {"count": len(users), "users": [_public(u) for u in users]}


@router.post("/{user_id}/disable")
def disable(conn: Conn, admin: AdminUser, user_id: str) -> dict[str, Any]:
    """Disable an account. An admin may not disable themselves.

    Not paternalism: an operator who locks out the only admin has no way back in
    without direct database access, and the failure arrives at the worst moment.
    """
    if user_id == admin.user_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="an admin cannot disable their own account",
        )
    if user_store.get_user(conn, user_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")

    user_store.set_disabled(conn, user_id, True)
    return {"user_id": user_id, "disabled": True}
