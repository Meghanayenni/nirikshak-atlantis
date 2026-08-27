"""Identity and authorisation contracts (decision D25).

Two roles, deliberately. The Concept Report promises that *"access to raw files
is role-separated from access to findings"*, and two roles is the smallest thing
that makes that true. A richer permission model is a platform this project does
not need and would have to maintain.

The rule the rest of the system enforces:

    user    sees only resources they own
    admin   sees the fleet, and performs management operations

Ownership is recorded on the things a user creates — an upload, an audit run —
rather than on content-addressed rows, because the same configuration file
uploaded by two people is one file and two ingestions.

**No password material appears in this module.** `User` carries no hash and no
plaintext, so a user object cannot leak a credential into a log line, an API
response or an audit payload. The hash lives in the store and is read only by
`authenticate`.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict
from pydantic import Field as Constraint

from api.models.enums import Role

USERNAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"
"""Lowercase, 3–64 characters. Narrow on purpose: a username appears in audit
records and log lines, and a permissive pattern is how those become injectable."""


class User(BaseModel):
    """An authenticated identity. Deliberately carries no credential material."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: str = Constraint(min_length=1)
    username: str = Constraint(pattern=USERNAME_PATTERN)
    role: Role = Role.USER
    created_at: datetime | None = None
    disabled: bool = False

    @property
    def is_admin(self) -> bool:
        return self.role.is_admin

    def may_access(self, owner_id: str | None) -> bool:
        """Whether this user may see a resource owned by `owner_id`.

        An admin sees everything. A user sees only their own.

        An **unowned** resource (`None`) is admin-only. That is the conservative
        reading and it matters: rows created before ownership existed have no
        owner, and defaulting those to "everyone" would silently expose the
        entire pre-existing corpus of uploads to every account.
        """
        if self.disabled:
            return False
        if self.is_admin:
            return True
        return owner_id is not None and owner_id == self.user_id


class AuthenticatedActor(BaseModel):
    """A user, as the audit chain records them.

    Separate from `Actor` in the audit contract, which is deliberately broader —
    it also describes system and model actors. This is the narrowing that says a
    human did something.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: str = Constraint(min_length=1)
    username: str = Constraint(pattern=USERNAME_PATTERN)
    role: Role
