"""Remediation snippets — the vetted library (DEVELOPER_GUIDE.md Rule 4).

Commands come from here and nowhere else. There is no generation path in this
contract or in the resolver that reads it: a missing snippet yields nothing, not
an improvisation. A hallucinated command pasted into a production device is the
most damaging failure this system could produce, so the safe behaviour is
designed in rather than guarded against.

`vetted_by` is mandatory and non-empty. An unvetted snippet is not a snippet.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import LockoutRisk


class ImpactAssessment(BaseModel):
    """What applying this snippet does to a running device.

    `lockout_risk` drives ordering, not just presentation: disabling an insecure
    management protocol before its replacement is verified would strand the
    operator outside their own device.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    service_affecting: bool = False
    requires_reload: bool = False
    lockout_risk: LockoutRisk = LockoutRisk.NONE
    notes: str | None = None

    @model_validator(mode="after")
    def _check(self) -> ImpactAssessment:
        if self.lockout_risk is LockoutRisk.HIGH and not self.notes:
            raise ValueError(
                "a high lockout risk must explain itself — the operator needs to "
                "know what could strand them before they paste anything"
            )
        return self


class RemediationSnippet(BaseModel):
    """Vetted commands to bring one platform into compliance with one rule."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    snippet_id: str = Constraint(min_length=1)
    rule_id: str = Constraint(min_length=1)

    vendor: str = Constraint(min_length=1)
    os_family: str = Constraint(min_length=1)
    os_version_range: str | None = Constraint(default=None, description="e.g. '>=15.0 <18.0'")

    commands: tuple[str, ...] = Constraint(min_length=1)
    rollback: tuple[str, ...] = ()
    preconditions: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()

    impact: ImpactAssessment = Constraint(default_factory=ImpactAssessment)
    depends_on: tuple[str, ...] = Constraint(
        default=(), description="snippet_ids that must be applied first"
    )
    order_hint: int = Constraint(default=100, ge=0)

    vetted_by: str = Constraint(
        min_length=1, description="Who checked these commands. Rule 4 — never model-generated."
    )
    vetted_at: datetime | None = None
    reference: str | None = Constraint(
        default=None, description="Vendor document these were checked against"
    )

    @model_validator(mode="after")
    def _check(self) -> RemediationSnippet:
        if self.snippet_id in self.depends_on:
            raise ValueError(f"snippet {self.snippet_id!r} depends on itself")

        if any(not c.strip() for c in self.commands):
            raise ValueError(f"snippet {self.snippet_id!r} contains a blank command")

        # A service-affecting change the operator cannot undo is a trap.
        if self.impact.service_affecting and not self.rollback:
            raise ValueError(
                f"snippet {self.snippet_id!r} is service-affecting but has no "
                "rollback block; the operator must be able to get back"
            )
        return self

    @property
    def key(self) -> tuple[str, str, str]:
        """The lookup key: remediation is resolved, never generated."""
        return (self.vendor, self.os_family, self.rule_id)

    @property
    def is_lockout_risk(self) -> bool:
        return self.impact.lockout_risk is LockoutRisk.HIGH
