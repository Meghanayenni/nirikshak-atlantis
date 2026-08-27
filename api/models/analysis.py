"""Contracts for structural analysis — decision D22.

An ACL observation is **not a compliance verdict**, and this module exists so it
cannot be mistaken for one. The two live on separate rails:

    CSM.fields  ──►  ComplianceRule  ──►  Finding          (P6, a verdict)
    CSM.acls    ──►  AclAnalysis     ──►  AclObservation   (P7, a fact)

`CheckSpec` reads `CSM.fields[name]` and has no path to `CSM.acls`, so widening
`Finding` to carry an ACL result would have meant widening the one object the
whole Rule 1 argument rests on. A shadowed entry is a fact about a list's own
internal logic; whether that breaches a control is a separate question that needs
a control to breach, and none has been sourced.

Both rails are deterministic. Neither admits model output.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import AclObservationKind, Severity, UnresolvedReason
from api.models.evidence import Evidence


class AclObservation(BaseModel):
    """One conclusion about one access-list entry.

    Carries the citation of the entry it is about **and** of every entry that
    caused the conclusion. "Line 40 can never fire" is not actionable on its own;
    "line 40 can never fire, because of line 20" is.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: AclObservationKind
    acl_id: str = Constraint(min_length=1)
    entry_seq: int = Constraint(ge=0)

    severity: Severity = Severity.INFO
    detail: str = Constraint(min_length=1, description="Our own words, never vendor prose")

    evidence: tuple[Evidence, ...] = Constraint(
        default=(), description="The entry's own source line"
    )
    caused_by: tuple[int, ...] = Constraint(
        default=(), description="Sequence numbers of the entries responsible"
    )
    caused_by_evidence: tuple[Evidence, ...] = Constraint(
        default=(), description="Source lines of those entries"
    )

    unresolved_reason: UnresolvedReason | None = None

    @model_validator(mode="after")
    def _check(self) -> AclObservation:
        if self.kind is AclObservationKind.UNDETERMINED:
            if self.unresolved_reason is None:
                raise ValueError(
                    "an UNDETERMINED observation must record why it could not be "
                    "analysed; silent uncertainty is indistinguishable from an "
                    "oversight (Rule 3)"
                )
        elif self.unresolved_reason is not None:
            raise ValueError(f"a {self.kind.value} observation must not carry an unresolved_reason")

        # Shadowing and redundancy are claims *about another entry*. Without
        # naming it, the observation cannot be checked or acted on.
        if self.kind in (AclObservationKind.SHADOWED, AclObservationKind.REDUNDANT):
            if not self.caused_by:
                raise ValueError(
                    f"a {self.kind.value} observation must name the entries "
                    "responsible — an unattributed claim cannot be verified"
                )
        return self

    @property
    def is_actionable(self) -> bool:
        """Whether an operator should do something about this.

        UNDETERMINED is not actionable on the ACL: the action it calls for is to
        resolve the object-group, which is a different task.
        """
        return self.kind is not AclObservationKind.UNDETERMINED

    def citations(self) -> list[str]:
        return [e.cite() for e in (*self.evidence, *self.caused_by_evidence)]


class AclAnalysis(BaseModel):
    """Every observation about one access list."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    acl_id: str = Constraint(min_length=1)
    acl_name: str = Constraint(min_length=1)
    entries_analysed: int = Constraint(ge=0)
    observations: tuple[AclObservation, ...] = ()

    def of_kind(self, kind: AclObservationKind) -> tuple[AclObservation, ...]:
        return tuple(o for o in self.observations if o.kind is kind)

    @property
    def is_clean(self) -> bool:
        """No observation at all — which is a result, not an absence of one."""
        return not self.observations

    @property
    def undetermined_count(self) -> int:
        return len(self.of_kind(AclObservationKind.UNDETERMINED))


class AclAnalysisResult(BaseModel):
    """Structural analysis of every ACL on one device.

    Deliberately separate from `Finding`. A report may show both; nothing may
    merge them, because one is a verdict against a control and the other is an
    observation about a configuration's own logic.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str = Constraint(min_length=1)
    audit_id: str | None = None
    analysed_at: datetime | None = None
    analyser_version: str = Constraint(min_length=1)

    acls: tuple[AclAnalysis, ...] = ()

    @property
    def observations(self) -> tuple[AclObservation, ...]:
        return tuple(o for acl in self.acls for o in acl.observations)

    def summary(self) -> dict[str, int]:
        counts = dict.fromkeys((k.value for k in AclObservationKind), 0)
        for observation in self.observations:
            counts[observation.kind.value] += 1
        return counts

    @property
    def analysed_nothing(self) -> bool:
        """True when the device carried no ACL to analyse.

        The honest state today: the corpus contains no access lists at all, so
        every real device reaches P7 with nothing for it to do. That is reported
        rather than presented as a clean result — "no ACLs were found" and "the
        ACLs were fine" are different statements.
        """
        return not self.acls
