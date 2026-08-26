"""Structured, vendor-neutral ACL representation.

Modelled as intervals from the outset because the semantic analysis at P7 is
interval logic — shadowed, redundant and overly permissive rules are found by
computation, not pattern matching. A string-based ACL representation would make
that analysis impossible, so the normalisation happens here rather than later.

Two parallel representations are kept deliberately:

  * `kind` / `value`   — what the operator wrote, printed back in the report
  * `resolved_cidrs` / `low`..`high` — what the interval analysis consumes
"""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, ConfigDict, model_validator
from pydantic import Field as Constraint

from api.models.enums import AclAction, AclType, AddrKind, Direction, PortOp
from api.models.evidence import Evidence

PORT_MIN = 0
PORT_MAX = 65535


class ProtocolSpec(BaseModel):
    """IP protocol, by name and/or number. `any` matches every protocol."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Constraint(min_length=1, description="e.g. 'tcp', 'udp', 'ip', 'any'")
    number: int | None = Constraint(default=None, ge=0, le=255)

    @property
    def is_any(self) -> bool:
        return self.name.lower() in ("any", "ip")


class AddrSpec(BaseModel):
    """A source or destination address specification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: AddrKind
    value: str = Constraint(default="", description="As written in the configuration")
    resolved_cidrs: tuple[str, ...] = Constraint(
        default=(), description="Normalised CIDRs the interval analysis consumes"
    )

    @model_validator(mode="after")
    def _check(self) -> AddrSpec:
        if self.kind is AddrKind.ANY:
            if self.resolved_cidrs and set(self.resolved_cidrs) != {"0.0.0.0/0", "::/0"}:
                pass  # an explicit any is allowed to carry its own expansion
            return self

        if self.kind in (AddrKind.HOST, AddrKind.CIDR):
            if not self.resolved_cidrs:
                raise ValueError(
                    f"{self.kind} address {self.value!r} must resolve to at least "
                    "one CIDR for interval analysis"
                )
            for cidr in self.resolved_cidrs:
                try:
                    ipaddress.ip_network(cidr, strict=False)
                except ValueError as exc:
                    raise ValueError(f"invalid CIDR {cidr!r}: {exc}") from exc

        if self.kind is AddrKind.OBJECT and not self.value:
            raise ValueError("an object address must name the object")

        return self

    @property
    def is_any(self) -> bool:
        return self.kind is AddrKind.ANY


class PortSpec(BaseModel):
    """A port range, normalised to an inclusive interval."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    op: PortOp
    low: int = Constraint(default=PORT_MIN, ge=PORT_MIN, le=PORT_MAX)
    high: int = Constraint(default=PORT_MAX, ge=PORT_MIN, le=PORT_MAX)

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: object) -> object:
        """Derive the interval from the operator, so analysis sees one shape."""
        if not isinstance(data, dict):
            return data
        try:
            op = PortOp(data.get("op"))
        except ValueError:
            return data

        out = dict(data)
        low, high = out.get("low"), out.get("high")

        if op is PortOp.ANY:
            out["low"], out["high"] = PORT_MIN, PORT_MAX
        elif op is PortOp.EQ and low is not None:
            out["high"] = low
        elif op is PortOp.LT and high is not None:
            out["low"], out["high"] = PORT_MIN, max(PORT_MIN, high - 1)
        elif op is PortOp.GT and low is not None:
            out["low"], out["high"] = min(PORT_MAX, low + 1), PORT_MAX
        return out

    @model_validator(mode="after")
    def _check(self) -> PortSpec:
        if self.high < self.low:
            raise ValueError(f"port interval {self.low}..{self.high} is inverted")
        if self.op is PortOp.EQ and self.low != self.high:
            raise ValueError(f"eq port must be a single value, got {self.low}..{self.high}")
        return self

    @property
    def is_any(self) -> bool:
        return self.low == PORT_MIN and self.high == PORT_MAX

    def overlaps(self, other: PortSpec) -> bool:
        return self.low <= other.high and other.low <= self.high


class AclEntryFlags(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    established: bool = False
    log: bool = False
    disabled: bool = False


class ACLEntry(BaseModel):
    """One access-control entry. Evidence is mandatory, as for any claim."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    seq: int = Constraint(ge=0)
    action: AclAction
    protocol: ProtocolSpec

    src: AddrSpec
    src_port: PortSpec = Constraint(default_factory=lambda: PortSpec(op=PortOp.ANY))
    dst: AddrSpec
    dst_port: PortSpec = Constraint(default_factory=lambda: PortSpec(op=PortOp.ANY))

    flags: AclEntryFlags = Constraint(default_factory=AclEntryFlags)
    evidence: tuple[Evidence, ...] = Constraint(min_length=1)

    @property
    def is_permit_any_any(self) -> bool:
        """The classic overly-permissive shape, flagged by the P7 analysis."""
        return (
            self.action is AclAction.PERMIT
            and self.src.is_any
            and self.dst.is_any
            and self.protocol.is_any
            and self.dst_port.is_any
        )


class AclApplication(BaseModel):
    """Where an ACL is bound, and in which direction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    interface: str = Constraint(min_length=1)
    direction: Direction


class ACL(BaseModel):
    """A named access list with its ordered entries."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    acl_id: str = Constraint(min_length=1)
    name: str = Constraint(min_length=1)
    acl_type: AclType

    applied_to: tuple[AclApplication, ...] = ()
    entries: tuple[ACLEntry, ...] = ()
    implicit_deny: bool = True

    evidence: tuple[Evidence, ...] = ()

    @model_validator(mode="after")
    def _check_sequence(self) -> ACL:
        seqs = [e.seq for e in self.entries]
        if len(seqs) != len(set(seqs)):
            raise ValueError(f"ACL {self.name!r} has duplicate entry sequence numbers")
        if seqs != sorted(seqs):
            raise ValueError(
                f"ACL {self.name!r} entries are out of sequence order — order is "
                "semantically significant for shadowing analysis"
            )
        return self

    @property
    def is_applied(self) -> bool:
        return bool(self.applied_to)
