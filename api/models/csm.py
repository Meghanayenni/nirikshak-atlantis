"""The Canonical Security Model — the trust boundary.

Everything upstream of this object may deal in vendor syntax and model output.
Nothing downstream of it may. The compliance engine at P6 accepts a CSM and
nothing else, so there is no parameter through which raw configuration text or
a model suggestion could reach a verdict (DEVELOPER_GUIDE.md Rule 1).

`fields` is an open mapping rather than a fixed set of attributes. Adding a
canonical field is then a data change in a vendor pack and a rule, not an edit
to this class — which is what Rule 5 and the problem statement's
no-code-redeployment clause require.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict
from pydantic import Field as Constraint

from api.models.acl import ACL
from api.models.enums import Direction, FieldState
from api.models.evidence import Evidence
from api.models.field import Field

CSM_VERSION = "1.0"

CANONICAL_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "ssh_version",
        "telnet_enabled",
        "http_server_enabled",
        "https_server_enabled",
        "min_password_length",
        "idle_timeout_seconds",
        "logging_enabled",
        "logging_hosts",
        "ntp_servers",
        "snmp_v3_only",
        "banner_present",
        "aaa_enabled",
        "weak_ciphers",
    }
)
"""The fields shipped at P1.

Reference, not enforcement: the mapping accepts any key, because constraining it
would make adding a canonical field a code change.
"""


class DeviceIdentity(BaseModel):
    """Who this configuration belongs to, as far as the file reveals.

    **Not** `api.models.ingestion.DetectedDeviceIdentity`, which is the
    ingestion-layer type: a bundle of `Field[str]` objects, each carrying its own
    evidence and abstaining independently. This one is the resolved, flattened
    identity the canonical model carries, and P5 converts the former into the
    latter. The two were both called `DeviceIdentity` until P5; the ingestion
    side was renamed so an ambiguous import cannot silently pick the wrong one.

    `device_id` is currently the ingested file's content hash, so it identifies
    *this configuration*, not the physical device across time. Recorded as
    DEF-3 and deferred; nothing here may present it as a stable device identity.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str = Constraint(min_length=1)
    hostname: str | None = None
    vendor: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    model: str | None = None
    serial: str | None = None

    role: str | None = Constraint(default=None, description="e.g. 'core-switch', 'edge-router'")
    site: str | None = None
    peer_group: str | None = Constraint(
        default=None, description="Cohort for peer-baseline outlier detection at P12"
    )


class InterfaceAcl(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    acl_id: str = Constraint(min_length=1)
    direction: Direction


class Interface(BaseModel):
    """An interface and its exposure-relevant properties.

    Feeds the exposure-aware prioritisation at P12: a weak cipher on a
    management interface reachable from a user VLAN is not the same risk as the
    same cipher behind a deny-all ACL.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Constraint(min_length=1)
    description: str | None = None
    enabled: bool | None = None
    zone: str | None = None

    ip_addresses: tuple[str, ...] = ()
    is_management: bool | None = None
    vlan: int | None = Constraint(default=None, ge=0, le=4094)

    applied_acls: tuple[InterfaceAcl, ...] = ()
    evidence: tuple[Evidence, ...] = ()


class UnknownLine(BaseModel):
    """A residue line no vendor pack recognised.

    First-class output, not an error. This is the queue the adaptive learning
    loop consumes at P10-P11. The text is stored scrubbed, because it may reach
    an embedding model and must never carry secrets there (Rule 6).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    line_number: int = Constraint(ge=1)
    raw_line_scrubbed: str = Constraint(min_length=1)
    normalised_line: str = Constraint(
        default="", description="Token-shape signature used for clustering"
    )
    cluster_id: str | None = None
    file_id: str = Constraint(min_length=1)
    block_path: tuple[str, ...] = ()


class CsmSource(BaseModel):
    """Provenance of the model: which files and which pack versions produced it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    file_ids: tuple[str, ...] = ()
    ingested_at: datetime | None = None
    pack_versions: dict[str, str] = Constraint(
        default_factory=dict, description="vendor -> pack_version actually applied"
    )


class CanonicalSecurityModel(BaseModel):
    """One device, normalised. The only input the compliance engine accepts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    csm_version: str = CSM_VERSION
    device: DeviceIdentity
    source: CsmSource = Constraint(default_factory=CsmSource)

    fields: dict[str, Field[Any]] = Constraint(default_factory=dict)
    acls: tuple[ACL, ...] = ()
    interfaces: tuple[Interface, ...] = ()
    residue: tuple[UnknownLine, ...] = ()

    # -- access ------------------------------------------------------------

    def get(self, name: str) -> Field[Any] | None:
        return self.fields.get(name)

    def state_of(self, name: str) -> FieldState:
        """State of a field, treating an entirely absent key as UNKNOWN.

        A field the parser never produced is not determinable, which is the same
        conclusion as one it produced without confidence. Both abstain.
        """
        found = self.fields.get(name)
        return found.state if found is not None else FieldState.UNKNOWN

    def determinable_fields(self) -> dict[str, Field[Any]]:
        return {k: v for k, v in self.fields.items() if v.is_determinable}

    def abstained_fields(self) -> dict[str, Field[Any]]:
        return {k: v for k, v in self.fields.items() if not v.is_determinable}

    def acl_by_id(self, acl_id: str) -> ACL | None:
        return next((a for a in self.acls if a.acl_id == acl_id), None)

    def management_interfaces(self) -> tuple[Interface, ...]:
        """Interfaces **confirmed** to be management interfaces.

        `is True`, not truthiness. `Interface.is_management` is `bool | None`,
        where `None` means undocumented — and `None` is falsy, so a truthiness
        test folded *we do not know* into *confirmed not management*. That is the
        exact substitution Rule 3 forbids, in the accessor P12's exposure-aware
        prioritisation depends on: an interface we failed to classify would be
        quietly de-prioritised rather than surfaced as undetermined.

        Anything not confirmed either way is `indeterminate_interfaces()`, which
        a caller must handle rather than receive silently folded into this
        result.
        """
        return tuple(i for i in self.interfaces if i.is_management is True)

    def non_management_interfaces(self) -> tuple[Interface, ...]:
        """Interfaces **confirmed** not to be management interfaces."""
        return tuple(i for i in self.interfaces if i.is_management is False)

    def indeterminate_interfaces(self) -> tuple[Interface, ...]:
        """Interfaces whose management status is undocumented.

        Neither confirmed nor excluded. Kept as its own answer so a caller must
        decide what to do about it — abstaining is a result, not an empty set.
        """
        return tuple(i for i in self.interfaces if i.is_management is None)

    # -- summary -----------------------------------------------------------

    @property
    def residue_count(self) -> int:
        """Size of the training queue. Should shrink measurably after P11 re-audit."""
        return len(self.residue)

    def coverage(self) -> float:
        """Fraction of present fields that are determinable, 0.0 when empty."""
        if not self.fields:
            return 0.0
        return len(self.determinable_fields()) / len(self.fields)
