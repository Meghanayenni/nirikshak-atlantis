"""Exposure-aware prioritisation, and its refusal to guess.

The Concept Report states the goal in one sentence:

> Severity alone is a poor ranking. A weak cipher on a management interface
> reachable from a user VLAN is not the same risk as the same cipher behind a
> deny-all ACL. Reasoning over the canonical model together with parsed ACLs
> turns a flat findings list into an ordered remediation queue.

Read it carefully and it names its own inputs: **the canonical model together
with parsed ACLs**. Exposure is a claim about where a control lives and who can
reach it, so it needs interfaces to say where, and access lists to say who.

`CanonicalSecurityModel.interfaces` and `.acls` are both empty on every device in
this corpus, and empty by construction rather than by accident — no pack declares
an interface or ACL pattern, because no corpus file contains an access list at
all (SOURCING_BACKLOG gaps 1 and 5). So on this repository every assessment this
module produces is **UNDETERMINED**, and that is the correct answer rather than a
limitation being worked around.

**The alternative was available and is worse.** Ranking by `base_severity` alone
would produce a plausible ordered list that an operator could act on, and
DEVELOPER_GUIDE.md §7 forbids exactly that: *"Severity alone must not determine
remediation order."* A ranking that claims to be exposure-aware while being
severity sorted is not a partial implementation of this feature; it is a
different feature wearing its name.

So `exposure_score` stays `None`, `priority_rank` stays `None`, and the layer
reports which input was missing. The machinery is real, tested against
constructed models, and will produce numbers the day an ACL-bearing configuration
is sourced — the same shape P7 took for ACL analysis and P8 for remediation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from api.models.csm import CanonicalSecurityModel, Interface
from api.models.enums import Severity
from api.prioritise.errors import ExposureError

EXPOSURE_RELEVANT_FIELDS: frozenset[str] = frozenset(
    {
        "ssh_version",
        "telnet_enabled",
        "http_server_enabled",
        "https_server_enabled",
        "weak_ciphers",
        "snmp_v3_only",
        "idle_timeout_seconds",
        "min_password_length",
        "aaa_enabled",
    }
)
"""Canonical fields whose risk genuinely depends on reachability.

A control governing a management protocol is more dangerous on an interface a
user VLAN can reach. A control governing *logging* is not: an unlogged device is
equally unlogged whoever can reach it, and pretending otherwise would let an
exposure score drift into fields it has nothing to say about.

Reference rather than enforcement — a field outside this set is reported
NOT_EXPOSURE_RELEVANT, which is a determinate answer and not an abstention.
"""


class ExposureDeterminacy(StrEnum):
    """Whether exposure could be assessed, and if not, precisely what was missing.

    Every non-DETERMINED value names a specific absent input. "Undetermined" on
    its own would send an operator looking for a bug; "no interface data" sends
    them to the sourcing backlog, which is where the answer is.
    """

    DETERMINED = "determined"
    """Interfaces and reachability were known and the score means something."""

    NOT_EXPOSURE_RELEVANT = "not_exposure_relevant"
    """This control's risk does not depend on reachability. A real answer."""

    NO_INTERFACE_DATA = "no_interface_data"
    """The model carries no interfaces, so *where* the control lives is unknown."""

    NO_ACL_DATA = "no_acl_data"
    """Interfaces are known but no access list is, so *who can reach it* is unknown."""

    INDETERMINATE_INTERFACES = "indeterminate_interfaces"
    """Interfaces exist but their management status is undocumented (DEF-2).

    Kept distinct from NO_INTERFACE_DATA because the remedies differ: one needs
    interface parsing, the other needs the vendor documentation that says which
    interface is a management interface. Folding an undocumented interface into
    "not management" is the substitution Rule 3 forbids, and the accessor split
    at P5 exists precisely so this layer has to decide rather than be handed an
    answer.
    """


@dataclass(frozen=True)
class ExposureAssessment:
    """What exposure could be established for one finding, and why.

    The invariant enforced below is the whole module: **a score exists if and
    only if exposure was DETERMINED.** Without it, a caller sorting on
    `score or 0.0` would silently rank every undeterminable finding last, which
    reads as "we checked and it is safe".
    """

    determinacy: ExposureDeterminacy
    score: float | None = None
    reason: str = ""
    factors: tuple[str, ...] = ()
    """Human-readable contributions. The Concept Report requires peer analysis be
    "fully explainable"; the same standard applies here."""

    def __post_init__(self) -> None:
        if self.determinacy is ExposureDeterminacy.DETERMINED:
            if self.score is None:
                raise ExposureError(
                    "an exposure assessment marked DETERMINED carries no score; "
                    "determining exposure and producing a number are the same act"
                )
        elif self.score is not None:
            raise ExposureError(
                f"exposure is {self.determinacy} but a score of {self.score} is "
                "attached. An undetermined exposure has no number — attaching one "
                "would let a caller sort by a value nothing measured."
            )
        if self.determinacy is not ExposureDeterminacy.DETERMINED and not self.reason:
            raise ExposureError(f"exposure state {self.determinacy} must name what was missing")

    @property
    def is_determined(self) -> bool:
        return self.determinacy is ExposureDeterminacy.DETERMINED


def is_exposure_relevant(field_name: str) -> bool:
    return field_name in EXPOSURE_RELEVANT_FIELDS


def management_exposure(interfaces: tuple[Interface, ...]) -> float:
    """How reachable the management plane is, from the interfaces alone.

    Deliberately crude and deliberately explainable: the fraction of management
    interfaces that carry an address and are not disabled. There is no weighting
    curve here and no tuned constant, because any such number would be a
    judgement nobody made and nobody could check.
    """
    if not interfaces:
        return 0.0
    reachable = sum(1 for i in interfaces if i.ip_addresses and i.enabled is not False)
    return reachable / len(interfaces)


def assess(
    csm: CanonicalSecurityModel,
    *,
    field_name: str,
    severity: Severity,
) -> ExposureAssessment:
    """Exposure for one finding on one device.

    Ordered so the most fundamental absence is reported first. A model with no
    interfaces cannot have its ACL coverage assessed, and saying "no ACL data"
    would point at the second missing input while the first is also missing.
    """
    if not is_exposure_relevant(field_name):
        return ExposureAssessment(
            determinacy=ExposureDeterminacy.NOT_EXPOSURE_RELEVANT,
            reason=(
                f"{field_name!r} does not govern a reachable service, so its risk "
                "does not vary with exposure. Severity stands on its own here."
            ),
        )

    if not csm.interfaces:
        return ExposureAssessment(
            determinacy=ExposureDeterminacy.NO_INTERFACE_DATA,
            reason=(
                "the canonical model carries no interfaces, so where this control "
                "applies and who can reach it are both unknown. No vendor pack "
                "declares an interface pattern yet (SOURCING_BACKLOG gap 5)."
            ),
        )

    if csm.management_interfaces() == () and csm.indeterminate_interfaces():
        return ExposureAssessment(
            determinacy=ExposureDeterminacy.INDETERMINATE_INTERFACES,
            reason=(
                f"{len(csm.indeterminate_interfaces())} interface(s) have "
                "undocumented management status, so the management plane cannot be "
                "located. An undocumented interface is not a non-management one "
                "(DEF-2)."
            ),
        )

    if not csm.acls:
        return ExposureAssessment(
            determinacy=ExposureDeterminacy.NO_ACL_DATA,
            reason=(
                "interfaces are known but no access list is, so who can reach this "
                "control cannot be established. The corpus contains no access list "
                "in any split (SOURCING_BACKLOG gap 1)."
            ),
        )

    management = csm.management_interfaces()
    reachability = management_exposure(management)
    weight = SEVERITY_WEIGHT[severity]
    score = round(min(1.0, reachability * weight), 4)

    return ExposureAssessment(
        determinacy=ExposureDeterminacy.DETERMINED,
        score=score,
        reason="assessed from management interface reachability and control severity",
        factors=(
            f"{len(management)} management interface(s)",
            f"reachability {reachability:.2f}",
            f"severity weight {weight:.2f}",
        ),
    )


SEVERITY_WEIGHT: dict[Severity, float] = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.8,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.3,
    Severity.INFO: 0.1,
}
"""Severity's contribution to exposure — a factor, never the whole answer.

DEVELOPER_GUIDE.md §7: *"Severity alone must not determine remediation order."* These
weights only ever multiply a reachability term that must be established from real
interface data first, so a severity value can never produce a score on its own.
The numbers are ordinal and plainly chosen; they are not calibrated against
anything and nothing here presents them as probabilities.
"""
