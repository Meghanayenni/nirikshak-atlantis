"""Analysing every ACL on one device.

Structural analysis runs beside compliance evaluation, never inside it. The two
consume different halves of the canonical model and produce different types: the
canonical *fields* are evaluated against rules and yield verdicts, while the
canonical *ACLs* are analysed here and yield observations. A verdict says a
device breaches a control; an observation says a list does not do what reading it
suggests. Only the first needs a control to exist.

`api/comply/` cannot import this package, which is asserted rather than trusted.
If it could, a verdict would become influenceable by analysis performed outside
the canonical model — which is the one thing the trust boundary exists to
prevent.
"""

from __future__ import annotations

from datetime import UTC, datetime

from api.analyse.acl_analysis import ANALYSER_VERSION, analyse_acl
from api.models.analysis import AclAnalysisResult
from api.models.csm import CanonicalSecurityModel


def analyse_device(
    csm: CanonicalSecurityModel,
    *,
    audit_id: str | None = None,
    analysed_at: datetime | None = None,
) -> AclAnalysisResult:
    """Analyse every access list the canonical model carries.

    A device with no ACLs yields a result with no analyses, and
    `analysed_nothing` says so. That distinction matters more than it looks:
    "no access lists were found" and "the access lists were fine" would render
    identically as an empty list, and only one of them is reassuring.

    Today every real device takes that path — the corpus contains no access lists
    in any split, so `CSM.acls` is always empty. The analyser is exercised against
    constructed ACL objects instead, and no claim is made about vendor ACL parsing
    coverage.
    """
    return AclAnalysisResult(
        device_id=csm.device.device_id,
        audit_id=audit_id,
        analysed_at=analysed_at or datetime.now(UTC),
        analyser_version=ANALYSER_VERSION,
        acls=tuple(analyse_acl(acl) for acl in csm.acls),
    )
