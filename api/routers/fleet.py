"""Fleet-level peer baselines over HTTP (P12).

One endpoint, admin-only. The comparison is fleet-wide by construction — a device
is judged against its peers, so answering the question means reading every
device's canonical model, including uploads the caller does not own. That is an
administrator's view, and scoping it per-user would produce a "peer group" of one
person's devices, which is a different and much less useful claim.

**What this returns on the current corpus is a page of refusals**, and that is
the honest result rather than a broken one. Every cohort holds fewer devices than
`MIN_COHORT_SIZE`, so no baseline is established and no device is called an
outlier. The endpoint returns the cohorts, their sizes and the reason each
produced no claim, because a caller shown an empty `outliers` list and nothing
else would reasonably conclude the fleet is uniform.

The models are rebuilt from stored configurations rather than read from a
findings table. Baselines compare *canonical field states*, which is what the
normaliser produces; deriving them from persisted verdicts instead would make the
baseline a function of whichever rules happened to run.
"""

from __future__ import annotations

import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Query

from api.config import settings
from api.ingest import blobs
from api.ingest.device_identity import extract_identity
from api.ingest.lines import split_lines
from api.ingest.packs import find_pack
from api.models.csm import CanonicalSecurityModel
from api.normalise.service import build_csm
from api.parse.service import parse_configuration
from api.prioritise.baseline import MIN_COHORT_SIZE, BaselineOutcome
from api.prioritise.service import fleet_baseline
from api.routers.deps import AdminUser, Conn

router = APIRouter(prefix="/fleet", tags=["fleet"])


def _models(
    conn: sqlite3.Connection, *, limit: int
) -> tuple[list[CanonicalSecurityModel], list[str]]:
    """Rebuild a canonical model for every ingested configuration.

    Skipped rather than guessed: a file whose platform was never identified has
    no pack, so it has no canonical model and cannot join a cohort. It is
    reported as skipped rather than silently dropped — a fleet view that quietly
    omitted devices would understate every cohort it touched.
    """
    rows = conn.execute(
        """
        SELECT file_id, blob_path, detected_vendor, detected_os_family
        FROM config_file ORDER BY first_seen_at, file_id LIMIT ?
        """,
        (limit,),
    ).fetchall()

    models: list[CanonicalSecurityModel] = []
    skipped: list[str] = []

    for row in rows:
        pack = find_pack(row["detected_vendor"], row["detected_os_family"])
        if pack is None:
            skipped.append(row["file_id"])
            continue
        try:
            raw = blobs.read(settings.blob_root, row["file_id"])
        except (OSError, FileNotFoundError):
            skipped.append(row["file_id"])
            continue

        text = raw.decode("utf-8", errors="replace")
        parsed = parse_configuration(text, pack, file_id=row["file_id"], file_path=row["blob_path"])
        identity = extract_identity(
            pack, split_lines(text), file_id=row["file_id"], file_path=row["blob_path"]
        )
        models.append(build_csm(parsed, pack, device_id=row["file_id"], detected_identity=identity))

    return models, skipped


@router.get("/baseline")
def read_baseline(
    conn: Conn,
    _admin: AdminUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    """Peer-baseline outlier detection across every ingested device."""
    models, skipped = _models(conn, limit=limit)
    result = fleet_baseline(models)

    return {
        "devices": result.device_count,
        "skipped_files": len(skipped),
        "cohorts": [
            {
                "cohort": cohort,
                "size": sum(1 for o in result.observations if o.cohort == cohort),
                "devices": sorted(o.label for o in result.observations if o.cohort == cohort),
            }
            for cohort in result.cohorts
        ],
        "minimum_cohort_size": MIN_COHORT_SIZE,
        "summary": result.describe(),
        # Every baseline, including the ones that established nothing. The
        # refusals are the informative half on a corpus this size: a response
        # carrying only comparable baselines would be an empty page that reads
        # as a uniform fleet.
        "baselines": [
            {
                "cohort": b.cohort,
                "field": b.field,
                "outcome": str(b.outcome),
                "cohort_size": b.cohort_size,
                "determinable": b.determinable,
                "indeterminate": b.indeterminate,
                "majority_state": str(b.majority_state) if b.majority_state else None,
                "majority_count": b.majority_count,
                "counts": b.counts,
                "explanation": b.explain(),
            }
            for b in result.baselines
        ],
        "comparable_baselines": sum(
            1 for b in result.baselines if b.outcome is BaselineOutcome.COMPARED
        ),
        # An observation about the fleet, never a verdict (the separation D22
        # drew for ACL findings, applied to drift).
        "outliers": [
            {
                "device_id": o.device_id,
                "device": o.label,
                "cohort": o.cohort,
                "field": o.field,
                "device_state": str(o.device_state),
                "majority_state": str(o.baseline.majority_state),
                "cohort_size": o.baseline.cohort_size,
                "agreeing": o.baseline.majority_count,
                "of_readable": o.baseline.determinable,
                "explanation": o.explain(),
            }
            for o in result.outliers
        ],
        "is_verdict": False,
        "note": (
            "A deviation from a peer group is an observation about the fleet, not "
            "a compliance verdict. Whether it breaches a control is decided by the "
            "rule engine over the canonical model, on a separate rail."
        ),
    }
