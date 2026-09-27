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

from fastapi import APIRouter, HTTPException, Query

from api.config import settings
from api.ingest import blobs
from api.ingest.device_identity import extract_identity
from api.ingest.lines import split_lines
from api.ingest.packs import find_pack
from api.models.csm import CanonicalSecurityModel
from api.models.enums import FieldState
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


@router.get("/baseline/device/{device_id}")
def read_device_baseline(
    device_id: str,
    conn: Conn,
    _admin: AdminUser,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> dict[str, Any]:
    """One device against its own peer group — the fleet baseline, filtered.

    Admin-only for the same reason as `/fleet/baseline`: a cohort's majority is a
    fact about other people's devices. Nothing is recomputed here. The cohort,
    every per-field baseline and every deviation come from `fleet_baseline`
    unchanged; this route selects the rows that concern one device and names the
    state the whole answer is in, so the interface decides nothing.

    `status` is one of:

      * `cohort_too_small` — fewer than `floor` devices; no claim either way.
      * `nothing_compared` — enough devices, but no field produced a baseline
        (a pack that reads no canonical field, or a cohort in which no device
        sets any field its pack reads). Not "no deviation": no comparison was
        made.
      * `compared` — at least one field was compared against a majority.

    Baselines compare field *states* (read and present, absent by default,
    absent and unsupported), never values. UNKNOWN on this device is shown as
    UNKNOWN and is never counted as agreeing with the cohort.
    """
    known = conn.execute("SELECT 1 FROM config_file WHERE file_id = ?", (device_id,)).fetchone()
    if known is None:
        raise HTTPException(status_code=404, detail="no such device")

    models, skipped = _models(conn, limit=limit)
    result = fleet_baseline(models)

    device = next((o for o in result.observations if o.device_id == device_id), None)
    if device is None:
        reason = (
            "this file's platform has no active vendor pack, so it has no canonical "
            "model and belongs to no cohort"
            if device_id in skipped
            else f"this file is outside the first {limit} files read, so its cohort was not built"
        )
        raise HTTPException(status_code=409, detail=reason)

    cohort = device.cohort
    cohort_size = sum(1 for o in result.observations if o.cohort == cohort)
    rows = [b for b in result.baselines if b.cohort == cohort]
    deviating = {o.field: o for o in result.outliers if o.device_id == device_id}

    if cohort_size < MIN_COHORT_SIZE:
        status = "cohort_too_small"
    elif not any(b.outcome is BaselineOutcome.COMPARED for b in rows):
        status = "nothing_compared"
    else:
        status = "compared"

    return {
        "device_id": device_id,
        "cohort": cohort,
        "cohort_size": cohort_size,
        "floor": MIN_COHORT_SIZE,
        "status": status,
        "per_field": [
            {
                "field": b.field,
                "outcome": str(b.outcome),
                "device_state": str(device.states.get(b.field, FieldState.UNKNOWN)),
                "majority_state": str(b.majority_state) if b.majority_state else None,
                "agreeing": b.majority_count,
                "of_readable": b.determinable,
                "deviation": b.field in deviating,
                "explanation": (
                    deviating[b.field].explain() if b.field in deviating else b.explain()
                ),
            }
            for b in rows
        ],
        "overall_deviation": bool(deviating),
        "is_verdict": False,
        "note": (
            "A deviation from a peer group is an observation about the fleet, not "
            "a compliance verdict. Baselines compare field states, not values."
        ),
    }
