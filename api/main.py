"""NIRIKSHAK API entry point.

Each router is introduced by the phase that needs it: the audit chain at P2,
uploads at P3, findings at P6, reports at P8, training and packs at P11.

`/health` is the one public route, and it is a readout rather than a ping. It
reports the two Rule 3 abstention floors, the airgap flag, whether this machine
can render a PDF, and how many vetted snippets exist — the last two so an
operator can tell a missing capability from a broken one.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.config import settings
from api.db.connection import connect
from api.db.migrate import AUDIT_MIGRATIONS, OPERATIONAL_MIGRATIONS, current_version, migrate
from api.learn.embedding import MODEL_NAME
from api.learn.embedding import availability as model_availability
from api.remediate.library import load_active_library
from api.report.pdf import availability as pdf_availability
from api.routers import audit as audit_router
from api.routers import audits as audits_router
from api.routers import ingest as ingest_router
from api.routers import reports as reports_router
from api.routers import training as training_router
from api.routers import users as users_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Bring the schema up to date before serving anything.

    `migrate` re-checks the recorded checksum of every applied migration first
    and refuses to proceed if one has been edited since. Starting on a schema
    that disagrees with its own history would undermine every hash the audit
    chain contains, so failing loudly here is the correct behaviour.
    """
    # Two databases (decision D4): the operational store holds configuration
    # content, the audit chain holds identifiers and hashes. Keeping them apart
    # makes "no configuration content in the audit database" checkable by
    # opening the file rather than by trusting payload discipline.
    settings.blob_root.mkdir(parents=True, exist_ok=True)

    for path, migrations in (
        (settings.db_path, OPERATIONAL_MIGRATIONS),
        (settings.audit_db_path, AUDIT_MIGRATIONS),
    ):
        conn = connect(path)
        try:
            migrate(conn, migrations)
        finally:
            conn.close()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="NIRIKSHAK",
    description=(
        "Self-learning, vendor-agnostic network security compliance auditor. "
        "Operates on offline configuration exports only."
    ),
    version="0.1.0",
)

app.include_router(audit_router.router)
app.include_router(audits_router.router)
app.include_router(ingest_router.router)
app.include_router(reports_router.router)
app.include_router(training_router.router)
app.include_router(users_router.router)


@app.get("/health")
def health() -> dict[str, object]:
    """Liveness check, and a readout of the safety-relevant settings."""
    pdf_state = pdf_availability()
    model_state = model_availability(airgap=settings.airgap)
    library = load_active_library()

    versions = {}
    for name, path in (("operational", settings.db_path), ("audit", settings.audit_db_path)):
        conn = connect(path)
        try:
            versions[name] = current_version(conn)
        finally:
            conn.close()

    return {
        "status": "ok",
        "version": "0.1.0",
        "phase": "P11",
        "schema_version": versions["audit"],
        "schema_versions": versions,
        "airgap": settings.airgap,
        # Rule 3 has two abstention floors from P4 onward (decision D6), and a
        # readout naming only one would suggest a single threshold governs every
        # population — which is the misreading D6 exists to prevent.
        "confidence_threshold": settings.confidence_threshold,
        "platform_default_min_confidence": settings.platform_default_min_confidence,
        # D13 — the confidence an accepted platform default is ASSIGNED, distinct
        # from the floor above it must clear. Reported because an operator
        # checking why a control passed on an absent directive needs both.
        "platform_default_confidence": settings.platform_default_confidence,
        # P8 — whether the PDF path can serve, probed live rather than assumed
        # (ADR 0006). HTML reporting has no native dependency and is always
        # available; the PDF endpoint answers 503 when this says otherwise, and
        # never substitutes the HTML document for the PDF it could not make.
        # P11 — the embedding model, probed live for the same reason the PDF
        # stack is (ADR 0018). Reported from this phase onward because P11 is
        # what puts a training queue in front of a person: until then the model
        # had no operator-facing consequence, and now its absence is the
        # difference between a ranked queue and an unranked one. The queue works
        # either way and says which it is.
        "similarity_model": {
            "available": model_state.available,
            "model": MODEL_NAME,
            "package_installed": model_state.package_installed,
            "weights_present": model_state.weights_present,
            "summary": model_state.summary,
            "calibrated": False,
            "note": (
                "No calibrator is fitted (D42). Every suggestion is "
                "UNCALIBRATED_SIMILARITY and forces the field to UNKNOWN; a "
                "similarity score is never a probability."
            ),
        },
        "pdf_reporting": {
            "available": pdf_state.available,
            "weasyprint_installed": pdf_state.weasyprint_installed,
            "missing_libraries": list(pdf_state.missing_libraries),
            "detail": pdf_state.summary,
        },
        # Rule 4 — an empty library resolves nothing, which is the honest state
        # while no vendor documentation has been sourced. Reported so an operator
        # can tell "no remediation available" from "reporting is broken".
        "remediation_library": {
            "snippets": len(library.snippets),
            "version": library.version,
        },
    }
