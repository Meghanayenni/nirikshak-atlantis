"""NIRIKSHAK API entry point.

P0 scaffolding. The only endpoint is a health check; every other router is
introduced by the phase that needs it (uploads at P3, findings at P6, training
and packs at P11, reports at P8).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.config import settings
from api.db.connection import connect
from api.db.migrate import current_version, migrate
from api.routers import audit as audit_router


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Bring the schema up to date before serving anything.

    `migrate` re-checks the recorded checksum of every applied migration first
    and refuses to proceed if one has been edited since. Starting on a schema
    that disagrees with its own history would undermine every hash the audit
    chain contains, so failing loudly here is the correct behaviour.
    """
    conn = connect(settings.db_path)
    try:
        migrate(conn)
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


@app.get("/health")
def health() -> dict[str, object]:
    """Liveness check, and a readout of the safety-relevant settings."""
    conn = connect(settings.db_path)
    try:
        schema_version = current_version(conn)
    finally:
        conn.close()

    return {
        "status": "ok",
        "version": "0.1.0",
        "phase": "P2",
        "schema_version": schema_version,
        "airgap": settings.airgap,
        "confidence_threshold": settings.confidence_threshold,
    }
