"""NIRIKSHAK API entry point.

P0 scaffolding. The only endpoint is a health check; every other router is
introduced by the phase that needs it (uploads at P3, findings at P6, training
and packs at P11, reports at P8).
"""

from fastapi import FastAPI

from api.config import settings

app = FastAPI(
    title="NIRIKSHAK",
    description=(
        "Self-learning, vendor-agnostic network security compliance auditor. "
        "Operates on offline configuration exports only."
    ),
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, object]:
    """Liveness check, and a readout of the safety-relevant settings."""
    return {
        "status": "ok",
        "version": "0.1.0",
        "phase": "P0",
        "airgap": settings.airgap,
        "confidence_threshold": settings.confidence_threshold,
    }
