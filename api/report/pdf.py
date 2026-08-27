"""The PDF adapter - WeasyPrint only, behind an availability probe (ADR 0006).

Problem Statement 26155 names per-device PDF reporting as a deliverable and
ADR 0006 fixes the renderer as WeasyPrint with Jinja2. WeasyPrint is pure Python
but is not self-contained: from version 53 it lays text out through Pango, which
is part of the native GTK stack - DLLs installed by a system installer, not by
pip.

That stack is **absent on this machine**, verified by probe at P0 and again at
P8. So this module exists in a specific shape:

  * the probe is the same one ADR 0006 ran, kept in code rather than in prose so
    it re-runs on every request instead of describing a machine from August;
  * `render_pdf` raises `PdfBackendUnavailableError` naming exactly what is missing;
  * there is **no fallback**. Not another engine, not a headless browser, not
    HTML returned under a .pdf name.

The last point is the whole reason this file is separate from `render.py`. HTML
reporting has no native dependency at all and works everywhere; keeping the PDF
step behind its own boundary means the absent runtime blocks one endpoint rather
than the reporting feature.
"""

from __future__ import annotations

import ctypes.util
import importlib.util
from dataclasses import dataclass

from api.report.errors import PdfBackendUnavailableError

REQUIRED_LIBRARIES: tuple[str, ...] = (
    "libgobject-2.0-0",
    "libpango-1.0-0",
    "libpangoft2-1.0-0",
    "libharfbuzz-0",
    "libfontconfig-1",
    "libcairo-2",
    "libgdk_pixbuf-2.0-0",
    "libglib-2.0-0",
)
"""The native libraries ADR 0006 probed, in the order that ADR lists them.

Kept identical to the ADR so a failure message and the decision record name the
same set. `libgdk_pixbuf-2.0-0` is needed only for raster images and
`libglib-2.0-0` is transitive, but a partial stack is not a working one, and
reporting a subset would send someone to install half of what they need.
"""


@dataclass(frozen=True)
class PdfAvailability:
    """Whether a PDF can be produced here, and if not, precisely why."""

    weasyprint_installed: bool
    missing_libraries: tuple[str, ...]

    @property
    def available(self) -> bool:
        return self.weasyprint_installed and not self.missing_libraries

    @property
    def summary(self) -> str:
        if self.available:
            return "PDF rendering is available."
        reasons: list[str] = []
        if not self.weasyprint_installed:
            reasons.append("the weasyprint package is not installed")
        if self.missing_libraries:
            reasons.append(f"{len(self.missing_libraries)} native GTK libraries are missing")
        return "PDF rendering is unavailable: " + "; ".join(reasons) + "."


def missing_libraries() -> tuple[str, ...]:
    """Which of the required native libraries the loader cannot find.

    `ctypes.util.find_library` is what WeasyPrint's own bindings ultimately rely
    on, so this asks the same question the renderer would ask, rather than
    checking a list of directories that happen to be conventional today.
    """
    return tuple(name for name in REQUIRED_LIBRARIES if ctypes.util.find_library(name) is None)


def weasyprint_installed() -> bool:
    """Whether the Python package is importable, without importing it.

    Deliberately `find_spec` rather than a try/import. Importing WeasyPrint with
    the native stack absent raises from deep inside its FFI bindings, and the
    resulting message is about a missing symbol rather than about a missing
    runtime - which is not what the person reading it needs to know.
    """
    return importlib.util.find_spec("weasyprint") is not None


def availability() -> PdfAvailability:
    """Probe this environment. Cheap enough to run per request, and it must be.

    Not cached: the GTK runtime can be installed while the service is running,
    and a cached negative would keep reporting the absence of something that is
    now present until someone restarted the process.
    """
    return PdfAvailability(
        weasyprint_installed=weasyprint_installed(),
        missing_libraries=missing_libraries(),
    )


def render_pdf(html: str, *, base_url: str | None = None) -> bytes:
    """Render an HTML report to PDF bytes, or raise.

    The only outcomes are a PDF and an exception. If this function ever gains a
    third, the guarantee that a `.pdf` response contains a PDF is gone.
    """
    state = availability()
    if not state.available:
        raise PdfBackendUnavailableError(
            weasyprint_installed=state.weasyprint_installed,
            missing_libraries=state.missing_libraries,
        )

    try:
        from weasyprint import HTML  # noqa: PLC0415 - optional [report] dependency
    except Exception as exc:  # pragma: no cover - requires a half-installed stack
        raise PdfBackendUnavailableError(
            weasyprint_installed=state.weasyprint_installed,
            missing_libraries=state.missing_libraries,
            detail=f"weasyprint could not be imported: {exc}",
        ) from exc

    try:
        return bytes(HTML(string=html, base_url=base_url).write_pdf())
    except Exception as exc:  # pragma: no cover - requires a working GTK stack
        raise PdfBackendUnavailableError(
            weasyprint_installed=state.weasyprint_installed,
            missing_libraries=state.missing_libraries,
            detail=f"weasyprint failed while rendering: {exc}",
        ) from exc
