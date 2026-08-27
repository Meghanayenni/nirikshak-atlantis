"""Reporting-layer errors.

One of these matters more than the rest. `PdfBackendUnavailableError` is raised when
the WeasyPrint/GTK stack is absent, and the correct response to it is to **fail**
- not to return the HTML report with a `.pdf` name, not to switch renderer, not
to return an empty document. A caller who asked for a PDF and received something
else has been told the request succeeded when it did not.
"""

from __future__ import annotations


class ReportError(RuntimeError):
    """Base for every reporting-layer failure."""


class ReportRenderError(ReportError):
    """A report could not be rendered from a valid model.

    A template that raises is a defect in this repository, not in the operator's
    data, so it surfaces rather than degrading into a partial document. Half a
    compliance report is more dangerous than none: the missing half is invisible.
    """


class PdfBackendUnavailableError(ReportError):
    """The PDF renderer specified by ADR 0006 is not usable in this environment.

    Carries the specific missing pieces rather than a generic message. An
    operator seeing "PDF unavailable" can do nothing with it; one seeing which
    native libraries are absent can install them.

    **There is deliberately no fallback path behind this exception.** ADR 0006
    considered and rejected pointing WeasyPrint at another application's private
    DLL bundle, and substituting a different PDF engine would deviate from the
    specified stack and needs its own ADR. Silently returning HTML instead would
    be worse than both.
    """

    def __init__(
        self,
        *,
        weasyprint_installed: bool,
        missing_libraries: tuple[str, ...],
        detail: str | None = None,
    ) -> None:
        self.weasyprint_installed = weasyprint_installed
        self.missing_libraries = missing_libraries
        self.detail = detail

        parts: list[str] = ["PDF rendering is unavailable in this environment."]
        if not weasyprint_installed:
            parts.append(
                "The 'weasyprint' package is not installed; it belongs to the optional "
                "[report] dependency group (make install-report)."
            )
        if missing_libraries:
            parts.append(
                "The following native GTK libraries are missing: "
                + ", ".join(missing_libraries)
                + ". These are installed by a system installer, not by pip."
            )
        if detail:
            parts.append(detail)
        parts.append(
            "See docs/adr/0006-weasyprint-gtk-probe.md. The HTML report at the same "
            "path with a .html suffix is complete and requires none of this."
        )
        super().__init__(" ".join(parts))
