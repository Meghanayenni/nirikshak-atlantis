"""Rendering a `Report` to self-contained HTML.

Three decisions worth stating, because each is load-bearing:

**Autoescaping is on, and the report is full of operator data.** Every evidence
line in a report is verbatim text from an uploaded configuration file. A
configuration containing `<script>` - through a banner message, a description, or
deliberately - must render as characters on a page. Rule 2 requires the raw line
be shown exactly; escaping is what lets that be true and safe at once.

**`StrictUndefined`.** A template referring to a field the model does not have
raises instead of rendering an empty string. In a compliance report the silent
version is the dangerous one: a remediation block that renders blank looks
exactly like a control with nothing to fix.

**The output is one file with no external references.** No CDN, no linked
stylesheet, no web font. The CSS is inlined at render time. An operator can save
the report, mail it, or open it on a machine with no network - and the PDF path
needs no resource fetching either, which is one fewer thing to fail behind an
air gap (Rule 6).

The visual design follows `docs/ui_reference.html`, which is the specification
for the P13 React interface. It is followed for tokens, hierarchy and the
evidence block; it is **not** followed where it shows data this build does not
have. See ADR 0015 for the list of omissions and why each one is an omission
rather than a placeholder.
"""

from __future__ import annotations

import functools
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from api.report.errors import ReportRenderError
from api.report.model import Report

TEMPLATE_ROOT = Path(__file__).resolve().parent / "templates"
REPORT_TEMPLATE = "report.html.j2"
STYLESHEET = "report.css"


@functools.lru_cache(maxsize=1)
def environment() -> Environment:
    """The one Jinja environment, configured once."""
    return Environment(
        loader=FileSystemLoader(TEMPLATE_ROOT),
        autoescape=select_autoescape(default_for_string=True, default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


@functools.lru_cache(maxsize=1)
def stylesheet() -> str:
    path = TEMPLATE_ROOT / STYLESHEET
    if not path.is_file():
        raise ReportRenderError(f"the report stylesheet is missing at {path}")
    return path.read_text(encoding="utf-8")


def render_html(report: Report) -> str:
    """One `Report`, as a complete standalone HTML document.

    Failures are wrapped rather than propagated raw: a Jinja traceback names a
    template line, which tells whoever is on call nothing about which report
    failed or for which audit.
    """
    try:
        template = environment().get_template(REPORT_TEMPLATE)
        return template.render(report=report, stylesheet=stylesheet())
    except ReportRenderError:
        raise
    except Exception as exc:
        raise ReportRenderError(
            f"report {report.report_id} for audit {report.audit_id} failed to render: {exc}"
        ) from exc


def clear_render_cache() -> None:
    environment.cache_clear()
    stylesheet.cache_clear()
