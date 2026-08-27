"""Boundaries around reporting (P8).

A report is the only artefact most people will ever see. Everything the rest of
the system refuses to claim has to survive the trip into a document, and the ways
that goes wrong are specific:

    a report that re-runs the pipeline       describes a fresh audit, not the recorded one
    a report that fills an empty column      invents coverage the project does not have
    a PDF path that falls back to HTML       tells a caller it succeeded when it did not
    a template that renders raw config text  executes an operator's own file as markup

Each has a test here.

`api/report/` may import `api.models` and `api.remediate` and nothing else from
`api/`. Notably it may **not** import `api.db`: the router performs the I/O and
hands the view model plain data, which is what lets the whole package be tested
without a database and keeps it off every path that could reach a stored
configuration.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT = REPO_ROOT / "api" / "report"
TEMPLATES = REPORT / "templates"
UI_REFERENCE = REPO_ROOT / "docs" / "ui_reference.html"

ML_MODULES = ["sentence_transformers", "torch", "faiss", "sklearn", "transformers", "ollama"]
NETWORK_MODULES = ["netmiko", "napalm", "paramiko", "requests", "httpx", "socket", "telnetlib"]


def _sources(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py"))


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
    return found


def _offending(root: Path, module: str) -> list[str]:
    return [
        f"{path.relative_to(REPO_ROOT)} imports {imported}"
        for path in _sources(root)
        for imported in _imports(path)
        if imported == module or imported.startswith(f"{module}.")
    ]


def test_report_package_is_populated() -> None:
    modules = [p for p in _sources(REPORT) if p.name != "__init__.py"]
    assert len(modules) >= 4, f"expected the reporting modules, found {len(modules)}"


# ---------------------------------------------------------------------------
# A report renders; it does not decide
# ---------------------------------------------------------------------------


def test_report_cannot_import_the_compliance_engine() -> None:
    """The one that matters.

    A report is assembled from persisted findings (decision D23). If it could
    reach the engine it could re-evaluate, and the document would describe a
    fresh audit that happens to agree with the recorded one - silently different
    if a pack version changed in between.
    """
    assert _offending(REPORT, "api.comply") == []


@pytest.mark.parametrize("package", ["parse", "normalise", "ingest", "learn", "db"])
def test_report_cannot_reach_the_pipeline(package: str) -> None:
    """Rendering has no business parsing, normalising, ingesting or querying."""
    assert _offending(REPORT, f"api.{package}") == []


def test_report_imports_only_contracts_and_remediation() -> None:
    """A whitelist. `api.remediate` is the one deliberate edge (decision D26)."""
    violations: list[str] = []
    for path in _sources(REPORT):
        for imported in _imports(path):
            if not imported.startswith("api."):
                continue
            top = ".".join(imported.split(".")[:2])
            if top not in {"api.models", "api.remediate", "api.report"}:
                violations.append(f"{path.relative_to(REPO_ROOT)} imports {imported}")

    assert violations == [], "\n".join(violations)


@pytest.mark.parametrize("module", ML_MODULES)
def test_report_uses_no_machine_learning(module: str) -> None:
    """Rule 1 — no model output may reach a document a human acts on."""
    assert _offending(REPORT, module) == []


@pytest.mark.parametrize("module", NETWORK_MODULES)
def test_report_has_no_network_capability(module: str) -> None:
    assert _offending(REPORT, module) == []


def test_report_performs_no_file_or_database_io_beyond_its_templates() -> None:
    """The only bytes this package reads are its own template and stylesheet."""
    offenders: list[str] = []
    for path in _sources(REPORT):
        source = path.read_text(encoding="utf-8")
        for pattern in ("sqlite3", "conn.execute", "open(", "urlopen"):
            if pattern in source:
                offenders.append(f"{path.relative_to(REPO_ROOT)} uses {pattern!r}")
    assert offenders == [], "\n".join(offenders)


# ---------------------------------------------------------------------------
# The PDF path never degrades (ADR 0006)
# ---------------------------------------------------------------------------


def test_only_weasyprint_is_used_for_pdf() -> None:
    """ADR 0006 fixes the renderer. Substituting one needs its own ADR.

    A second PDF engine appearing here would be the specified stack being
    replaced quietly because the specified one was inconvenient to install.
    """
    other_engines = ("reportlab", "fpdf", "pdfkit", "wkhtmltopdf", "xhtml2pdf", "playwright")
    offenders = [
        f"{path.relative_to(REPO_ROOT)} references {engine}"
        for path in _sources(REPORT)
        for engine in other_engines
        if engine in path.read_text(encoding="utf-8").lower()
    ]
    assert offenders == [], "\n".join(offenders)


def test_weasyprint_is_not_a_core_dependency() -> None:
    """It belongs to the optional [report] group, installed at P8 (ADR 0006)."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    core, _, extras = pyproject.partition("[project.optional-dependencies]")
    assert "weasyprint" not in core.lower()
    assert "weasyprint" in extras.lower()


def test_the_pdf_adapter_has_no_fallback_return() -> None:
    """`render_pdf` returns bytes or raises. There is no third outcome.

    A fallback would put an HTML document behind a `.pdf` response, and a file
    whose extension disagrees with its contents is worse than an error.
    """
    source = (REPORT / "pdf.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    render = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "render_pdf"
    )
    returns = [n for n in ast.walk(render) if isinstance(n, ast.Return)]

    assert len(returns) == 1, f"render_pdf has {len(returns)} return statements; expected exactly 1"
    assert not any(isinstance(n, ast.Return) and n.value is None for n in returns), (
        "render_pdf must never return None"
    )

    for banned in ("render_html", "return html", "text/html"):
        assert banned not in source, f"the PDF adapter references {banned!r}"


def test_the_pdf_probe_names_every_library_the_adr_lists() -> None:
    """The failure message and ADR 0006 must name the same set."""
    from api.report.pdf import REQUIRED_LIBRARIES

    adr = (REPO_ROOT / "docs" / "adr" / "0006-weasyprint-gtk-probe.md").read_text(encoding="utf-8")
    missing = [lib for lib in REQUIRED_LIBRARIES if lib not in adr]
    assert missing == [], f"the probe checks libraries ADR 0006 does not list: {missing}"


# ---------------------------------------------------------------------------
# The template claims nothing the data does not support
# ---------------------------------------------------------------------------


def _template_text() -> str:
    return (TEMPLATES / "report.html.j2").read_text(encoding="utf-8")


def test_the_template_contains_no_framework_identifier() -> None:
    """D16 — every rule ships `frameworks: []`.

    `docs/ui_reference.html` draws a framework column with `CIS 1.2.3`,
    `AC-17` and `V-215807` in it. That is the P13 target state and those values
    are illustrative. A shipped report carrying them would be claiming coverage
    against benchmarks nobody has read.
    """
    text = _template_text()
    invented = re.compile(
        r"\b(CIS[\s-]\d+\.\d+|AC-\d+|IA-\d+|AU-\d+|CM-\d+|V-\d{5,}|A\.\d+\.\d+)\b"
    )
    found = invented.findall(text)
    assert found == [], f"the report template carries framework identifiers: {found}"


def test_the_template_contains_no_vendor_command() -> None:
    """Rule 4 — a command in the template would be a command nobody vetted.

    The remediation block renders whatever the resolver returned. If it could
    also render a literal, an empty library would still produce commands.
    """
    text = _template_text()
    command_shaped = re.compile(
        r"^\s*(configure terminal|line vty|transport input|no ip http|"
        r"snmp-server|write memory|set system|commit)\b",
        re.MULTILINE | re.IGNORECASE,
    )
    found = command_shaped.findall(text)
    assert found == [], f"the report template contains device commands: {found}"


def test_the_template_states_the_no_remediation_sentence() -> None:
    """It is rendered from the resolver's constant, not retyped in the template.

    Two copies of an operator-facing sentence drift, and the copy in the document
    is the one the operator reads.
    """
    from api.remediate.resolver import NO_REMEDIATION_STATEMENT

    assert NO_REMEDIATION_STATEMENT not in _template_text(), (
        "the sentence is hard-coded in the template; render it from the resolver"
    )
    assert "item.remediation.statement" in _template_text()


def test_the_template_does_not_claim_exposure_ranking() -> None:
    """P12 — `priority_rank` and `exposure_score` are unset on every finding."""
    text = _template_text().lower()
    for phrase in ("ranked by exposure", "exposure score", "priority rank"):
        assert phrase not in text, f"the template claims {phrase!r}, which is not computed"


def test_the_template_never_calls_the_subject_a_device_identity() -> None:
    """DEF-3 — `device_id` is the configuration file's content hash.

    It changes when the file is edited, so presenting it as a device identity
    would let two audits of the same router look like two different devices.
    """
    text = _template_text()
    assert "device_id" not in text
    assert "config_file_id" in text


def test_autoescaping_is_enabled() -> None:
    """Rule 2 requires the raw line be shown; escaping is what makes that safe.

    Every evidence line is verbatim text from an uploaded configuration. A banner
    or description containing markup must render as characters.
    """
    source = (REPORT / "render.py").read_text(encoding="utf-8")
    assert "autoescape" in source
    assert "select_autoescape" in source
    assert "StrictUndefined" in source


def test_the_report_is_self_contained() -> None:
    """No CDN, no linked stylesheet, no web font (Rule 6, and PDF rendering).

    An air-gapped operator must get the same document as anyone else, and the
    PDF path must not need to fetch a resource to lay the page out.
    """
    text = _template_text()
    for external in ("http://", "https://", "<script", "cdn.", "fonts.googleapis"):
        assert external not in text, f"the report template references {external!r}"


def test_the_stylesheet_exists_and_is_inlined() -> None:
    assert (TEMPLATES / "report.css").is_file()
    assert "{{ stylesheet }}" in _template_text()


# ---------------------------------------------------------------------------
# The UI reference stays a specification
# ---------------------------------------------------------------------------


def test_the_ui_reference_is_untouched_by_the_backend() -> None:
    """`docs/ui_reference.html` is the P13 design specification, not a template.

    Nothing in `api/` may load it. It contains illustrative devices, framework
    identifiers and remediation commands that exist to show a designer what the
    interface should look like; rendering any of it would ship those values.
    """
    assert UI_REFERENCE.is_file(), "the UI reference has gone missing"

    offenders: list[str] = []
    for path in sorted((REPO_ROOT / "api").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        # A string that is its own statement is documentation - a module, class,
        # function or attribute docstring. Referring to the specification in
        # prose is expected and good; the thing that must never happen is a
        # module treating it as an input.
        documentation = {
            id(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        }

        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and "ui_reference" in node.value
                and id(node) not in documentation
            ):
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {node.value[:60]!r}")

    assert offenders == [], f"the backend reads the UI reference: {offenders}"


def test_the_ui_reference_is_not_a_jinja_template() -> None:
    """It must stay static: no template syntax, nothing to render it against."""
    text = UI_REFERENCE.read_text(encoding="utf-8")
    assert "{{" not in text and "{%" not in text
