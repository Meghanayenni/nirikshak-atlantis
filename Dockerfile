# NIRIKSHAK — a container where PDF rendering works.
#
# WHY THIS EXISTS. WeasyPrint lays text out through Pango, which is part of the
# native GTK stack: DLLs and shared objects installed by a system package
# manager, not by pip. ADR 0006 fixed the renderer as WeasyPrint and forbade
# every fallback — no second engine, no headless browser, no HTML returned under
# a `.pdf` name — which leaves exactly one way to make the endpoint work, and it
# is this: install the runtime.
#
# It is not a workaround for a developer machine. It is the supported way to run
# NIRIKSHAK with every deliverable available, and it doubles as the reproducible
# setup a reviewer can check: the build either succeeds or it does not.
#
# OFFLINE-FIRST (Rule 6). The build needs a network; the running container does
# not. Nothing under `api/` fetches anything, no model is downloaded here, and
# the image carries no credentials. Run it with `--network none` once built and
# every endpoint except PDF-less ones still works.

FROM python:3.11-slim-bookworm

# The eight components api/report/pdf.py probes for, by their Debian package
# names. `libgobject-2.0` and `glib-2.0` both come from libglib2.0-0.
#
# `fonts-dejavu-core` is not optional. WeasyPrint with no font installed renders
# a PDF of the correct size containing nothing legible, which is worse than the
# 503 it replaces — a file that looks like a report and is blank.
RUN apt-get update && apt-get install --no-install-recommends -y \
        libglib2.0-0 \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libharfbuzz0b \
        libfontconfig1 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependency metadata first, so a source edit does not reinstall the world.
COPY pyproject.toml README.md ./
COPY api/__init__.py api/__init__.py
RUN pip install --no-cache-dir -e ".[report]"

COPY api/ api/
COPY rules/ rules/
COPY packs/ packs/
COPY snippets/ snippets/

# `packs/trained/` is runtime state this deployment writes, and `uploads/`
# holds configuration files, which are sensitive data (DEVELOPER_GUIDE.md §9). Both are
# volumes in docker-compose.yml so neither is baked into an image that might be
# shared.
RUN mkdir -p packs/trained uploads

# Fail the build rather than ship an image whose PDF endpoint 503s. This runs
# the same probe the endpoint runs, and then actually renders — a probe that
# passes while rendering fails is exactly the gap this file closes.
RUN python -c "\
from api.report.pdf import availability, render_pdf; \
state = availability(); \
assert state.available, state.summary; \
out = render_pdf('<html><body><h1>NIRIKSHAK</h1></body></html>'); \
assert out.startswith(b'%PDF-'), 'the renderer returned something that is not a PDF'; \
print('PDF rendering verified at build time:', len(out), 'bytes')"

EXPOSE 8000
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
