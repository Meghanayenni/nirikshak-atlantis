# ADR 0006 — WeasyPrint requires a GTK runtime that this machine lacks

- **Status:** Accepted — environment requirement recorded; **R5 closed at P8**
- **Date:** 2026-08-26 (resolution appended 2026-08-27)
- **Decision reference:** R5 (closed — see *Resolution at P8* below)
- **Affects:** P8 (reporting), `README.md`, developer setup
- **Probe run at:** P0 step 8; **re-run at P8, unchanged**

## Context

Per-device PDF reporting is an explicit deliverable of Problem Statement 26155,
and the specified renderer is WeasyPrint with Jinja2.

WeasyPrint is pure Python but is **not self-contained on Windows**. From version
53 onward it lays out text through Pango, which is part of the GTK native
stack — a set of DLLs installed by a system installer, not by `pip`.

The risk was identified during planning as R5 and scheduled for an early probe
so the answer would be known eight phases before P8 depends on it, rather than
discovered the night before a demo.

## Probe

Read-only. No package installed, no library downloaded, no PATH modified.

```
python   : 3.11.9  (.venv)
platform : Windows-10-10.0.26200-SP0
machine  : AMD64
```

### Result — GTK is absent

Every required native library is missing. `ctypes.util.find_library` resolves
none of them:

| Library               | Status  | Role                          |
| --------------------- | ------- | ----------------------------- |
| `libgobject-2.0-0`    | MISSING | GObject — required            |
| `libpango-1.0-0`      | MISSING | Pango text layout — required  |
| `libpangoft2-1.0-0`   | MISSING | Pango FreeType — required     |
| `libharfbuzz-0`       | MISSING | HarfBuzz shaping — required   |
| `libfontconfig-1`     | MISSING | Fontconfig — required         |
| `libcairo-2`          | MISSING | Cairo                         |
| `libgdk_pixbuf-2.0-0` | MISSING | GdkPixbuf — raster images     |
| `libglib-2.0-0`       | MISSING | GLib — transitive             |

No GTK runtime is installed in any conventional location:
`C:\Program Files\GTK3-Runtime Win64\bin`, `C:\gtk\bin`,
`C:\msys64\mingw64\bin`, `%LOCALAPPDATA%\Programs\GTK3-Runtime Win64\bin` — all
absent.

The only PATH entry matching `mingw` is `C:\Program Files\Git\mingw64\bin`,
which ships with Git for Windows. Its 83 DLLs contain **no** GTK, Pango, GLib,
Cairo or Fontconfig library. (`libHarfBuzzSharp.dll` is present, but that is the
SkiaSharp .NET binding, unrelated to the HarfBuzz that Pango links against.)

### Render test — not executed

`weasyprint` is not installed; it belongs to the `[report]` extra, deferred to
P8 by design. Installing it was not authorised for this step, so the
minimal-PDF render was skipped. This does not weaken the finding: with the
native stack absent, WeasyPrint could not render here even once installed.

### Incidental observation — not a solution

A complete set of GTK-family DLLs exists inside `C:\Program Files\qemu\`
(`libgobject-2.0-0.dll`, `libpango-1.0-0.dll`, `libharfbuzz-0.dll`,
`libfontconfig-1.dll`, `libcairo-2.dll`, and others), bundled privately by QEMU.
That directory is **not** on `PATH`.

**This is recorded for completeness and explicitly rejected as an approach.**
Pointing WeasyPrint at another application's private DLL bundle would make PDF
reporting depend on an unrelated program's version, install location and
continued presence. It is not reproducible on a judge's machine, not
documentable as a setup step, and would fail silently if QEMU were updated or
removed. No such workaround was attempted.

## Decision

Record the GTK runtime as a **documented environment requirement** for PDF
reporting. Do not work around it.

## Consequences

**P0–P7 are unaffected.** WeasyPrint is not in the core dependency group, so
nothing before P8 touches it. The probe cost nothing and changed nothing.

**Before P8 can be completed, one of these must be chosen** — this is the open
half of R5 and remains a decision for the project owner:

1. **Install the GTK3 runtime for Windows** and add it to `PATH`. Restores the
   specified stack exactly, and setup becomes one documented step in the README.
   Recommended if PDF generation is to run on this machine.
2. **Generate reports under WSL2 or a container**, where the GTK stack installs
   from the system package manager without friction. Keeps the Windows host
   clean at the cost of a second environment.
3. **Substitute the PDF engine.** Deviates from the specified stack and would
   need its own ADR and justification. Not recommended without cause.

**README already reflects this**: the GTK3 runtime is listed under Requirements
as needed from P8 onward, and the `[report]` group is documented as installed at
P8 rather than P0.

**Judge-environment note.** Whatever is chosen must be reproducible from the
README on a clean machine, since a reviewer may well try. That constraint argues
for option 1 or 2 and against anything improvised.

---

## Resolution at P8 — R5 closed

**Appended 2026-08-27.** The probe above was re-run at P8, read-only, on the same
machine. **Nothing has changed:** all eight native libraries still resolve to
`MISSING`, none of the four conventional GTK directories exists, and `weasyprint`
is still not installed. The QEMU DLL bundle is still present and still rejected.

### What was decided

**None of the three options was taken as a precondition.** The engine was **not**
substituted — option 3 is explicitly not exercised, and an architecture test now
fails if `reportlab`, `fpdf`, `pdfkit`, `wkhtmltopdf`, `xhtml2pdf` or
`playwright` appears anywhere in `api/report/`.

Instead P8 was built so the choice between options 1 and 2 determines **when the
PDF endpoint returns bytes**, not whether reporting exists:

- **HTML reporting is complete and needs no GTK at all.** One self-contained
  document, no external stylesheet, script or web font. It works on this machine,
  on a judge's machine, and air-gapped.
- **PDF is a thin adapter behind a live probe.** `api/report/pdf.py` runs the
  same check this ADR ran, on every request, and raises
  `PdfBackendUnavailableError` naming the specific missing libraries and pointing
  back at this document.

`GET /compliance/audits/{id}/report.pdf` therefore answers **503** here, with a
message an operator can act on. It never returns the HTML document under a
`.pdf` name: `render_pdf` returns bytes or raises, and a test parses its AST to
require exactly one `return` statement.

The probe is deliberately **not cached** — GTK can be installed while the service
is running, and `/health` now carries a `pdf_reporting` block so the state is
visible without reading logs.

### What still has to happen for a PDF

Options 1 and 2 remain exactly as written above, and either will work
unmodified — installing the GTK3 runtime and restarting is sufficient, with no
code change and no configuration flag. The `[report]` extra is still uninstalled;
`make install-report` adds it.

Until then, the honest statement is: **NIRIKSHAK produces the report; this
machine cannot render it to PDF.** That is an environment gap, recorded here,
and not a missing capability in the product.

See ADR 0015 (decision D28) for the reporting design this resolution sits inside.

---

## Resolution, P17 — the runtime is present and the endpoint returns bytes

**Appended, not rewritten.** The reasoning above was right about the machine it
probed. The machine changed.

The GTK3 runtime is installed here through MSYS2. Probed directly:

```
libgobject-2.0-0    -> C:\msys64\mingw64\bin\libgobject-2.0-0.dll
… eight of eight resolved …
weasyprint installed: True
```

`GET /compliance/audits/{id}/report.pdf` returns **200** with
`application/pdf`. A report for `corpus/cisco/dev/sw-access-02.cfg` renders to
**seven A4 pages**, 48,666 bytes, carrying seven findings, two failures with
their cited configuration lines, and five disclosures.

So the sentence this ADR closed on — *"NIRIKSHAK produces the report; this
machine cannot render it to PDF"* — is no longer true, and had not been true for
some time while three documents went on repeating it.

### What kept the code honest while the prose went stale

This ADR's own decision: *"the probe is the same one ADR 0006 ran, kept in code
rather than in prose so it re-runs on every request instead of describing a
machine from August."*

That is exactly what happened. The probe re-ran and reported availability
correctly on every request. Four tests carrying
`skipif(availability().available)` began skipping and kept skipping. **Nothing
was broken.** What went wrong is that the documents asserted an environment fact
as a permanent one, and no test asserted the *positive* path — so a passing
suite and a working endpoint could sit beside three documents saying it was
blocked, indefinitely.

A live probe protects the behaviour. It does not protect the claims made about
the behaviour, and those need their own assertion.

### What changed in P17

- `api/report/pdf.py` probes **platform-appropriate library names**.
  `find_library("libpango-1.0-0")` returns `None` on Linux *with Pango
  installed* — it adds the `lib` prefix and `.so` suffix itself — so the Windows
  DLL names recorded above would report a complete stack as entirely missing.
  The **set** of eight components is unchanged; only the spelling varies by
  platform, and a test pairs the two lists positionally. See ADR 0039 (D103).
- A positive assertion exists at both levels: `render_pdf` returning `%PDF-`
  bytes, and the endpoint returning `application/pdf` from a persisted run.
  Both skip where GTK is absent, which remains correct.
- `Dockerfile` installs the runtime so the endpoint works regardless of host,
  and fails the build rather than shipping an image that answers 503. It has
  **not been built** — no Docker daemon on this machine (ADR 0039).

### What is unchanged

Every decision. WeasyPrint only; no second engine; no headless browser; no HTML
under a `.pdf` name; `render_pdf` returns bytes or raises and an AST test
enforces the single `return`. The 503 path is still the correct behaviour where
the runtime is absent, still names the missing libraries, and is still tested —
on a machine without GTK, which this one is not.

---

## Note on the title — appended at the submission pass

The title still reads *"WeasyPrint requires a GTK runtime that this machine
lacks"*, and the P17 resolution above records that the machine no longer lacks
it. **The title is left as written.** It was an accurate description of the
machine probed at P0 and again at P8, and the reasoning built on it — probe
live, never cache, answer 503 naming what is missing, never substitute an engine
— was right for that machine and is still in force.

Read the title as dated: *"this machine"* means the development machine as it
stood on 2026-08-26 and 2026-08-27. The current state is not in this ADR at all;
it is whatever `api/report/pdf.py` reports on the machine you are using, on
every request, and `/health` carries it under `pdf_reporting`.
