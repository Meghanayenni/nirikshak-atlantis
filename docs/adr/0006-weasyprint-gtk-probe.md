# ADR 0006 — WeasyPrint requires a GTK runtime that this machine lacks

- **Status:** Accepted — environment requirement recorded
- **Date:** 2026-08-26
- **Decision reference:** R5 (open)
- **Affects:** P8 (reporting), `README.md`, developer setup
- **Probe run at:** P0 step 8

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
