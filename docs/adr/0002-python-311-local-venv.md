# ADR 0002 — Python 3.11 with a project-local virtual environment

- **Status:** Accepted
- **Date:** 2026-08-26
- **Decision reference:** R2
- **Affects:** `pyproject.toml`, `Makefile`, `README.md`

## Context

The specified stack is Python 3.11. At the start of the project the development
machine had only Python 3.10.0 registered with the `py` launcher, installed at
`C:\Program Files\Python310` and first on `PATH`.

The gap matters for `tomllib`, exception groups and typing syntax, and a version
drift discovered during a demo is an expensive way to learn about it.

## Decision

NIRIKSHAK targets **Python 3.11**, pinned as `requires-python = ">=3.11,<3.12"`.

The project uses a **project-local `.venv`** created with `py -3.11 -m venv
.venv`. The system Python installation is neither replaced nor modified.

## Consequences

Python 3.11.9 was installed alongside 3.10.0 at
`C:\Users\megha\AppData\Local\Programs\Python\Python311` — a user-local install
that registers with the `py` launcher and leaves `C:\Program Files\Python310`
and the `PATH` default untouched. `python --version` outside the venv still
reports 3.10.0.

The upper bound `<3.12` is deliberate. It keeps the environment matching the
specification rather than drifting to whatever interpreter is newest, which
matters for reproducing published evaluation metrics.

All tooling resolves through `.venv`; the `Makefile` selects
`.venv/Scripts` on Windows and `.venv/bin` elsewhere. `.venv/` is gitignored.
