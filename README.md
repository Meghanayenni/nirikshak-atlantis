# NIRIKSHAK

A self-learning, vendor-agnostic network security compliance auditor.

Smart India Hackathon 2026 · Problem Statement 26155 · National Technical
Research Organisation (NTRO) · Team Atlantis

NIRIKSHAK ingests network device configuration files, normalises vendor-specific
syntax into a vendor-neutral security schema, evaluates that schema against
compliance frameworks with a deterministic rule engine, and produces
evidence-linked findings with vetted, device-specific remediation.

```
Ingest → Parse → Normalise → Comply → Prioritise → Remediate → Report
```

When it meets a structure it does not recognise, it does not guess. It asks the
administrator, and permanently learns the answer.

---

## Status

**Phase P2 — audit hash chain.** The eleven data contracts (P1) and the
hash-chained audit log on SQLite (P2) are in place. Parsing begins at P4.
See `docs/adr/` for the decisions taken so far.

---

## Requirements

- **Python 3.11** (3.11.9 verified). The project uses a local `.venv` and does
  not modify the system Python installation.
- **Node 18+** for the interface, from P13 onward. Not needed before then.
- **GTK3 runtime** for PDF reporting, from P8 onward. Not needed before then —
  see `docs/adr/0006-weasyprint-gtk-probe.md`.

---

## Setup

```bash
# 1. Create the project-local virtual environment
py -3.11 -m venv .venv

# 2. Activate it
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux / macOS

# 3. Install the core and development dependencies
pip install -e ".[dev]"

# 4. Verify
pytest
ruff check .
```

Dependency groups are installed as the phases need them:

| Group      | Installed at | Contents                                        |
| ---------- | ------------ | ----------------------------------------------- |
| *(core)*   | P0           | FastAPI, parsing, YAML, schema validation       |
| `[dev]`    | P0           | pytest, ruff                                    |
| `[report]` | P8           | WeasyPrint (plus the system GTK3 runtime)       |
| `[ai]`     | P10          | sentence-transformers, torch (CPU), FAISS       |

The machine-learning stack is deliberately deferred so the first nine phases
install quickly and stay within the 8 GB target hardware budget.

---

## Running

```bash
uvicorn api.main:app --reload
```

Endpoints so far:

| Method | Path | Purpose |
| ------ | ---- | ------- |
| GET | `/health` | Liveness and safety-relevant settings |
| GET | `/audit/head` | Current chain head |
| GET | `/audit/records` | Filtered history (never a verification claim) |
| GET | `/audit/verify` | Verify the chain |

The audit surface is **read-only by design**. Records are appended by the
services that perform the actions, never by an HTTP caller.

## Verifying the audit log

```bash
python scripts/verify_audit_chain.py          # 0 ok · 1 failed · 2 unreadable
python scripts/verify_audit_chain.py --json
make verify-audit
```

The verifier imports no web framework, so integrity can be checked without
trusting — or even running — the interface it polices.

> **Tamper-evident, not tamper-proof.** The chain detects record modification,
> deletion, reordering, broken links and accidental corruption. It does *not*
> detect an attacker with unrestricted database write access who recomputes the
> complete unkeyed chain. See `docs/adr/0008-chain-authenticity-limits.md`.

---

## Architecture in one paragraph

A deterministic spine does all the work that matters: parse, normalise,
evaluate, prioritise, remediate, report. A single advisory branch — the
similarity layer — proposes mappings for configuration lines no vendor pack
recognises. **Those proposals are not facts.** An administrator confirms or
corrects them, and only that confirmation compiles into a versioned vendor
pack. The compliance engine's only input is the typed Canonical Security Model,
so neither raw configuration text nor model output can reach a verdict.

Full architecture: `docs/architecture.md` (written at P14).

---

## Non-negotiable rules

These come from `DEVELOPER_GUIDE.md` and are enforced by tests in
`tests/architecture/`, not by convention.

1. **AI never issues a compliance verdict.** A deterministic rule engine reading
   the canonical model decides PASS, FAIL or UNKNOWN.
2. **Evidence is mandatory.** Every parsed security field carries value,
   confidence and evidence pointing at an exact file and line. No evidence, no
   claim.
3. **Low confidence abstains.** Below threshold, the answer is UNKNOWN and the
   field is routed to training. Never a guessed PASS or FAIL.
4. **Remediation is never AI-generated.** Commands come only from the vetted
   snippet library, keyed by vendor, OS family and rule ID.
5. **Rules and vendor packs are data.** Adding a vendor, framework or OS version
   is a data change.
6. **Offline-first.** Local CPU inference, secrets scrubbed before any model
   call, no paid cloud API, configurations never need to leave the operator's
   network.

## Deliberately not built

No live device access. No network scanning. No automatic remediation. No
model-generated production CLI. No configuration chatbot. No model fine-tuning.

NIRIKSHAK operates on offline configuration exports and requires no device
credentials. This is enforced by dependency choice and lint rule, not policy —
see `docs/adr/0001-no-live-device-access.md`.

---

## Repository layout

| Path        | Contents                                                    |
| ----------- | ----------------------------------------------------------- |
| `api/`      | Python backend (FastAPI)                                    |
| `packs/`    | Vendor packs — **data**, how vendor syntax maps to canonical |
| `rules/`    | Compliance rules and framework mappings — **data**          |
| `snippets/` | Vetted remediation command library — **data**               |
| `corpus/`   | Sample configurations, ground-truth labels, held-out vendor |
| `eval/`     | Evaluation harness and metrics reports                      |
| `ui/`       | React + Tailwind interface (from P13)                       |
| `tests/`    | Unit, integration, golden and architecture tests            |
| `docs/`     | Specification, architecture, content policy, decision records |

Configuration data, rules, vendor packs and remediation snippets are kept
separate from application logic throughout.

---

## Specification

`docs/NIRIKSHAK_Concept_Report.pdf` is the product specification and the source
of truth. `DEVELOPER_GUIDE.md` defines the permanent implementation constraints.
