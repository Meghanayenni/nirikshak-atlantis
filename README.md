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

**Phase P10 — the similarity layer.** The eleven data contracts (P1), the
hash-chained audit log on SQLite (P2), configuration ingestion with deterministic
vendor detection (P3), the structural parser (P4), normalisation into the
Canonical Security Model (P5), the rule engine that evaluates it (P6), semantic
ACL analysis with an authenticated findings API (P7), the remediation resolver
with the report an operator reads (P8), and the harness that measures all of it
against hand-authored ground truth (P9), and the similarity layer that proposes
mappings for lines no pack recognises (P10) are in place.

The pipeline runs end to end: a configuration file goes in, and an
evidence-linked HTML report comes out, citing the exact lines it rests on. And
the accuracy of that pipeline is a measurement rather than a claim —
`make evaluate`, with the numbers in `eval/reports/evaluation.txt`.

The similarity layer clusters unrecognised lines and ranks up to three candidate
mappings. **It proposes; it never decides.** Every suggestion is uncalibrated, so
the field stays UNKNOWN until an administrator confirms the mapping — the
confirmation workflow itself is P11.

The parser turns configuration text into a `ConfigTree` and applies a vendor pack
to it, producing canonical fields that each carry a value, a confidence and
evidence citing an exact line. Normalisation then resolves what every **absent**
directive means — the platform's documented default, a control the platform
cannot express, or an honest UNKNOWN — and builds the canonical model the
compliance engine will consume.

The Cisco IOS pack reads eight canonical fields; every other pack is still
detection-only, which is an honest state rather than a placeholder — the platform
is recognised, and every field it cannot read says UNKNOWN.

The compliance engine reads only the canonical model and produces PASS, FAIL,
UNKNOWN or NOT_APPLICABLE, each carrying the exact line it rests on or the reason
it abstained.

### What is deliberately not claimed

**No platform defaults ship.** Absence-aware evaluation is entirely data-driven,
and no vendor documentation has been sourced, so every absent field resolves to
UNKNOWN rather than to a manufactured default. The engine is built and tested
against synthetic packs; populating it is a data change requiring a real citation.

**No framework control mappings ship.** Every rule has `frameworks: []`. Writing
a CIS, NIST, DISA STIG or ISO/IEC 27001 identifier without having read the
benchmark would be inventing it, so NIRIKSHAK currently evaluates its own checks
and maps them to nothing. **No claim of coverage against any of those four
frameworks is made or supported by this repository.**

**The corpus is synthetic and small.** Two Cisco development devices are enough to
validate the *evaluator*; they are not enough to validate a *rule*.

**No ACL parsing coverage.** The corpus contains no access control lists at all,
so the semantic ACL analyser — shadowed, redundant and overly permissive entries,
by interval logic — is tested against constructed model objects and has never seen
a parsed one. No detection rate against real access lists is claimed.

**Similarity scores are not confidence, and no calibrator is fitted.** Every
suggestion carries `UNCALIBRATED_SIMILARITY`, which forces the field to UNKNOWN
regardless of score. Fitting a calibrator needs labelled score outcomes that do
not exist, and the fitter refuses below a sample floor the corpus cannot reach.
No similarity number in this system may be read as a probability.

**Held-out generalisation and top-3 accuracy are not measured.** The similarity
layer exists, so that is no longer the obstacle. The metric is defined over the
held-out vendor's commands, reading them needs a parser for its format, and that
parser waits on a sample independent of the held-out files — building it from
them would destroy the experiment. **The holdout has never been opened.**

**Evaluation results are synthetic-corpus results.** Every configuration in
`corpus/` is hand-written, so the harness scores the parser against its author's
imagination rather than against the field. The numbers are real measurements of a
synthetic sample and **are not real-world accuracy.**

**The ground-truth labels are not independent.** They are unreviewed, and the
Cisco labels were written by the author of the Cisco parsing patterns — so
correlated error between parser and ground truth is not visible in the Cisco
figures. The label files declare this, and the report prints it. Arista and
Juniper carry no such conflict, because no parsing pattern exists for either.

**No remediation commands ship.** The vetted snippet library is **empty**. Rule 4
requires commands come from that library, and `docs/CONTENT_POLICY.md` requires
each one cite the vendor document it was checked against — so a snippet cannot
exist without a person who read a document and checked the commands. No vendor
documentation has been sourced. Every failing finding in every report therefore
reads *"No vetted remediation is available for this platform and rule."* The
loader, resolver, dependency ordering and report integration are built and tested
against constructed fixtures; **none has ever handled a real snippet.**

**PDF rendering does not work on the development machine.** HTML reporting is
complete and has no native dependency. The PDF endpoint needs the WeasyPrint/GTK
stack, which is absent here, and answers 503 naming the missing libraries rather
than substituting another engine or returning the HTML document under a `.pdf`
name. See `docs/adr/0006-weasyprint-gtk-probe.md`.

See `docs/CORPUS_PREREQUISITES.md` and `docs/SOURCING_BACKLOG.md`.

Held-out generalisation, top-3 mapping accuracy and confidence calibration
remain **unmeasured**, each for a reason recorded in `docs/adr/0017-similarity-layer.md`;
the PAN-OS holdout has still not been opened. The administrator training workflow
is P13's interface over P11's confirmation loop. Exposure-aware prioritisation and
peer-baseline detection are P12. See `docs/adr/` for the decisions taken so far,
and `docs/SOURCING_BACKLOG.md` for the six gaps that cannot be closed by writing
code.

---

## Requirements

- **Python 3.11** (3.11.9 verified). The project uses a local `.venv` and does
  not modify the system Python installation.
- **Node 18+** for the interface, from P13 onward. Not needed before then.
- **GTK3 runtime** for PDF reporting only. **Not required for HTML reporting**,
  which is the complete report and needs nothing beyond the core dependencies.
  Without GTK the `.pdf` endpoint answers 503 and names what is missing — see
  `docs/adr/0006-weasyprint-gtk-probe.md`.

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
| `[report]` | P8, optional | WeasyPrint (plus the system GTK3 runtime)       |
| `[ai]`     | P10, optional| sentence-transformers, torch (CPU), FAISS       |

The machine-learning stack is deliberately deferred so the first nine phases
install quickly and stay within the 8 GB target hardware budget.

---

## Running

```bash
uvicorn api.main:app --reload
```

Endpoints so far:

| Method | Path | Purpose | Auth |
| ------ | ---- | ------- | ---- |
| GET | `/health` | Liveness and safety-relevant settings | public |
| POST | `/ingest/upload` | Upload configurations | user |
| GET | `/ingest/files` | Files you uploaded (admins: all) | user |
| GET | `/ingest/devices` | Devices you uploaded (admins: all) | user |
| GET | `/ingest/stats` | Fleet-wide cache effectiveness | **admin** |
| POST | `/compliance/audits` | Audit one file; persists the result | user |
| GET | `/compliance/audits` | Your audit runs (admins: all) | user |
| GET | `/compliance/audits/{id}` | One run's summary | user |
| GET | `/compliance/audits/{id}/findings` | Findings with evidence | user |
| GET | `/compliance/audits/{id}/report.html` | Evidence-linked report | user |
| GET | `/compliance/audits/{id}/report.pdf` | The same, or 503 (see below) | user |
| GET | `/compliance/audits/{id}/remediation` | Plan, in application order | user |
| GET | `/audit/head` · `/audit/records` · `/audit/verify` | The hash chain | user |
| GET · POST | `/users`, `/users/{id}/disable` | Account management | **admin** |
| GET | `/users/me` | Who you are | user |

**Everything except `/health` requires authentication** (HTTP Basic). A user sees
only what they uploaded and audited; an admin sees the fleet. A resource you may
not see answers 404, not 403 — 403 would confirm the id exists.

The `/audit/*` chain surface is **read-only by design**. Records are appended by
the services that perform the actions, never by an HTTP caller. `/compliance/audits`
is a different resource and does accept POST.

### Reports

`report.html` is one self-contained file — no external stylesheet, script or web
font — so it can be saved, mailed, or opened on a machine with no network.

`report.pdf` requires WeasyPrint and the system GTK3 runtime. Where either is
absent it returns **503** listing the missing native libraries. It never falls
back to HTML under a `.pdf` name and never substitutes a different PDF engine;
`GET /health` reports whether this machine can render one.

Every failing finding carries either a vetted command or the sentence *"No vetted
remediation is available for this platform and rule."* There is no third
possibility: commands are read from `snippets/` and never generated.

Create the first administrator out-of-band:

```bash
python scripts/create_admin.py --username alice
```

## Measuring accuracy

```bash
make evaluate                 # score, and write eval/reports/evaluation.txt
python -m eval.run            # print only
```

The harness scores the **evaluation split only** against labels in
`corpus/labels/`. It refuses to score development files — that would measure
memorisation — and it cannot open the held-out vendor at all: a sealed-split
guard raises before any file handle is opened.

Ground truth is authored by reading the raw configuration, never from parser
output. Each label cites a line number and that line's verbatim text, and the
loader refuses any label whose citation has drifted from the file.

It exits non-zero only when the measurement cannot be made honestly, never
because a number is low. See `eval/reports/README.md`.

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
   snippet library, keyed by vendor, OS family and rule ID. That library is
   currently empty, so no command is offered for anything.
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
| `eval/`     | Evaluation harness, ground-truth scoring, metrics reports    |
| `ui/`       | React + Tailwind interface (from P13)                       |
| `tests/`    | Unit, integration, golden and architecture tests            |
| `docs/`     | Specification, architecture, content policy, decision records |

Configuration data, rules, vendor packs and remediation snippets are kept
separate from application logic throughout.

---

## Specification

`docs/NIRIKSHAK_Concept_Report.pdf` is the product specification and the source
of truth. `DEVELOPER_GUIDE.md` defines the permanent implementation constraints.
