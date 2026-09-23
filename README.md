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

**Phase P13 — the interface.** The eleven data contracts (P1), the
hash-chained audit log on SQLite (P2), configuration ingestion with deterministic
vendor detection (P3), the structural parser (P4), normalisation into the
Canonical Security Model (P5), the rule engine that evaluates it (P6), semantic
ACL analysis with an authenticated findings API (P7), the remediation resolver
with the report an operator reads (P8), the harness that measures all of it
against hand-authored ground truth (P9), the similarity layer that proposes
mappings for lines no pack recognises (P10), and the administrator confirmation
loop that turns one of those proposals into a permanent vendor-pack pattern
(P11), and the prioritisation stage that ranks findings by exposure and compares
each device against its peers (P12), and the React interface an operator
actually uses (P13) are in place.

The pipeline runs end to end: a configuration file goes in, and an
evidence-linked HTML report comes out, citing the exact lines it rests on. And
the accuracy of that pipeline is a measurement rather than a claim —
`make evaluate`, with the numbers in `eval/reports/evaluation.txt`.

The similarity layer clusters unrecognised lines and ranks up to three candidate
mappings. **It proposes; it never decides.** Every suggestion is uncalibrated, so
the field stays UNKNOWN until an administrator confirms the mapping.

**P11 closes the loop.** An administrator reads the queue one shape at a time,
confirms or corrects, and that recorded decision compiles into a deterministic
pattern in a new vendor-pack version:

```
residue → cluster → a human decides → compile → DRAFT → VALIDATED
        → activate → re-parse → the line is no longer unknown
```

Activation is explicit, admin-only, and takes effect without a restart. The
generated regex is deliberately boring — `logging host 192.0.2.10` becomes
`^logging\s+host\s+(\S+)$` — because an administrator who cannot read a pattern
cannot verify it, and their confirmation is permanent. They may edit it before
activating; the edit is re-validated and must still match the line it came from.

Every compiled pattern keeps the training example and audit sequence it came
from, so any mapping traces back to the person who confirmed it. A field read by
a learned pattern reports `admin_confirmed`, never `deterministic` — an operator
always knows which mappings NIRIKSHAK shipped and which this deployment learned.

**The queue works with no model installed**, which is the state of this
repository. It shows clusters ranked by frequency and says *why* there are no
suggestions. It never returns an empty list as though the model had run and found
nothing: those are opposite statements, and confusing them at the one screen
where a mistake becomes permanent is not a tolerable interface.

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

**A check may bound a value at both ends.** `NRK-TIMEOUT-001` asked only for
`lte: 600` and therefore passed `exec-timeout 0 0` — a management session that
never expires, the least secure setting the platform offers, reported as
compliant with a citation. `CheckSpec` now accepts `all_of`, a conjunction of
conditions over one field, and the rule asks for `gt 0 and lte 600`. One corpus
verdict moved; the 600 boundary still passes, so the value was bounded rather
than narrowed, and no evaluation-split device was affected. Conjunction only —
no disjunction, no negation, no nesting, because a rule needing disjunction is
two rules and an expression language here is where vendor logic would reappear.
DEF-8; see `docs/adr/0032-a-check-may-bound-a-value-at-both-ends.md`.

**The interface shows what the backend says, and says where it cannot.** The
P13 React application is a pure consumer: it never evaluates a rule, computes a
verdict, scores exposure or ranks a finding. Where a capability has no data it
renders the reason rather than an empty table — an empty list and a refusal are
different statements, and confusing them is how an operator concludes their
fleet is clean when nothing was measured.

**Prioritisation runs and abstains.** The Prioritise stage exists as of P12 and
produces no ranking on this corpus, because exposure needs interfaces and access
lists. Both are now read from Cisco IOS configurations, and the ACL analyser
reports shadowed, redundant and overly-permissive entries. Exposure still
abstains: nothing establishes which interface is the management plane, so
`exposure_score` and `priority_rank` stay `None`, the audit response names
`indeterminate_interfaces` as the blocker, and no severity-sorted list is offered
in their place — severity alone must not determine remediation order.

**Peer baselines now run.** Devices are grouped by platform and compared against
their own cohort. Until P15 the largest cohort held four devices against a floor
of five and nothing was established; the P15 corpus took it to nine, and **eight
baselines are computed with zero deviations**. A cohort still below the floor
carries an explanation and an outcome that is not `compared`, so an abstention
never reads as agreement. An abstaining field is never counted as an absent one:
a device we could not read is not a device without logging.

**The cohort is comparable, not representative.** Six of the nine Cisco devices
were written by one author in one sitting, and `edge-rtr-11.cfg` is a deliberate
near-twin of `edge-rtr-01.cfg` — it exists to test pattern reuse, not to add
fleet diversity. `SOURCING_BACKLOG.md` already warns that near-copies flatter a
peer-baseline figure, and this is that case: **zero deviations may be measuring
one author's habits rather than agreement between independently configured
devices.** Nothing here is evidence about real networks.

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

**Two stored findings cannot name the pack that read them.** A trained vendor
pack, `cisco/ios 1.1.5`, was deleted when contaminated patterns were reset, and
two audit runs on this deployment cite it. The files were recovered and committed
to `packs/archive/`, where each still verifies against its own checksum — so the
evidence exists and a person can read it. **The loader still cannot resolve the
version**, because every archived file declares itself active and reinstating one
would give a platform two active versions. Recorded as DEF-18; see
`docs/adr/0030-...` and `docs/adr/0031-a-durable-archive-for-superseded-packs.md`.

**PDF rendering does not work on the development machine.** HTML reporting is
complete and has no native dependency. The PDF endpoint needs the WeasyPrint/GTK
stack, which is absent here, and answers 503 naming the missing libraries rather
than substituting another engine or returning the HTML document under a `.pdf`
name. See `docs/adr/0006-weasyprint-gtk-probe.md`.

See `docs/CORPUS_PREREQUISITES.md` and `docs/SOURCING_BACKLOG.md`.

Held-out generalisation, top-3 mapping accuracy and confidence calibration
remain **unmeasured**, each for a reason recorded in `docs/adr/0017-similarity-layer.md`;
the PAN-OS holdout has still not been opened. `docs/ui_reference.html` remains
the untouched visual specification the P13 interface was translated from. See `docs/adr/` for the decisions taken so far,
and `docs/SOURCING_BACKLOG.md` for the six gaps that cannot be closed by writing
code.

---

## Requirements

- **Python 3.11** (3.11.9 verified). The project uses a local `.venv` and does
  not modify the system Python installation.
- **Node 18+** for the interface (Node 24 verified). Only needed to build or run
  the frontend; the API and the evaluation harness need nothing beyond Python.
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
uvicorn api.main:app --reload          # the API, on :8000
```

And the interface, in a second terminal:

```bash
cd ui
npm install
npm run dev                            # the UI, on :5173
```

The dev server proxies `/health`, `/ingest`, `/compliance`, `/fleet`, `/training`,
`/audit` and `/users` to the API, so the browser makes same-origin requests and no
API host is baked into the bundle. Sign in with an account created by
`scripts/create_admin.py`; **there is no self-registration**, and the role comes
from the server rather than from anything the login form offers.

```bash
cd ui
npm run typecheck && npm run lint && npm run test && npm run build
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
| GET | `/fleet/baseline` | Peer baselines and deviations | **admin** |
| GET | `/training/queue` | Unknown shapes, clustered and ranked | **admin** |
| POST | `/training/confirm` | Record one administrator decision | **admin** |
| POST | `/training/compile` | Compile it into a DRAFT pack version | **admin** |
| POST | `/training/activate` | Activate a validated pack — no restart | **admin** |
| POST | `/training/rollback` | Return a platform to an earlier pack | **admin** |
| GET | `/training/examples` | Decisions recorded so far | **admin** |
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

Full architecture: `docs/architecture.md`.

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
   field is routed to training. Never a guessed PASS or FAIL. Trust is created by
   an administrator's confirmation, never by a score.
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
| `packs/`    | Vendor packs — **data**. `builtin/` reviewed, `trained/` learned, `archive/` superseded and unloadable |
| `rules/`    | Compliance rules and framework mappings — **data**          |
| `snippets/` | Vetted remediation command library — **data**               |
| `corpus/`   | Sample configurations, ground-truth labels, held-out vendor |
| `eval/`     | Evaluation harness, ground-truth scoring, metrics reports    |
| `ui/`       | React + TypeScript + Tailwind interface (P13)                |
| `tests/`    | Unit, integration, golden and architecture tests            |
| `docs/`     | Specification, architecture, content policy, decision records |

Configuration data, rules, vendor packs and remediation snippets are kept
separate from application logic throughout.

---

## Specification

`docs/NIRIKSHAK_Concept_Report.pdf` is the product specification and the source
of truth. `DEVELOPER_GUIDE.md` defines the permanent implementation constraints.
