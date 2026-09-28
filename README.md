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

**Vendor packs:** Cisco IOS, Cisco NX-OS, Juniper Junos, Arista EOS.

**Sourced compliance frameworks:** NIST SP 800-53 Rev 5 (5.2.0); DISA Cisco IOS
XE Router NDM STIG (V3R7); CIS Cisco IOS XE 17.x Benchmark (v2.2.1).

An administrator reads the training queue one unrecognised shape at a time,
confirms or corrects a mapping, and that recorded decision compiles into a
deterministic pattern in a new vendor-pack version:

```
residue → cluster → a human decides → compile → DRAFT → VALIDATED
        → activate → re-parse → the line is no longer unknown
```

Activation is explicit, admin-only, and takes effect without a restart. The
generated regex is deliberately boring — `logging host 192.0.2.10` becomes
`^logging\s+host\s+(\S+)$` — because an administrator who cannot read a pattern
cannot verify it, and their confirmation is permanent. They may edit it before
activating.

Every compiled pattern keeps the training example and audit sequence it came
from, so any mapping traces back to the person who confirmed it. A field read by
a learned pattern reports `admin_confirmed`, never `deterministic` — an operator
always knows which mappings NIRIKSHAK shipped and which this deployment learned.

A platform with no pack at all can be started from the interface: for a file no
pack claims, the bootstrap page shows what the file itself shows — its syntax
mode with the counts behind it, its comment style, and lines no known platform
uses — and never proposes a vendor name: the administrator supplies the name,
the file supplies the structure. Every derived value can be changed. The result
is a detection-only pack, activated through the same lifecycle as any other; the
training loop then fills it in.

The parser turns configuration text into a structural tree and applies a vendor
pack to it, producing canonical fields that each carry a value, a confidence and
evidence citing an exact line. Normalisation then resolves what an absent
directive means — the platform's documented default or the platform's
inexpressibility of that control — and builds the canonical model the
compliance engine consumes.

The compliance engine reads only the canonical model and produces PASS, FAIL,
UNKNOWN or NOT_APPLICABLE, each carrying the exact line it rests on or the
reason it abstained.

A device is scored per framework once its file has been fully reviewed. Per
framework, each control rolls up to fully satisfied, no violation found,
violated or undetermined, and the headline is a fraction of assessed controls
fully satisfied — for example "1 of 10 assessed controls fully satisfied" —
never a percentage.

An audit can be scoped to a selected benchmark: `POST /compliance/audits?file_id=…&framework=nist`
evaluates only the rules mapped to it, and the report names that scope and
shows each finding's mapped controls.

A finding shows the controls it maps to — framework, identifier, the edition it
was validated against, and *project asserted*, meaning the mapping is this
project's judgement rather than a published crosswalk.

Devices are grouped by platform and compared against their own peer cohort for
outlier detection.

The interface is a pure consumer of the API: it evaluates no rule, computes no
verdict, and scores no exposure itself.

Remediation is ordered for lockout risk, not just listed:
`GET /compliance/audits/{id}/remediation` returns a plan in application order,
and a change that could strand the operator outside the device they are fixing
sorts last. Every snippet carries its rollback and its preconditions, and the
report shows a command with both or not at all. Nothing is ever applied
automatically: the system recommends, and a human operator types the command.

Twenty vetted remediation snippets ship across Cisco IOS, Juniper Junos and
Arista EOS, each naming the person who checked it and the vendor document they
checked it against.

---

## Requirements

- **Python 3.11**. The project uses a local `.venv` and does not modify the
  system Python installation.
- **Node 18+** for the interface.
- **GTK3 runtime**, for PDF reporting.

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

# 3b. WeasyPrint, for PDF reports.
pip install -e ".[report]"

# 3c. For AI mapping suggestions (optional): the [ai] extra, then the model once.
pip install -e ".[ai]"
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"
```

**GTK3 on Windows**: install [MSYS2](https://www.msys2.org), run
`pacman -S mingw-w64-x86_64-pango mingw-w64-x86_64-cairo` in its shell, and add
`C:\msys64\mingw64\bin` to `PATH`.

---

## Running

Create the first administrator out-of-band, from the repository root with the
virtual environment active. It prompts twice for a password of at least 12
characters; there is no self-registration:

```bash
python scripts/create_admin.py --username alice
```

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
`scripts/create_admin.py`.

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
| GET | `/compliance/audits/{id}/report.pdf` | The same, as a PDF | user |
| GET | `/compliance/audits/{id}/remediation` | Plan, in application order | user |
| GET | `/compliance/audits/frameworks` | Sourced benchmarks, each edition and sha256 | public |
| GET | `/compliance/audits/frameworks/device/{file_id}` | Which benchmarks describe this device | user |
| GET | `/compliance/devices/{device_id}/posture` | Per-framework compliance posture | user |
| GET | `/ingest/files/{file_id}/lines` | Stored lines of a file you uploaded (evidence context) | user |
| GET | `/fleet/baseline` | Peer baselines and deviations | **admin** |
| GET | `/training/queue` | Unknown shapes, clustered and ranked | **admin** |
| POST | `/training/confirm` | Record one administrator decision | **admin** |
| POST | `/training/compile` | Compile it into a DRAFT pack version | **admin** |
| POST | `/training/activate` | Activate a validated pack — no restart | **admin** |
| POST | `/training/rollback` | Return a platform to an earlier pack | **admin** |
| POST | `/training/withdraw` | Withdraw a trained mapping | **admin** |
| GET | `/training/packs` | Pack inventory | **admin** |
| GET | `/training/examples` | Decisions recorded so far | **admin** |
| GET | `/audit/head` · `/audit/records` · `/audit/verify` | The hash chain | user |
| GET · POST | `/users`, `/users/{id}/disable` | Account management | **admin** |
| GET | `/users/me` | Who you are | user |

Everything except `/health` and `/compliance/audits/frameworks` requires
authentication (HTTP Basic). A user sees only what they uploaded and audited;
an admin sees the fleet.

`report.html` is one self-contained file — no external stylesheet, script or web
font — so it can be saved, mailed, or opened on a machine with no network.
`report.pdf` renders the same persisted run through WeasyPrint.

---

## Non-negotiable rules

1. **AI never issues a compliance verdict.** A deterministic rule engine reading
   the canonical model decides PASS, FAIL or UNKNOWN.
2. **Evidence is mandatory.** Every parsed security field carries value,
   confidence and evidence pointing at an exact file and line.
3. **Low confidence abstains.** Below threshold, the answer is UNKNOWN and the
   field is routed to training. Trust is created by an administrator's
   confirmation, never by a score.
4. **Remediation is never AI-generated.** Commands come only from the vetted
   snippet library, keyed by vendor, OS family and rule ID. Twenty snippets ship
   across Cisco IOS, Juniper Junos and Arista EOS, each naming the person who
   checked it and the vendor document they checked it against.
5. **Rules and vendor packs are data.** Adding a vendor, framework or OS version
   is a data change.
6. **Offline-first.** Local CPU inference, secrets scrubbed before any model
   call, no paid cloud API, configurations never need to leave the operator's
   network.

---

## Architecture in one paragraph

A deterministic spine does all the work that matters: parse, normalise,
evaluate, prioritise, remediate, report. A single advisory branch — the
similarity layer — proposes mappings for configuration lines no vendor pack
recognises. An administrator confirms or corrects them, and only that
confirmation compiles into a versioned vendor pack. The compliance engine's
only input is the typed Canonical Security Model, so neither raw configuration
text nor model output can reach a verdict.

---

## Specification

The NIRIKSHAK Concept Report is the product specification.
