# NIRIKSHAK — Problem Statement 26155 compliance

Smart India Hackathon 2026 · PS 26155 · NTRO · Team Atlantis.
Derived from commit `28ab52b`, the frozen submission build. Every status below is
backed by the file named beside it; nothing is claimed from intention.

**Source of the clause wording.** The official PS 26155 text is not held in this
repository. Clauses are taken from the team's restatement of it in
`docs/NIRIKSHAK_Concept_Report.pdf` §1 (Background, *The two hard parts*, and
*What the problem statement explicitly asks for*), and from the two further
clauses quoted by the team: *"support any network device configuration,
regardless of vendor"*, and the suggested workflow's naming of Netmiko/NAPALM
and ReportLab/FPDF. A judge holding the official text should read these as the
team's reading of it.

Status key: **DELIVERED** — built, tested, observable. **PARTIAL** — built, with a
named gap. **ABSENT** — not built. Every PARTIAL and ABSENT states whether it is
blocked on **SOURCING** (material from outside the repository) or
**ENGINEERING** (work nobody is prevented from doing), and what closes it.

---

## Summary

| # | Clause | Status |
| --- | --- | --- |
| B1 | Heterogeneous estate — routers, switches, firewalls, cloud security groups | PARTIAL |
| B2 | Compliance with CIS, NIST SP 800-53, DISA STIG, ISO/IEC 27001 | PARTIAL |
| C1 | Syntactic diversity | PARTIAL |
| C2 | Scalability and adaptation — learn a new vendor without code redeployment | PARTIAL |
| R1 | Unified ingestion engine — single and bulk, any device | DELIVERED |
| R2 | AI-powered training module — GUI to map unseen syntax | PARTIAL |
| R3 | Multi-framework compliance engine — user-selected CIS / NIST / STIG / ISO | PARTIAL |
| R4 | Actionable intelligence and PDF reporting | PARTIAL |
| R5 | Vendor-agnostic scalability without code modification | PARTIAL |
| V | "Support any network device configuration, regardless of vendor" | PARTIAL |
| W1 | Suggested workflow: Netmiko / NAPALM | Deliberate deviation |
| W2 | Suggested workflow: ReportLab / FPDF | Deliberate deviation |

No clause is marked DELIVERED unless every part of it is. Four of the five
numbered requirements are PARTIAL, as at the last audit; none has drifted upward.

---

## Background and core challenge

### B1 — A heterogeneous estate. PARTIAL

Four platforms are read, each by a vendor pack under `packs/builtin/`: Cisco IOS
(`cisco_ios/1.4.0.yaml`), Cisco NX-OS (`cisco_nxos/1.0.0.yaml`), Juniper JunOS
(`juniper_junos/1.2.0.yaml`) and Arista EOS (`arista_eos/1.1.0.yaml`). Routers,
switches and firewalls are among the 19 non-holdout corpus files, all 19
detected (`corpus/MANIFEST.yaml`; detection in `api/ingest/vendor_detect.py`).

**Gap.** Cloud security groups: ABSENT — no pack and no corpus sample. A
structured export would need the JSON syntax mode, which is declared and not
implemented (`api/parse/block_parser.py`, `DEFERRED_MODE_PHASE`). PAN-OS firewalls: held out
unopened for the generalisation experiment (`corpus/holdout/panos/`). *Blocked
on:* SOURCING (a real security-group export) then ENGINEERING (the JSON mode).

### B2 — The four frameworks. PARTIAL

Three are sourced and selectable, each pinned by its source's sha256
(`rules/frameworks/*.index.yaml`): NIST SP 800-53 Rev 5 edition 5.2.0 (8
controls mapped, from all 7 rules); DISA Cisco IOS XE Router NDM STIG V3R7 (4 of
42 requirements, from 3 rules); CIS Cisco IOS XE 17.x Benchmark v2.2.1 (6 of 84
recommendations, from 6 rules). Every mapping is `project_asserted`
(`rules/canonical/*.yaml`, enforced by `tests/unit/test_framework_mappings.py`).

**Gap.** ISO/IEC 27001 is ABSENT from the selector, by design: it is a purchased
standard and no catalog is held. STIG and CIS describe Cisco IOS XE 17.x only
(`covers` in each index), so they apply to 2 of the 19 corpus devices. *Blocked
on:* SOURCING (the ISO standard; editions for other platforms).

### C1 — Syntactic diversity. PARTIAL

Vendor syntax is mapped into one vendor-neutral model — 13 canonical fields
(`CANONICAL_FIELD_NAMES`, `api/models/csm.py`) — and the rule engine reads only
that model (`api/comply/engine.py`; `comply` may not import `parse`,
`tests/architecture/test_import_rules.py`). The block parser implements three
syntax modes — indentation, brace nesting, flat `set` paths
(`IMPLEMENTED_MODES`, `api/parse/block_parser.py`).

**Gap.** XML and JSON modes raise `UnsupportedSyntaxModeError` rather than
returning an empty tree. Canonical coverage is uneven: IOS reads 8 fields, NX-OS
7, JunOS and EOS none (`api/parse/fields.py`, `declared_fields`). *Blocked on:*
SOURCING (an XML sample independent of the holdout; vendor documentation for
JunOS/EOS field patterns), then ENGINEERING.

### C2 — Learn a new vendor without backend code redeployment. PARTIAL

The confirmation loop turns an administrator's decision into a new vendor-pack
version at runtime: `confirm` → `compile_confirmation` → `activate_draft` in
`api/train/service.py`, which calls `clear_pack_cache()` so the next parse uses
the new pack with no restart. Patterns are compiled by
`compile_pattern` (`api/train/compile.py`); packs move DRAFT → VALIDATED →
ACTIVE (`api/train/activation.py`). A new text-format vendor is a new YAML pack,
not code.

**Gap.** A vendor whose export is XML or JSON cannot be taught this way: the
structural parser for those formats does not exist (C1). *Blocked on:*
SOURCING, then ENGINEERING. SONiC and new indigenous hardware have no sample in
the corpus.

---

## The five required capabilities

### R1 — Unified ingestion engine. DELIVERED

`POST /ingest/upload` (`api/routers/ingest.py`) accepts multiple files in one
request; ZIP archives are extracted with Zip-Slip and zip-bomb guards
(`api/ingest/archive.py`); the interface's file input is `multiple`
(`ui/src/pages/Devices.tsx`). Each file is validated (`api/ingest/validate.py`),
content-addressed (`api/ingest/blobs.py`) and fingerprinted by
`detect_vendor` (`api/ingest/vendor_detect.py`). A file no pack recognises is
accepted and counted as UNKNOWN vendor rather than rejected (the batch summary,
`api/models/ingestion.py`); a file that fails validation is recorded as
`FILE_REJECTED` and does not stop the rest of the batch
(`api/ingest/service.py`).

### R2 — AI-powered training module. PARTIAL

The GUI is the device's *Needs review* tab (`ui/src/components/device/Review.tsx`)
over `GET /training/queue`, `POST /training/confirm`, `/compile`, `/activate`,
`/rollback`, `/withdraw` (`api/routers/training.py`). Unknown lines are clustered
by token shape (`api/learn/cluster.py`, `api/learn/signature.py`) and each
cluster is offered up to three ranked candidate fields (`MAX_SUGGESTIONS = 3`,
`api/learn/suggest.py`) from `all-MiniLM-L6-v2` embeddings
(`api/learn/embedding.py`).

**Gap.** The ranking needs the optional `[ai]` extra and the model weights; on a
default install the mapping screen works by hand and offers no suggestions.
Suggestions are never calibrated — every one is `UNCALIBRATED_SIMILARITY` — and
calibration is refused below 200 labelled samples
(`MIN_CALIBRATION_SAMPLES`, `api/learn/calibration.py`), which do not exist.
*Blocked on:* SOURCING (line-level ground truth, which accrues from real
administrator confirmations).

### R3 — Multi-framework compliance engine. PARTIAL

User selection works end to end: `GET /compliance/audits/frameworks/device/{id}`
lists the sourced frameworks and whether each describes the device
(`device_framework_options`, `api/comply/frameworks.py`); the interface renders it
(`ui/src/components/device/BenchmarkScope.tsx`); `POST /compliance/audits?framework=`
evaluates only rules mapping to the selection, reports every rule left out as
*not assessed* with its reason, and answers 409 when no selected edition
describes the device (`scope_selection`, `api/comply/frameworks.py`;
`run_audit_endpoint`, `api/routers/audits.py`). The same device fails
`NRK-HTTP-001` under STIG (`CISC-ND-000470`) and is not assessed under CIS, which
records that it never requires the HTTP server disabled
(`rules/canonical/NRK-HTTP-001.yaml`, `not_mapped`).

**Gap.** As B2: ISO absent; STIG and CIS scoped to IOS XE 17.x. *Blocked on:*
SOURCING.

### R4 — Actionable intelligence and PDF reporting. PARTIAL

| Part | Status | Evidence |
| --- | --- | --- |
| Device identification | PARTIAL | Hostname and OS version on all four platforms; hardware model on EOS only (`identity` in each pack; `api/ingest/device_identity.py`). |
| Serial number | ABSENT | A serial is inventory data from `show version`, not in a configuration export; recorded as an input limit (`api/models/source_limits.py`, ADR 0044). |
| Pass/fail with risk severity | DELIVERED | `Finding.status` and `base_severity` (`api/models/finding.py`), from `evaluate_device` (`api/comply/engine.py`). |
| Device-specific CLI remediation | PARTIAL | 20 vetted snippets for Cisco IOS, JunOS and EOS, each with rollback (`snippets/`, `api/remediate/resolver.py`). None for NX-OS; none for the EOS SSH-version rule, which EOS cannot express. |
| A single PDF per device | DELIVERED | `GET /compliance/audits/{id}/report.pdf` (`api/routers/reports.py`, `api/report/pdf.py`) — one document per audit run, rendered from the same template as the HTML report. Requires WeasyPrint and GTK3; answers 503 naming what is missing otherwise. |

*Blocked on:* serial — ENGINEERING (a second input type for `show` output, ADR
0044); model on other platforms and NX-OS remediation — SOURCING (vendor
documentation to vet commands against).

### R5 — Vendor-agnostic scalability. PARTIAL

Vendor packs and rules are YAML (`packs/`, `rules/canonical/`); a new pack version
is written and activated at runtime (C2); a new framework edition is an index
file (`rules/frameworks/`); a new canonical field needs no code, since the model
accepts any key (`CANONICAL_FIELD_NAMES` is reference, not enforcement,
`api/models/csm.py`). Vendor-specific logic cannot reach the rule engine:
`tests/architecture/test_comply_boundaries.py` fails if `api/comply/` names any
vendor.

**Gap.** New *file formats* (XML, JSON) need parser code. *Blocked on:* SOURCING,
then ENGINEERING.

### V — "Support any network device configuration, regardless of vendor". PARTIAL

What is true: four packs read text configurations — Cisco IOS, Cisco NX-OS,
Juniper JunOS and Arista EOS; the training loop extends coverage to further
text-format vendors as data, without code changes; XML-format vendors, PAN-OS
among them, need an XML parser, which waits on an XML sample that does not
compromise the PAN-OS holdout (`DEFERRED_MODE_PHASE`,
`api/parse/block_parser.py`; `docs/SOURCING_BACKLOG.md` gap 3).

---

## The suggested workflow, and two deliberate deviations

The statement's workflow names libraries *by example*. Neither pair is used.

**W1 — Netmiko / NAPALM (ADR 0001).** Both are live-device access libraries: they
open SSH sessions to routers. NIRIKSHAK audits configuration files exported
offline and never connects to a device. The architecture forbids live access,
and `tests/architecture/test_no_device_libraries.py` fails if any
device-connection library is imported. Offline operation is what lets the tool
run inside an air-gapped network without credentials to production devices.

**W2 — ReportLab / FPDF (ADR 0006, ADR 0015).** The report is one Jinja2 HTML
template (`api/report/templates/report.html.j2`) rendered to HTML directly and to
PDF by WeasyPrint (`api/report/pdf.py`), so both formats are the same document
and cannot drift apart. A second engine would be a second copy of the layout; an
architecture test fails if `reportlab`, `fpdf` or four other PDF engines appear
in `api/report/`. The cost is a system dependency (GTK3), documented in the
README, and HTML reporting works without it.

---

## Submission deliverables — for judges

| Deliverable | Status | Where |
| --- | --- | --- |
| Source code link | Exists | `https://github.com/Meghanayenni/nirikshak`, `main` at `28ab52b` (remote and local match) |
| README with setup | Exists | `README.md` — Setup, Running and the interface build verified from a fresh clone (`D:\nirikshak-clean`): suite 2,553 passed / 0 failed / 13 skipped; `npm run build` exit 0 |
| Architecture document (max 2 pages) | Exists | `docs/ARCHITECTURE_2PAGE.pdf`, two A4 pages, five diagrams; source `docs/ARCHITECTURE_2PAGE.html` (inline SVG, rendered by WeasyPrint). The full reference is `docs/architecture.md` |
| Demo video (max 2 min) | **To be produced by the team** | — |
| Technical presentation (max 5 slides) | **To be produced by the team** | — |

Supporting material: `docs/NIRIKSHAK_Technical_Report.pdf` (full technical
report), `docs/adr/` (60 decision records), `docs/SOURCING_BACKLOG.md` (every
gap that code cannot close).
