# NIRIKSHAK — Problem Statement 26155 compliance

Smart India Hackathon 2026 · PS 26155 · NTRO · Team Atlantis.
Derived from the code at commit `28ab52b`, the frozen submission build; `api/`,
`packs/`, `rules/`, `snippets/`, `corpus/` and `ui/` are unchanged since. Every
status below is backed by the file named beside it; nothing is claimed from
intention.

**Source of the clause wording.** The official statement is held verbatim in
`docs/PS26155_STATEMENT.md`, including the `â€”` encoding artefacts it arrived
with. Every clause below is quoted from it. An earlier version of this document
worked from the team's restatement in `docs/NIRIKSHAK_Concept_Report.pdf`; the
section *What the official wording changed* at the end lists every place the
official text moved an assessment.

Status key: **DELIVERED** — built, tested, observable. **PARTIAL** — built, with a
named gap. **ABSENT** — not built. **DEVIATION** — not done the way the statement
describes, on purpose, with the reason. Every PARTIAL and ABSENT states whether it
is blocked on **SOURCING** (material from outside the repository) or
**ENGINEERING** (work nobody is prevented from doing), and what closes it.

---

## Summary

| # | Clause (official wording, abridged) | Status |
| --- | --- | --- |
| B1 | Heterogeneous networks — firewalls & SASE, routers & switches, specialized networking | PARTIAL |
| B2 | Align devices with CIS Benchmarks, NIST SP 800-53, DISA STIGs, ISO/IEC 27001 | PARTIAL |
| H | Hardening the frameworks call for: disable Telnet/HTTP, strong cryptographic suites, granular ACLs, logging all administrative access | PARTIAL |
| C1 | Syntactic diversity — a 'secure password' setting on Cisco IOS vs Juniper SRX | PARTIAL |
| C2 | Scalability & adaptation — SONiC, cloud-native security groups, AI-driven infrastructure | PARTIAL |
| A1 | The AI-based engine performs Normalization and Deviation Analysis | DEVIATION |
| A2 | Dynamic Adaptation — learn to parse a new vendor's logic without backend code redeployment | PARTIAL |
| R1 | Unified Ingestion Engine — single or bulk files from any network device | DELIVERED |
| R2 | AI-Powered Training Module — train the system to parse unseen vendor formats | PARTIAL |
| R3 | Multi-Framework Compliance Engine — user-selected CIS / NIST / STIGs / ISO | PARTIAL |
| R4 | Actionable Intelligence & PDF Reporting — one PDF per device | PARTIAL |
| R5 | Vendor-Agnostic Scalability — new vendors, standards and OS versions without code modification | PARTIAL |
| V | "ideally designed to support any network device configuration, regardless of vendor or market segment" | PARTIAL |
| W1 | Workflow 1: normalise CLI into a structured JSON/Schema model | DELIVERED |
| W2 | Workflow 2: Netmiko or NAPALM for data collection | DEVIATION |
| W3 | Workflow 3: NLP or pattern matching for keywords not pre-trained on | DELIVERED |
| W4 | Workflow 4: ReportLab or FPDF, customised to model and software version | DEVIATION |

No clause is marked DELIVERED unless every part of it is. All five numbered
capabilities except R1 are PARTIAL.

---

## Background and the core challenge

### B1 — A heterogeneous estate. PARTIAL

*"The network environment includes, but is not limited to"* some forty named
vendors across firewalls & SASE, routers & switches, and specialized networking;
*"The aforementioned list is illustrative."*

Four platforms from three of those vendors are read, each by a vendor pack under
`packs/builtin/`: Cisco IOS (`cisco_ios/1.4.0.yaml`), Cisco NX-OS
(`cisco_nxos/1.0.0.yaml`), Juniper JunOS (`juniper_junos/1.2.0.yaml`) and Arista
EOS (`arista_eos/1.1.0.yaml`). The 19 non-holdout corpus files are routers,
switches and Juniper SRX firewalls (three `srx-*.conf` files), and all 19 are
detected (`corpus/MANIFEST.yaml`; detection in `api/ingest/vendor_detect.py`).

**Gap.** Of the named categories: cloud-native firewalls and security groups —
ABSENT, no pack and no sample, and a structured export needs the JSON syntax
mode, which is declared and not implemented (`api/parse/block_parser.py`,
`DEFERRED_MODE_PHASE`). Palo Alto — held out unopened for the generalisation
experiment (`corpus/holdout/panos/`). SASE, open/disaggregated (SONiC, Cumulus)
and physical infrastructure — no sample. *Blocked on:* SOURCING (real exports),
then ENGINEERING (the JSON and XML modes).

### B2 — The four frameworks. PARTIAL

*"Organizations are mandated to align these devices with rigorous security
frameworks, including CIS Benchmarks, NIST SP 800-53, DISA STIGs, and ISO/IEC
27001."*

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

### H — The hardening the statement names. PARTIAL

*"…such as disabling insecure protocols (Telnet/HTTP), enforcing strong
cryptographic suites, configuring granular ACLs, and logging all administrative
access."* Not in the team's restatement; assessed here because the official text
uses these four as its examples of what the frameworks require.

| Example | Status | Evidence |
| --- | --- | --- |
| Disable Telnet / HTTP | DELIVERED on Cisco IOS and NX-OS | `NRK-TELNET-001`, `NRK-HTTP-001` (`rules/canonical/`); both packs read `telnet_enabled` and `http_server_enabled`. JunOS and EOS read no canonical field, so both rules abstain there. |
| Strong cryptographic suites | ABSENT | `weak_ciphers` is in the canonical model (`CANONICAL_FIELD_NAMES`, `api/models/csm.py`), but no pack reads it and no rule checks it. |
| Granular ACLs | PARTIAL | Access lists are read and analysed by interval logic for shadowed, redundant and overly permissive entries (`api/analyse/`). These are observations, not compliance verdicts, and no rule requires an ACL on a management interface. |
| Logging all administrative access | ABSENT | `NRK-LOGGING-001` checks that a remote logging host is configured (`logging_hosts`, `non_empty`). Accounting of administrative sessions is not read and not checked. |

*Blocked on:* ENGINEERING for the cipher and accounting patterns on Cisco;
SOURCING (vendor documentation) for the other platforms.

### C1 — Syntactic diversity. PARTIAL

*"A 'secure password' setting in a Cisco IOS switch is syntactically distinct
from the same setting in a Juniper SRX firewall."*

Vendor syntax is mapped into one vendor-neutral model — 13 canonical fields
(`CANONICAL_FIELD_NAMES`, `api/models/csm.py`) — and the rule engine reads only
that model (`api/comply/engine.py`; `comply` may not import `parse`,
`tests/architecture/test_import_rules.py`). The block parser implements three
syntax modes — indentation, brace nesting, flat `set` paths
(`IMPLEMENTED_MODES`, `api/parse/block_parser.py`). OS version is extracted on
all four platforms (`identity` in each pack; `api/ingest/device_identity.py`).

**Gap.** The statement's own example is not demonstrable: `min_password_length`
is read by no pack, and the JunOS pack — which reads the three SRX files — reads
no canonical field at all. Coverage is uneven: IOS reads 8 fields, NX-OS 7,
JunOS and EOS none (`declared_fields`, `api/parse/fields.py`). XML and JSON modes
raise `UnsupportedSyntaxModeError` rather than returning an empty tree.
*Blocked on:* SOURCING (vendor documentation for JunOS/EOS field patterns; an
XML sample independent of the holdout), then ENGINEERING.

### C2 — Scalability and adaptation. PARTIAL

*"As organizations adopt 'White Box' networking (SONiC), Cloud-native security
groups (AWS/Azure), or specialized AI-driven infrastructure, traditional parsers
fail…"*

A new text-format platform is a new YAML vendor pack — detection signatures,
identity patterns and field patterns — loaded without a code change
(`api/ingest/packs.py`), and an existing pack is extended at runtime by the
training loop (A2).

**Gap.** None of the three named examples has a sample in the corpus.
Cloud-native security groups are JSON exports, and the JSON mode is not
implemented. *Blocked on:* SOURCING, then ENGINEERING.

---

## The AI-based engine

### A1 — "the AI-based engine will: Normalization … Deviation Analysis". DEVIATION

*"The requested solution is an AI-augmented, vendor-agnostic Compliance Engine.
Rather than relying on a hard-coded library of commands … the system will
employ Ai based approaches … to interpret configuration files."* The statement
then assigns Normalization and Deviation Analysis to that engine.

In NIRIKSHAK both are deterministic. Normalization is pattern matching from
vendor packs (`parse_configuration`, `build_csm`); Deviation Analysis is a rule
engine over the canonical model (`evaluate_device`, `api/comply/engine.py`). AI
is confined to proposing meanings for lines no pack recognises (A2), and cannot
reach a verdict: `comply` and `normalise` may not import `learn` or `train`
(`tests/architecture/test_import_rules.py`).

**Why.** A verdict must cite the configuration line it rests on and be
reproducible from the same input. A model's reading of a line can do neither,
and a confident wrong PASS is the one output a compliance tool must not produce
(DEVELOPER_GUIDE.md Rule 1; wrong-confident rate is the harness's safety metric,
`eval/`).

**What is true of "a hard-coded library of commands".** The vendor packs *are* a
library of patterns, and a judge should hear that from us. They are data, not
code: versioned YAML, checksum-verified on load, extended at runtime by the
training loop and activated without a restart (`api/train/`). What the
statement warns against — a library that goes stale with each firmware release —
is answered by making the library something an administrator extends, not by
removing it.

The statement's own example of Deviation Analysis is delivered on Cisco IOS:
*"checking if the parsed 'ssh_version' is '2' as required by CIS"* is
`NRK-SSH-001` (`ssh_version`, `equals 2`), mapped to CIS 2.1.1.2
(`project_asserted`), and the IOS pack reads `ssh_version`.

### A2 — Dynamic Adaptation, the 'Training' Loop. PARTIAL

*"…the administrator will be presented with the 'raw' unrecognized command
lines … will map these commands to specific security categories … The AI engine
will then update its internal heuristics, effectively 'learning' to parse this
new vendor's logic without requiring backend code redeployment."*

Delivered for platforms NIRIKSHAK already reads. Lines no pack matched become the
training queue (`record_residue`, `api/train/service.py`); they are clustered by
token shape and offered up to three ranked canonical fields
(`api/learn/cluster.py`, `MAX_SUGGESTIONS = 3` in `api/learn/suggest.py`). A
confirmation is chained to the audit log, compiled into an anchored pattern
(`compile_pattern`, `api/train/compile.py`) and activated without a restart
(`activate_draft`, `clear_pack_cache()`). "Update its internal heuristics"
happens in two places: the pack gains a deterministic pattern, and the
confirmation joins the labelled-example index the ranking searches
(`current_index`, `api/train/service.py`).

**Gap — a new vendor cannot be taught through this loop.** A file whose platform
is not detected answers 409 at audit ("no vendor pack applies",
`run_audit_endpoint`, `api/routers/audits.py`), so it never produces residue and
never reaches the queue; and `compile_confirmation` refuses when no active pack
exists for the platform ("a confirmation extends an existing platform
description and cannot create one"). A new vendor needs a hand-written YAML
pack with at least its detection signatures; after that, the loop extends it.
No code change is needed either way, but the first step is not in the GUI.
*Blocked on:* ENGINEERING (a pack-creation step in the training interface,
seeded from a file detection could not place).

**A deliberate difference.** Lines are shown with secrets scrubbed
(`raw_line_scrubbed`, `api/routers/training.py`), not raw: DEVELOPER_GUIDE.md §9 requires
scrubbing before any inference, and the queue is what the model reads.

---

## The five features

### R1 — Unified Ingestion Engine. DELIVERED

*"A dashboard for uploading single or bulk configuration files from any network
device."*

`POST /ingest/upload` (`api/routers/ingest.py`) accepts multiple files in one
request; ZIP archives are extracted with Zip-Slip and zip-bomb guards
(`api/ingest/archive.py`); the interface's file input is `multiple`
(`ui/src/pages/Devices.tsx`). Each file is validated (`api/ingest/validate.py`),
content-addressed (`api/ingest/blobs.py`) and fingerprinted by `detect_vendor`
(`api/ingest/vendor_detect.py`). A file from any device is accepted: one no pack
recognises is counted as UNKNOWN vendor rather than rejected (the batch summary,
`api/models/ingestion.py`), and a file that fails validation is recorded as
`FILE_REJECTED` without stopping the batch (`api/ingest/service.py`). Accepting a
file is not auditing it — see A2.

### R2 — AI-Powered Training Module. PARTIAL

*"A dedicated, intuitive GUI where administrators can 'train' the system to parse
unseen vendor formats by mapping specific command outputs to compliance
parameters."*

The GUI is the device's *Needs review* tab (`ui/src/components/device/Review.tsx`)
over `GET /training/queue`, `POST /training/confirm`, `/compile`, `/activate`,
`/rollback`, `/withdraw` (`api/routers/training.py`), with ranked suggestions
from `all-MiniLM-L6-v2` embeddings (`api/learn/embedding.py`).

**Gaps.** First, the one the official wording exposes: *unseen vendor formats*
cannot be trained — the loop extends a platform that already has a pack (A2).
Second, the ranking needs the optional `[ai]` extra and the model weights; on a
default install the screen works by hand and offers no suggestions. Third,
suggestions are never calibrated — every one is `UNCALIBRATED_SIMILARITY` — and
calibration is refused below 200 labelled samples (`MIN_CALIBRATION_SAMPLES`,
`api/learn/calibration.py`), which do not exist. *Blocked on:* ENGINEERING (pack
creation from the GUI); SOURCING (line-level ground truth, which accrues from
real administrator confirmations).

### R3 — Multi-Framework Compliance Engine. PARTIAL

*"A logic engine that evaluates configurations against user-selected benchmarks
(CIS, NIST, STIGs, ISO)."*

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

### R4 — Actionable Intelligence & PDF Reporting. PARTIAL

| Part (official wording) | Status | Evidence |
| --- | --- | --- |
| *"A comprehensive, single PDF report for each device"* | DELIVERED | `GET /compliance/audits/{id}/report.pdf` (`api/routers/reports.py`, `api/report/pdf.py`) — one document per audit run, rendered from the same template as the HTML report. Requires WeasyPrint and GTK3; answers 503 naming what is missing otherwise. |
| *"Device Identification: Including serial numbers …"* | ABSENT | A serial is inventory data from `show version`, not in a configuration export; the report states the reason rather than leaving a blank (`api/models/source_limits.py`, ADR 0044). |
| *"… and hardware details"* | PARTIAL | Hostname and OS version on all four platforms; hardware model on EOS only (`identity` in each pack; `api/ingest/device_identity.py`). |
| *"Clear 'Pass/Fail' results with risk severity assessments"* | DELIVERED | `Finding.status` and `base_severity` (`api/models/finding.py`), from `evaluate_device` (`api/comply/engine.py`). UNKNOWN and N/A are reported as themselves rather than folded into Pass/Fail. |
| *"Device-specific, step-by-step CLI command sequences"* | PARTIAL | 20 vetted snippets for Cisco IOS, JunOS and EOS, each an ordered command list with its rollback, impact and, where they apply, dependencies (`snippets/`, `api/remediate/resolver.py`). None for NX-OS; none for the EOS SSH-version rule, which EOS cannot express. |

*Blocked on:* serial — ENGINEERING (a second input type for `show` output, ADR
0044); model on other platforms and NX-OS remediation — SOURCING (vendor
documentation to vet commands against).

### R5 — Vendor-Agnostic Scalability. PARTIAL

*"A modular architecture designed to support new vendors, standards, and OS
versions without requiring manual code modifications for every update."*

Vendors: a new pack is YAML (`packs/`). Standards: a new framework edition is an
index file (`rules/frameworks/`), and a rule is YAML (`rules/canonical/`). A new
canonical field needs no code, since the model accepts any key
(`CANONICAL_FIELD_NAMES` is reference, not enforcement, `api/models/csm.py`).
Vendor-specific logic cannot reach the rule engine:
`tests/architecture/test_comply_boundaries.py` fails if `api/comply/` names any
vendor.

**Gaps.** New *file formats* (XML, JSON) need parser code. OS versions are
handled coarsely: a pack is keyed by vendor and OS family, and no pattern can be
scoped to an OS version (`PatternDef`, `api/models/pack.py`); framework editions
and snippets do carry version scope (`covers`; `os_version_range`). *Blocked
on:* SOURCING, then ENGINEERING.

### V — "ideally designed to support any network device configuration, regardless of vendor or market segment". PARTIAL

The official wording says *ideally designed*, which asks for a design that does
not close the door rather than for coverage of every device. What is true: four
packs read text configurations from Cisco, Juniper and Arista; any further
text-format platform is a YAML pack, not code; once a pack exists, the training
loop extends it from the interface; XML- and JSON-format devices — Palo Alto
and cloud security groups among them — need parser modes that are declared and
not built (`DEFERRED_MODE_PHASE`, `api/parse/block_parser.py`;
`docs/SOURCING_BACKLOG.md` gap 3).

---

## The suggested development workflow

The statement introduces these as *"can be visualized in the following stages"*
and names libraries with *"e.g."*.

**W1 — Normalization into a structured JSON/Schema model. DELIVERED.** The
canonical security model is a typed Pydantic contract (`CanonicalSecurityModel`,
`api/models/csm.py`); every field carries value, confidence and evidence.

**W2 — Netmiko or NAPALM for data collection. DEVIATION (ADR 0001).** Both open
live SSH sessions to devices. NIRIKSHAK audits configuration files exported
offline and never connects to a device, so it needs no production credentials
and can run inside an air-gapped network.
`tests/architecture/test_no_device_libraries.py` fails if any device-connection
library is imported.

**W3 — NLP or pattern matching for keywords not pre-trained on. DELIVERED.**
Both: token-shape clustering (`api/learn/signature.py`, `api/learn/cluster.py`)
and sentence embeddings (`api/learn/embedding.py`) over lines no pack matched.

**W4 — ReportLab or FPDF, customised to model and software version. DEVIATION
(ADR 0006, ADR 0015).** One Jinja2 template (`api/report/templates/report.html.j2`)
is rendered to HTML directly and to PDF by WeasyPrint (`api/report/pdf.py`), so
both formats are the same document and cannot drift apart; an architecture test
fails if `reportlab`, `fpdf` or four other PDF engines appear in `api/report/`.
The report prints the device's OS version on all four platforms and its model
where one was read (EOS only). The cost is a system dependency (GTK3),
documented in the README; HTML reporting works without it.

---

## What the official wording changed

Compared with the assessment made from the team's restatement:

1. **R2 and A2 — "unseen vendor formats", "this new vendor's logic".** The
   earlier version said the training loop could extend coverage to *further
   vendors*. It cannot: it extends a platform that already has a pack, and a file
   from an undetected vendor never reaches the queue. Status stays PARTIAL; the
   gap is now the first one named, and V was corrected.
2. **A1 — the AI-based engine performs Normalization and Deviation Analysis.**
   Not in the restatement. Recorded as a deliberate deviation with its reason.
3. **H — the four hardening examples.** Not in the restatement. Telnet/HTTP is
   delivered on Cisco; strong ciphers and logging of administrative access are
   not checked.
4. **C1 — the statement's own example** (a password setting on Cisco IOS versus
   Juniper SRX) is not demonstrable: no pack reads `min_password_length`.
5. **C2 — "indigenous hardware".** The earlier version listed it as a named
   example; the official text does not mention it. It names SONiC, cloud-native
   security groups and AI-driven infrastructure.
6. **V — "ideally designed … or market segment".** The quotation is now exact.
   *Ideally* makes the clause a design aim; the assessment stays PARTIAL.
7. **R5 — "OS versions".** Not assessed before; patterns cannot be scoped to an
   OS version.

---

## Submission deliverables — for judges

| Deliverable | Status | Where |
| --- | --- | --- |
| Source code link | Exists | `https://github.com/Meghanayenni/nirikshak`, `main` |
| README with setup | Exists | `README.md` — Setup, Running and the interface build verified from a fresh clone of `28ab52b` (`D:\nirikshak-clean`): suite 2,553 passed / 0 failed / 13 skipped; `npm run build` exit 0. The documentation commits since add one architecture test (`api/learn/` now bans `httpx`): 2,554 passed / 0 failed / 13 skipped |
| Architecture document (max 2 pages) | Exists | `docs/ARCHITECTURE_2PAGE.pdf`, two A4 pages, five diagrams; source `docs/ARCHITECTURE_2PAGE.html` (inline SVG, rendered by WeasyPrint). The full reference is `docs/architecture.md` |
| Demo video (max 2 minutes) | **To be produced by the team** | — |
| Technical presentation (max 5 slides) | **To be produced by the team** | — |

Supporting material: `docs/PS26155_STATEMENT.md` (the official statement),
`docs/NIRIKSHAK_Technical_Report.pdf` (full technical report), `docs/adr/` (60
decision records), `docs/SOURCING_BACKLOG.md` (every gap that code cannot close).
