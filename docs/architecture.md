# NIRIKSHAK — Architecture

Self-learning, vendor-agnostic network security compliance auditor.
Smart India Hackathon 2026 · Problem Statement 26155 · NTRO · Team Atlantis.

This document describes the system **as it stands at P14**, not as it was
planned. Where a capability is built but has no data to run on, that is stated
here as plainly as the capability itself — because on this build the difference
between *"the check passed"* and *"the check could not be made"* is most of what
NIRIKSHAK is for.

The specification is `docs/NIRIKSHAK_Concept_Report.pdf`. The permanent
implementation constraints are in `DEVELOPER_GUIDE.md`. The reasoning behind individual
choices is in `docs/adr/`; this document is the map, not the argument.

---

## 1. What the system does, in one paragraph

NIRIKSHAK reads network device configuration files that were exported offline,
normalises vendor-specific syntax into a vendor-neutral security schema,
evaluates that schema against declarative compliance rules with a deterministic
engine, and produces findings that each cite the exact configuration line they
rest on. When it meets a line no vendor pack recognises, it does not guess: it
asks an administrator, and compiles their confirmed answer into a versioned
vendor pack so the next parse recognises it deterministically.

**AI suggests. Rules decide.**

---

## 2. The pipeline

The deterministic spine does all the work that produces a verdict:

```
  Ingest  ->  Parse  ->  Normalise  ->  Comply  ->  Prioritise  ->  Remediate  ->  Report
     |          |            |            |             |              |             |
  detect     ConfigTree     CSM        Finding      exposure       snippet        HTML
  vendor,    + residue   (typed,      (PASS/FAIL/   (abstains      lookup       document
  hash,      per pack    evidence-     UNKNOWN/     without ACL    (library     with cited
  store                  bearing)      N/A)         + interface    is empty)      lines
                             |                       data)
                             |
                        residue (lines no pack matched)
                             |
                             v
              +----------------------------------+
              |   ADVISORY BRANCH — not a verdict |
              |                                    |
              |   learn   cluster, embed, rank     |
              |     |     top-3 candidate fields   |
              |     v                              |
              |   HUMAN   administrator confirms   |
              |     |     or corrects              |
              |     v                              |
              |   train   compile -> DRAFT ->      |
              |           VALIDATED -> ACTIVE      |
              +----------------------------------+
                             |
                    a new vendor pack version
                             |
                             v
                    re-parse: the line is now
                    matched DETERMINISTICALLY
```

**The advisory branch is beside the pipeline, never inside it.** `api/learn/`
produces `Suggestion` objects that carry no value — only a proposed *meaning* for
a line — and every one leaves the package marked `UNCALIBRATED_SIMILARITY`, which
the contract treats as forcing the field to UNKNOWN regardless of the number
attached. A suggestion reaches a verdict by exactly one route: a human confirms
it, it becomes pack **data**, and the deterministic parser matches it on the next
run.

That is a structural property, not a convention. `comply` may not import `learn`
or `train`; `normalise` may not import `learn` or `train`; a `Suggestion` has no
`value` field to promote. See §5.

---

## 3. The six rules, and where each is enforced

DEVELOPER_GUIDE.md states six non-negotiable rules. Each is enforced by a test or a
contract, not by intention.

| Rule | Enforced by |
| --- | --- |
| **1. AI never issues a compliance verdict** | 75 forbidden import edges in `tests/architecture/test_import_rules.py`, of which `comply -> learn`, `comply -> train`, `normalise -> learn`, `normalise -> train` and `report -> learn` carry the weight. Plus: `Suggestion` has no `value` field; `assert_never_confidence()` raises at the package boundary; the audit database has `CHECK (actor_type <> 'model' OR action = 'ai_suggested')` below Python. |
| **2. Evidence is mandatory** | `Field` construction. A PRESENT field without evidence cannot be built. Comment prefixes and literal blocks never become parse nodes, so a commented-out directive cannot produce a PRESENT field. |
| **3. Low confidence abstains** | The `ConfidenceMethod` split. Populations are floored separately: `deterministic` and `admin_confirmed` are exactly 1.0 or nothing; `platform_default` has its own floor and is always marked INFERRED; only `calibrated_similarity` is compared against `confidence_threshold`. `UNCALIBRATED_SIMILARITY` forces UNKNOWN whatever the score. |
| **4. Remediation is never AI-generated** | `remediate -> learn`, `remediate -> train` and `prioritise -> remediate` are forbidden edges. Commands are read from `snippets/` and never synthesised. `RemediationSnippet` requires `vetted_by` and `reference`, and a content-policy test refuses a vetter whose name looks automated. |
| **5. Rules and vendor packs are data** | `packs/` and `rules/` are YAML. A new pack version is written at runtime by `api/train/` and activated without a restart — `clear_pack_cache()` makes the next parse use it in the same process. |
| **6. Offline-first** | No device library may be imported (`tests/architecture/test_no_device_libraries.py`). No network client in `ingest`, `parse`, `learn`, `train` or `prioritise`. Secrets are scrubbed before any text reaches an embedding model. `settings.airgap` makes the model loader fail closed rather than fetch. |

---

## 4. Packages and responsibilities

Fifteen packages under `api/`, 110 modules.

| Package | Responsibility |
| --- | --- |
| `models/` | The typed contracts everything else speaks. A **leaf**: it may import nothing else from `api/`, so no forbidden edge can be satisfied transitively through it. |
| `security/` | Password hashing (scrypt) and secret scrubbing before inference. |
| `db/` | SQLite connections, forward-only checksum-verified migrations, and the row-level stores. |
| `audit/` | The append-only hash chain: append, read, verify. Records events; never judges them. |
| `ingest/` | Upload, validation, format and vendor detection, line hashing and the fleet line cache, device identity extraction, vendor-pack loading and checksum verification. |
| `parse/` | Text to `ConfigTree`; applies a pack's patterns to produce `FieldMatch` objects and the **residue** — every node no pattern matched. |
| `normalise/` | `ParseResult` to `CanonicalSecurityModel`. Decides what an **absent** directive means, and scrubs residue for the training queue. |
| `comply/` | The deterministic rule engine. Reads the canonical model and nothing else; emits `Finding` objects. |
| `analyse/` | Semantic ACL analysis by interval logic — shadowed, redundant, overly permissive. Observations, not verdicts. |
| `prioritise/` | Exposure assessment and peer baselines. Ranks findings when exposure can be determined, and abstains when it cannot. |
| `remediate/` | Resolves a vetted snippet for a failing finding, or states that none exists. |
| `report/` | Renders a persisted run as a self-contained HTML document with its own disclosures. |
| `learn/` | The advisory branch: token-shape clustering, the labelled-example index, embedding adapter, top-3 retrieval, calibration machinery. Proposes; never decides. |
| `train/` | The confirmation loop: queue, pattern compiler, pack lifecycle, and the audit records for each. The only package permitted to compose `learn` with storage. |
| `routers/` | The HTTP surface. Performs the I/O and the authorisation checks; the layers below stay free of both. |

### Forbidden boundaries

**75 forbidden import edges**, asserted by `tests/architecture/test_import_rules.py`,
distributed by source package:

```
  analyse 8 · audit 3 · comply 9 · ingest 6 · learn 8 · normalise 6
  parse 6 · prioritise 10 · remediate 8 · report 7 · train 4
```

The shape of the argument is always the same: **a layer that decides must not be
able to see the layer that suggests, and a layer that suggests must not be able to
reach the layer that decides.** `comply` cannot import `parse` (no vendor syntax
reaches a verdict), `learn` cannot import `db` (the advisory branch cannot
persist), `prioritise` cannot import `comply` (a ranking layer that could see
verdict logic could start disagreeing with it), and `analyse` may import
`api.models` and nothing else.

Fourteen further architecture test files guard the same properties from other
angles: no ML library outside `learn`, no network capability, no vendor literal
in a vendor-neutral layer, no raw configuration line in the training queue, and
no path from the evaluation harness into any pipeline package.

---

## 5. One audit, end to end

A single request, `POST /compliance/audits?file_id=...`, traverses the whole
spine. Each arrow is a typed contract.

1. **Read** — the stored blob is fetched by its content hash.
2. **Parse** — `parse_configuration(text, pack)` builds a `ConfigTree`, applies
   the pack's patterns, and returns a `ParseResult` carrying `fields`, the
   `pack_version` that actually read them, and `residue`.
3. **Identity** — `extract_identity()` reads hostname, model, OS version and
   serial from the raw lines using the pack's `identity` patterns.
4. **Normalise** — `build_csm()` resolves what every **absent** field means:
   the platform's documented default, a control the platform cannot express, or
   an honest UNKNOWN. It emits a `CanonicalSecurityModel`.
5. **Evaluate** — `evaluate_device(csm, rulepack)` produces one `Finding` per
   applicable rule: PASS, FAIL, UNKNOWN or NOT_APPLICABLE, each carrying the
   evidence it rests on or the reason it abstained.
6. **Analyse** — `analyse_device(csm)` runs ACL interval logic on a separate
   rail from findings.
7. **Prioritise** — `prioritise(csm, findings, rulepack)` assesses exposure per
   finding and ranks only what it could determine.
8. **Persist** — the run and its findings are written to the operational store.
9. **Queue** — residue is recorded as the durable training queue, replacing that
   file's previous entries.
10. **Attest** — an `AUDIT_RUN` record is appended to the hash chain: counts,
    identifiers and versions only.
11. **Report** — `report.html` is regenerated from the persisted run on request,
    never stored as a second copy that could drift.

Every finding carries a `FindingProvenance`: engine version, rulepack version and
the vendor pack versions that read the lines. A verdict is reproducible only if
the data that produced it is identified.

---

## 6. Two databases, deliberately separate

```
  operational store              audit store
  ------------------             -----------
  config_file, config_line       audit_log
  line_cache, device             audit_chain_head
  ingestion, app_user            schema_migrations
  audit_run, finding
  finding_evidence
  unknown_line, training_example
```

**The operational store holds configuration-derived content. The audit store
holds attestations about it, and nothing else** (decision D4). The chain records
*that* an audit ran, over which device, with which rulepack and how many findings
of each verdict — never a value, never a raw line. Keeping them in separate files
makes that claim checkable by opening one.

`audit_log` is append-only, enforced by database triggers rather than by
convention. Each record binds the hash of its payload to the hash of the record
before it, so a retroactive edit anywhere breaks verification everywhere after.
`audit_chain_head` is a singleton that detects deletion of the chain's tail, which
the links alone cannot.

**The chain is tamper-evident, not tamper-proof.** It detects record
modification, deletion, reordering, broken links and accidental corruption. It
does *not* detect an attacker with unrestricted database write access who
recomputes the complete unkeyed chain (ADR 0008).

Evidence is stored as **pointers**, not copies: `(file_id, line_number)` resolves
through `config_line` and `line_cache` to the exact stored text, so a report
quotes the operator's own file rather than a transcription that could drift.

---

## 7. What NIRIKSHAK does not currently claim

This section is the most important one in the document. Every item is a
capability that is **built and tested** but has no data to run on. The machinery
is real; the output is an honest refusal.

| Not claimed | Why |
| --- | --- |
| **Coverage against CIS, NIST SP 800-53, DISA STIG or ISO/IEC 27001** | Every rule ships an empty framework list. Writing an identifier without having read the benchmark would be inventing it. |
| **Absence-aware evaluation accuracy** | No platform default and no capability claim ships, so the `EVALUATE` branch has never fired on real data. |
| **Exposure scores or a priority ranking** | Interfaces and access lists are read, and `interface_roles` now exists for a pack to declare which names are management-plane (ADR 0034) — but **no pack declares one**, because no vendor documentation has been sourced. Exposure stays indeterminate. Severity alone must not determine remediation order, so no severity-sorted list is offered in its place. |
| **Held-out generalisation** | Blocked: the metric is defined over the held-out vendor's commands, reading them needs an XML parser, and that parser waits on a sample independent of the holdout. |
| **Top-3 mapping accuracy or a calibrated confidence** | No line-level ground truth exists, and no calibrator is fitted. Every similarity score is a ranking, never a probability. |
| **Real-world accuracy** | Every corpus file is hand-written by one author. The harness measures a synthetic sample honestly; that is not field accuracy. |
| **Independent ground truth** | The labels are unreviewed, and the Cisco labels share an author with the Cisco parsing patterns. |

Three items have since left this table.

**ACL analysis.** The P7 interval analyser produced nothing until P16, because
`build_csm` returned `acls=()` unconditionally and no extractor existed. It now
reports overly-permissive, redundant and shadowed entries on real corpus
configurations — and reports **none** on a deliberately clean list, which is the
result that shows it is reading rather than pattern-matching for alarm. It is
still measured on synthetic data written by this team, so no detection *rate* is
claimed; what changed is that the machinery has run on a parsed access list at
all. See ADR 0027.

**Two dialects now, across two vendors.** P17 added JunOS firewall filters in
flat `set` form (ADR 0033), where a list has no block header and one term spans
several top-level lines — so the dialect table dispatches on the extraction
*shape*, not only on the entry grammar. The corpus tally is **4 access lists
analysed, 0 dropped**.

The brace-nested form of the same JunOS filters is **not** read, and the blocker
is upstream: vendor detection does not identify a brace-nested file at all, so
`corpus/juniper/dev/core-rtr-01.conf` never reaches a pack. A reader for it
could be written today and nothing would call it, which is a declaration no test
could show right or wrong. The blocker is pinned by a test that is expected to
fail when detection is fixed.

**Peer-baseline outliers.** Until P15 every cohort held fewer than the five
devices a baseline needs, so none was established. Registering the P15 corpus
took the Cisco IOS cohort to nine and **eight baselines are now computed**, with
zero deviations. That zero is a result rather than an abstention, and the fleet
response distinguishes them: a cohort below the floor carries an explanation and
an outcome that is not `compared`, while these were compared and agreed. Two
files are reported as skipped rather than silently dropped — `dc1-leaf-01.cfg`
is NX-OS and `core-rtr-01.conf` is brace-nested JunOS, and neither has an active
pack.

**The cohort is comparable, not representative.** Six of the nine Cisco devices
were written by one author in one sitting, and `edge-rtr-11.cfg` is a deliberate
near-twin of `edge-rtr-01.cfg` — it exists to test pattern reuse, not to add
fleet diversity. `SOURCING_BACKLOG.md` already warns that near-copies flatter a
peer-baseline figure, and this is that case: **zero deviations may be measuring
one author's habits rather than agreement between independently configured
devices.** Nothing here is evidence about real networks.

The vetted snippet library
shipped empty until every entry could name the person who checked it
and the vendor document they checked it against; twenty snippets covering
three platforms now satisfy both, and `tests/architecture/test_remediate_boundaries.py` asserts those two
properties directly rather than asserting that no snippet exists. A rule with no
snippet for a platform still resolves to nothing and says so — the Arista SSH
protocol-version rule is the live example, because EOS exposes no such setting
and inventing one would be worse than abstaining.

All eight trace to the eight entries in `docs/SOURCING_BACKLOG.md`:

1. ACL-bearing configurations
2. Vendor capability and default documentation
3. XML samples that do not compromise the PAN-OS holdout
4. Framework control-ID sources
5. Broader vendor and configuration diversity
6. Vendor remediation documentation
7. Line-level ground truth for the similarity layer
8. A corpus written by more than one author

**None can be closed by writing code**, and none may be closed by inventing data.

---

## 8. The sealed holdout

One vendor — **PAN-OS** — is held out entirely for the generalisation experiment.
Two files under `corpus/holdout/panos/` are recorded in `corpus/MANIFEST.yaml`
with `split: holdout`.

**They have never been opened.** Not read, not hashed, not parsed, at any point
in any phase. The seal is structural rather than procedural:

- The evaluation harness raises before a file handle is opened for a held-out
  split.
- PAN-OS has no active vendor pack, and `build_tree(..., mode=XML)` raises
  `UnsupportedSyntaxModeError` rather than returning an empty tree — so a
  held-out file cannot enter the pipeline even by accident.
- Architecture tests scan `api/learn/`, `api/train/` and `api/prioritise/` for the
  path fragments `holdout/`, `corpus/holdout`, `panos` and `paloalto`, with
  docstrings stripped first: explaining the rule is expected, constructing a path
  is not.
- Tests that must reason about splits skip holdout manifest entries **before any
  read**, and a helper that would receive one asserts against it.

The reason is single-use: once those files have been studied to build a parser,
top-3 accuracy on them measures memory rather than generalisation. The experiment
can be run once, and it has not been spent.

---

## 9. Defect register

Eighteen numbered defects. **Three are open.**

| # | Description | Status |
| --- | --- | --- |
| DEF-1 | Two distinct classes both named `DeviceIdentity`; an ambiguous import returned the wrong one | Fixed (ADR 0012) |
| DEF-2 | `management_interfaces()` folded undocumented status into "not management" | Fixed (ADR 0012) |
| **DEF-3** | **`device_id` is the configuration file's content hash, so it identifies *this configuration* rather than the physical device across time** | **OPEN** |
| DEF-4 | `on_capability_unknown` was configurable and could have turned every abstention into a pass | Fixed (ADR 0013) |
| DEF-5 | README misattributed exposure prioritisation to P7 | Fixed (ADR 0014) |
| DEF-6 | Evaluation harness defect | Fixed (ADR 0016) |
| DEF-7 | FAIL precision and recall undefined for the class that matters most | Closed by D32 (ADR 0016) |
| DEF-8 | `NRK-TIMEOUT-001` passed `exec-timeout 0 0` — a session that never expires was reported as compliant | Fixed (ADR 0032) |
| DEF-9 | Arista pack did not declare `!` as a comment prefix; 23 of 57 residue lines were comments | Fixed (ADR 0017) |
| DEF-10 | Field provenance hard-coded `BUILTIN`, so a learned mapping would claim to be vendor-shipped | Fixed (ADR 0019) |
| DEF-11 | Pack versions ordered by string comparison; `1.0.10` sorted below `1.0.9` | Fixed (ADR 0020) |
| DEF-12 | `packs/trained/` was defined and read by nothing | Fixed (ADR 0019, 0020) |
| DEF-13 | Pack checksums were declared and never verified against file bytes | Fixed (ADR 0020) |
| DEF-14 | `POST /compliance/audits` never appended `AUDIT_RUN` to the chain | Fixed (ADR 0021) |
| DEF-15 | Detected device identity never reached the canonical model in the live pipeline | Fixed (ADR 0021) |
| **DEF-16** | **The confirmation loop does not know about corpus splits, so an administrator working the Needs-review queue can compile a pattern from a file reserved for measuring the parser** | **OPEN** |
| DEF-17 | Two patterns asserting different values for one field collapsed to UNKNOWN, so a device whose weakest vty line enables telnet reported no FAIL | Fixed (ADR 0026) |
| **DEF-18** | **Deleting a trained pack orphans every stored finding that cites it — two audit runs on this deployment can no longer name the pack that read them** | **OPEN** — evidence secured (ADR 0031) |

### Why the remaining defects are open

**DEF-3** — fixing it means redefining `device_id`, which every `Finding`, every
`audit_run` row, every report and the P9 evaluation already carry. Changing it
would move a measurement, and no phase since P5 has been the right place to do
that. P12 examined whether peer baselines needed it and found they do not: the
comparison is cross-sectional (*forty-seven switches now, three switches now*),
not longitudinal. The real consequence is recorded rather than hidden — **a
configuration re-uploaded after an edit counts as a second device** in its cohort.
Nothing anywhere presents a content hash as a stable device identity: the report
names its field `config_file_id`, and the interface labels devices by hostname.

**DEF-18** — `audit_run.pack_versions` points into `packs/trained/`, so removing
a trained pack silently orphans every finding produced by it. D67 removed the
contaminated admin-trained patterns at P15 on the reasoning that the directory is
gitignored deployment state; that is true of the repository and false of the
database beside it.

Restoring is not a one-line fix. The archived file carries `status: active`, so
returning it would give the platform two active versions and the loader would
fail closed, correctly (D46). Making it resolvable needs an archive the
activation scan never reads — a change to how pack storage is organised, with its
own decision. Until then a finding exists that cannot name the pack that read it,
which is the property the version field exists to provide. See ADR 0030.

**The evidence is no longer at risk, and the defect is unchanged.** ADR 0031
committed the ten recovered pack files to `packs/archive/`, outside every pack
root, each still verifying against its own declared checksum — so the bytes that
read those two runs are in the repository rather than in a scratch directory.
Nothing resolves a version *through* that directory: a human can open the file, a
loader cannot. The repair — a version resolvable for provenance and ineligible
for activation, plus a `pack_versions` column that is keyed by `pack_id` rather
than by vendor, so `cisco/ios` and `cisco/nxos` cannot collide in it — is still
open.

**DEF-16** — found at P15 by the corpus-policy suite, which reported that two
admin-trained patterns in the active Cisco pack had been compiled from
`edge-rtr-11.cfg` — a file whose entire purpose is to be a regression fixture
nobody authors from. Nobody misused the interface: an administrator uploaded a
configuration, worked the queue and confirmed what the lines meant, which is the
loop doing its job.

The loop has no notion of a corpus split, and for an arbitrary operator upload it
cannot have one — most deployments have no corpus. In *this* repository the same
files serve as evaluation data, so the loop can silently contaminate the
measurement the parser is judged by. The trained patterns were reset (D67) and
the contamination is gone, but nothing prevents it recurring. A guard belongs
with the training workflow and needs its own ADR, so it is recorded rather than
patched in a corpus commit.

**DEF-8 is fixed** (ADR 0032). `CheckSpec` gained `all_of`, a conjunction of
conditions over one field, and `NRK-TIMEOUT-001` now asks for
`gt 0 and lte 600`. `corpus/cisco/dev/edge-rtr-09.cfg` moved from PASS to FAIL
and every other verdict in the corpus is unchanged, including the 600 boundary —
so the value was bounded rather than narrowed. No evaluation-split device carries
`exec-timeout 0 0` inside the vty scope, so the harness figures did not move.

Conjunction only: no `any_of`, no negation, no nesting. A rule needing
disjunction is two rules. That line is what keeps a closed operator set from
becoming an expression language, which is where vendor logic and model calls
would reappear inside a layer built to have neither.

---

## 10. Decision index

Eighty-eight numbered decisions across 34 ADRs. (D63 and D64 were never issued; the
count is of decisions recorded, not of the highest number reached.)

| ADR | Phase | Subject | Decisions |
| --- | --- | --- | --- |
| 0001 | P0 | No live device access; Netmiko and NAPALM removed | — |
| 0002 | P0 | Python 3.11 with a project-local virtual environment | — |
| 0003 | P0 | Specification filename standardised | — |
| 0004 | P0 | NIRIKSHAK-owned hierarchical block parser | — |
| 0005 | P0 | Conservative approach to framework content | — |
| 0006 | P0 | WeasyPrint requires a GTK runtime this machine lacks | — |
| 0007 | P2 | Audit hash chain on SQLite | D1, D2 |
| 0008 | P2 | The audit log is tamper-evident, not tamper-proof | — |
| 0009 | P3 | Configuration ingestion and vendor detection | D3, D4, D5 |
| 0010 | P3 | Corpus policy and evaluation separation | R9 |
| 0011 | P4 | Structural parsing and the first Cisco parsing pack | D6, D7, D8, D9 |
| 0012 | P5 | Normalisation, and what an absent directive means | D10, D11, D12, D13, D14 |
| 0013 | P6 | Deterministic compliance evaluation | D15, D16, D17, D18, D19 |
| 0014 | P7 | Semantic ACL analysis, findings persistence, protected API | D20, D21, D22, D23, D24, D25 |
| 0015 | P8 | Remediation resolution and evidence-linked reporting | D26, D27, D28, D29, D30 |
| 0016 | P9 | The evaluation harness, and what it is allowed to claim | D31, D32, D33, D34, D35, D36 |
| 0017 | P10 | The similarity layer, and what it is not allowed to conclude | D37, D38, D39, D41, D42, D43 |
| 0018 | P10 | The embedding model is an environment prerequisite | D40 |
| 0019 | P11 | The confirmation loop, and where trust originates | D44, D48, D49, D50 |
| 0020 | P11 | Pack activation, and a checksum that finally checks something | D45, D46, D47, D51 |
| 0021 | P12 | The Prioritise stage, and the ranking it declines to produce | D52, D53, D54, D55, D56, D57 |
| 0022 | P13 | The interface, and what it refuses to draw | D58, D59, D60, D61, D62 |
| 0023 | P14 | This document | — |
| 0024 | P15 | Corpus registration, and a training loop that could contaminate its own evaluation | D65, D66, D67, D68 |
| 0025 | P15 | Presence assertion in the training form, and what happens when two lines disagree | D69, D70 |
| 0026 | P16 | Per-field merge semantics, and why "undecided" is not universal | D71, D72, D73 |
| 0027 | P16 | Reading access lists and interfaces, and what that did and did not start | D74, D75, D76 |
| 0028 | P16 | The analyser caught an authoring error in its own test data | D77 |
| 0029 | P16 | A dropped access list announces itself | D78, D79 |
| 0030 | P16 | Pack provenance after a re-stamp, and what the trained-pack reset destroyed | D80 |
| 0031 | P17 | A durable archive for superseded packs | D81, D82 |
| 0032 | P17 | A check may bound a value at both ends | D83, D84 |
| 0033 | P17 | JunOS filter terms, and the half that detection blocks | D85, D86, D87 |
| 0034 | P17 | Declaring the management plane rather than inferring it | D88, D89, D90 |

---

## 11. The interface

`ui/` is a React 18 + TypeScript + Vite + Tailwind application, and a **pure
consumer**. It never evaluates a rule, computes a verdict, scores exposure, ranks
a finding or compares a baseline. Every number it shows was returned by the API
or is a count of rows the API returned.

Navigation follows the pipeline: **Devices** (ingest, parse) → **Compliance**
(evaluate) → **Remediation** (resolve) → **Reports**, with the activity log and
the capability status beside it rather than inside it. The drawer stays closed
until it is asked for.

The three levels of zoom are still one question each, but they are reached
without leaving the screen. **Fleet** is the device list; **device** is the
workspace beside it; **finding** expands in place inside that workspace, with its
evidence, its remediation and its abstention reason. Nothing navigates to a
separate page to answer the next question down.

Inside a device the tabs are the pipeline again: *Overview* (what was read),
*Findings* (what was decided), *Needs review* (what no pack recognised),
*Remediation* (what to type), *Report*. The review tab is the deliberate
exception to the product's density — spacious, one line at a time, because a
cramped review produces careless confirmations and a careless confirmation
enters a vendor pack permanently.

**The report is gated.** A device's report opens once it has been audited, every
unrecognised line has been decided (including "not security relevant"), and every
vetted command has been marked reviewed. The gate is the interface's own workflow
rule and says so; the backend renders a report for any persisted run and is not
refusing. Review marks are `localStorage` notes, labelled as such on screen,
because no remediation-approval endpoint exists — they never reach the
hash-chained log, and the log says that too.

`docs/ui_reference.html` is the visual vocabulary — palette, verdict treatments,
density. It contains **illustrative** framework identifiers, compliance
percentages and remediation commands that exist to show a designer what those
components look like; the application ships their structure and none of their
data, and frontend tests assert that none of those values appears in the rendered
document. Its page-level layout predates the drawer navigation and the device
workspace and is no longer followed screen for screen.

Two typefaces are vendored under `ui/public/fonts/` with their OFL licences:
Inter for the interface (it has true tabular figures, which §10's dense tables
need) and Instrument Serif for the wordmark and the landing headline only, never
for anything carrying a verdict. They are self-hosted rather than linked, because
Rule 6 is offline-first and a font request at page load would both break an
airgapped deployment and disclose that the tool is in use.

Role checks in the interface are **UX controls, not security**. The backend
refuses independently: admin endpoints answer 403, and a resource belonging to
another user answers 404 rather than 403, so an unauthorised caller learns nothing
about which identifiers exist.

---

## 12. Where to look next

| Question | File |
| --- | --- |
| What are the contracts? | `docs/data-contracts.md` |
| Why was this decided? | `docs/adr/` |
| What is blocked, and on what? | `docs/SOURCING_BACKLOG.md` |
| What does the corpus need? | `docs/CORPUS_PREREQUISITES.md` |
| What may a document claim? | `docs/CONTENT_POLICY.md` |
| What did the harness measure? | `eval/reports/evaluation.txt` |
| What are the permanent constraints? | `DEVELOPER_GUIDE.md` |

---

*Prefer a small auditable claim over a large unverified one. An honest UNKNOWN is
a result; a guessed PASS is a liability.*
