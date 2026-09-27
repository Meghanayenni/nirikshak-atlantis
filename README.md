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
evidence-linked HTML or PDF report comes out, citing the exact lines it rests
on. And the accuracy of that pipeline is a measurement rather than a claim —
`make evaluate`, with the numbers in `eval/reports/evaluation.txt`.

### What it does today, in numbers

| | |
| --- | --- |
| Platforms with a vendor pack | **4** — Cisco IOS, Cisco NX-OS, Juniper Junos, Arista EOS |
| Platforms reading canonical security fields | **2** — IOS (ten fields), NX-OS (seven) |
| Access lists analysed, across 3 packs | **6**, none dropped |
| ACL observations on real corpus files | 5 shadowed, 4 redundant, 3 overly permissive |
| Frameworks with a sourced catalog | **3 of 4** — NIST SP 800-53 Rev 5 (5.2.0); DISA Cisco IOS XE Router NDM STIG (V3R7); CIS Cisco IOS XE 17.x Benchmark (v2.2.1). Each pinned by sha256; ISO/IEC 27001 not sourced |
| Vetted remediation snippets | **20**, across 3 platforms — every one with a rollback and preconditions |
| Report formats | HTML and PDF, both from the same persisted run |

Each of those is the subject of a test, and each is bounded elsewhere on this
page by what it does **not** mean. Juniper and Arista read structure and
identity and no canonical field, so every compliance check on them abstains.
The framework mappings are `project_asserted`. The corpus is synthetic. Six
access lists is not a detection rate.

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

The Cisco IOS pack reads ten canonical fields and the Cisco NX-OS pack seven.
Juniper reads firewall filters in both surfaces and four identity fields; Arista
reads three identity fields. **Neither reads a canonical security field**, so
every compliance check on those platforms abstains with `no_match` and both
score recall 0 in the harness — an honest state rather than a placeholder: the
platform is recognised, and every field no pack can read says UNKNOWN.

**Four platforms are now detected and three parse access lists.**
`corpus/cisco/dev/dc1-leaf-01.cfg` scored 0.25 against Cisco IOS — below the
detection floor — and could not be audited at all until the NX-OS pack landed.
Its detection signatures are constructs classic IOS does not write (`feature`,
`vrf context`, a bare `line vty`, `logging server`), so it wins by a margin of
0.85 and no other file's detection moved.

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

**A finding shows the controls it maps to** (ADR 0057). Each carries its
framework, identifier, the edition it was validated against and *project
asserted* — the mapping is this project's judgement, not a published crosswalk.
A mapping the rule declines is shown with its recorded reason (`CISC-ND-000720
not mapped — requires five minutes or less; this rule passes up to ten`), and a
framework that contributes nothing on the device says why. Until ADR 0057 the
finding view said "No framework control is mapped" on every finding, NIST
included, from P17 onward; when mappings are withheld because the run's rules
are not the active rules, it now gives that reason instead.

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

**No interface is classified as management-plane, so exposure still abstains.** A
pack can now declare `interface_roles` — anchored name patterns carrying the same
sourced provenance a platform default needs — and **none does**, for the same
reason: nothing in this repository documents which interface names a vendor
designates as management. Reading "MGMT" out of an operator's description would
be a guess wearing a citation, and a name matching no role stays *undocumented*
rather than becoming *not management* (DEF-2). The path is proven end to end on
a constructed pack, so an abstention here is a refusal rather than a breakage.

**Three frameworks of four are mapped, and no mapping claims to be official.**
All nine rules carry NIST SP 800-53 Rev 5 control identifiers, each validated
against the official OSCAL catalog — edition 5.2.0, pinned by the catalog's own
sha256, with withdrawn controls listed so a plausible-but-retired identifier
cannot ship. Three rules carry four DISA STIG IDs and six carry CIS recommendation
numbers (ADR 0052), each validated against an index of its edition. **Every mapping is `project_asserted`**: a catalog publishes
*controls*, not *mappings*, and that a NIRIKSHAK check satisfies a given control
is this project's judgement. `official` provenance is reachable only from a
published **crosswalk** — a document stating the mapping — and none has been
obtained.

**An audit can be scoped to a selected benchmark.**
`POST /compliance/audits?file_id=…&framework=nist` evaluates only the rules that
map to it, and the run records its own scope so a later reader can tell a
narrowed benchmark from a device that produced fewer findings. The report names
that scope and shows each finding's mapped controls.
`GET /compliance/audits/frameworks` is the selector, and it lists only
frameworks with a sourced catalog — asking for one without a catalog is refused
with 400, never answered with zero findings.

**Framework choice changes the verdict, and the selector says so** (ADR 0054).
On an IOS XE 17 configuration enabling `ip http server`, `framework=stig` gives
`NRK-HTTP-001` **FAIL** citing `CISC-ND-000470` and the line; `framework=cis`
leaves it **not assessed**, and the response and report give the rule's recorded
reason — CIS constrains the server and never requires it off. That input is
constructed in a test: no corpus file is both in the benchmarks' scope and
enables the server. A selected framework whose edition does not describe the
device is named as *not applied*, with why; if none of the selection describes
it, the audit is refused with 409 rather than run and reported clean.

**The interface offers the selector** (ADR 0058). Each device's workspace lists
the sourced frameworks the API returns for that device — ISO does not appear —
and a benchmark whose edition does not describe the device says so in the API's
words. A refused audit shows the API's 409 sentence beside the selector rather
than an empty result, and a scoped run's findings open with what the scope left
out and why. The STIG-versus-CIS contrast above was exercised end to end in
headless Chrome through the real interface.

**DISA STIG and CIS are mapped narrowly, and on one platform.** Both editions
describe Cisco IOS XE, so their identifiers appear only on `cisco/ios` devices
whose release reads 17.x — not on classic IOS 15.x, NX-OS, JunOS or EOS, where a
report says why rather than leaving the column blank. Four rules are looser than
the STIG control a prepared reading proposed for them (a 10-minute timeout
against the STIG's 5; one syslog host or NTP server against its two; a banner's
presence against its mandated text) and carry no STIG identifier, with the reason
recorded in the rule. **The two frameworks disagree about the HTTP server**: the
STIG says it must not be configured, and CIS constrains it without requiring it
disabled — so `NRK-HTTP-001` maps to the STIG and records the CIS disagreement
rather than forcing a row to look complete.

The STIG's XCCDF file is held in this repository and its index re-derives from it
on every test run. **The CIS Benchmark is never held**: its own terms forbid
third-party hosting, so it is read from outside the tree and only recommendation
numbers are recorded, and a test fails if any copy appears in the working tree.
No legal claim is made about either set of terms.

**ISO/IEC 27001 is unmapped** — a purchased standard. It is **absent** from the
selector rather than present and empty: an empty result reads as a clean bill of
health, and "we never read this benchmark" is a different statement. **No claim
of coverage against any framework is made or supported by this repository** —
four of 42 STIG requirements and six of 84 CIS recommendations carry a mapping —
and none of the four supports a claim of *certified* compliance. See
`docs/adr/0035-framework-mappings-against-a-content-addressed-catalog.md` and
`docs/adr/0052-two-benchmarks-one-held-and-one-referenced.md`.

**A serial number is not readable from a configuration, and that is a limit of
the input rather than of the parser.** A serial is inventory data from
`show version` / `show inventory`; a configuration export does not contain one,
so no pattern over this input could ever match and nobody can close it by
writing a regex. It is recorded against the **input type** rather than the
platform — every platform here can express a serial — and the report renders it
as *not applicable* with that reason rather than blank, because "we looked and
failed" and "this input does not contain one" call for different responses. The
clean path is accepting `show version` output as a second input type; it is
named in `docs/adr/0044-a-serial-is-not-a-parsing-gap.md` and not built.

**The report names the device.** Hostname, model and OS version appear in a
Subject block and the hostname is in the header. All three were extracted and
stored from the beginning and stopped at the report boundary until P18, so a
report for `8995304d…` could not be matched to a router by the person holding
it.

**The hardware model is read on Arista**, from the `! device:` header EOS writes
itself — and was **removed** from Cisco IOS, where the pattern's only evidence
was an annotation somebody typed into one corpus file that no real device emits.
That pattern shipped in a builtin pack for ten phases, reporting a fabricated
model as observed identity *with a citation*. It is the sharpest example in this
repository of why sourced provenance matters: an absent field invites a
question, and a field carrying a file name and a line number invites belief. See
`docs/adr/0037-a-model-read-from-a-line-a-device-writes.md`.

**The corpus is synthetic and small.** Two Cisco development devices are enough to
validate the *evaluator*; they are not enough to validate a *rule*.

**No ACL detection rate is claimed.** The analyser does now read parsed access
lists — four across Cisco IOS and JunOS, none dropped — and reports shadowed,
redundant and overly-permissive entries on them, including **none** on a
deliberately clean list. Every one of those files was written by this team, so
what is demonstrated is that the interval logic runs on real parsed structure,
not a rate at which it would find problems on a real network.

**Three ACL dialects across three vendors, and both surfaces JunOS ships.**
Cisco IOS wildcard lists, NX-OS prefix-length lists, and JunOS filter terms in
*both* the flat `set` form and the brace-nested hierarchy. Six access lists are
analysed, none dropped.

The brace-nested JunOS file was unreachable end to end until P18, and detection
was the smallest of four blockers: the syntax mode was keyed to the platform
rather than to the file, `SyntaxMode.BRACE` raised rather than parsing, and the
flat reader groups top-level lines where brace terms are subtrees. It now yields
the **first shadowed result on a non-Cisco platform** — a filter whose
`term allow-anything { then accept; }` sits above the term meant to block
telnet, so the block can never take effect. Arista declares no ACL extraction.
See `docs/adr/0043-the-second-surface-junos-ships.md`.

**Similarity scores are not confidence, and no calibrator is fitted.** Every
suggestion carries `UNCALIBRATED_SIMILARITY`, which forces the field to UNKNOWN
regardless of score. Fitting a calibrator needs labelled score outcomes that do
not exist, and the fitter refuses below a sample floor the corpus cannot reach.
No similarity number in this system may be read as a probability.

**Held-out generalisation and top-3 accuracy are not measured.** The similarity
layer exists, so that is no longer the obstacle. The metric is defined over the
held-out vendor's commands, reading them needs a parser for its format, and that
parser waits on a sample independent of the held-out files — building it from
them would destroy the experiment. **The holdout has never been parsed, studied
or used to author a pattern**; two integrity guards hash and scan its files on
every test run, and neither surfaces a held-out line to anyone (architecture §8).

**Evaluation results are synthetic-corpus results.** Every configuration in
`corpus/` is hand-written, so the harness scores the parser against its author's
imagination rather than against the field. The numbers are real measurements of a
synthetic sample and **are not real-world accuracy.**

**The ground-truth labels are not independent.** They are unreviewed, and the
Cisco labels were written by the author of the Cisco parsing patterns — so
correlated error between parser and ground truth is not visible in the Cisco
figures. The label files declare this, and the report prints it. Arista and
Juniper carry no such conflict, because no *canonical-field* pattern exists for
either — Juniper does read access lists and device identity, and neither feeds a
scored field.

**Remediation is ordered for lockout risk, not just listed.**
`GET /compliance/audits/{id}/remediation` returns a plan in application order,
and three of the twenty snippets carry `lockout_risk: high` — a change that
could strand the operator outside the device they are fixing. Those sort last,
and a high-risk snippet that does not explain itself in `notes` is refused at
load. Every snippet carries its rollback and its preconditions, and the report
shows a command with both or not at all. Nothing is ever applied: the system
recommends and a human types.

**No remediation *coverage* is claimed.** Twenty vetted snippets ship across
Cisco IOS, Juniper Junos and Arista EOS, each naming the person who checked it
and the vendor document they checked it against — Rule 4 and
`docs/CONTENT_POLICY.md` between them make a snippet impossible without both. A
fourth platform, or a rule nobody has vetted a command for, still resolves to
*"No vetted remediation is available for this platform and rule."* That sentence
is the correct output rather than a gap: `(arista, eos, NRK-SSH-001)` is
deliberately unfilled because EOS exposes no SSH protocol-version setting, and
inventing one would be worse than abstaining. Every shipped snippet leaves
`os_version_range` null, which the schema documents as *"the vetter did not
bound it"* — an operator on an old release is shown a command nobody confirmed
applies to their release.

**Two stored findings cannot name the pack that read them.** A trained vendor
pack, `cisco/ios 1.1.5`, was deleted when contaminated patterns were reset, and
two audit runs on this deployment cite it. The files were recovered and committed
to `packs/archive/`, where each still verifies against its own checksum — so the
evidence exists and a person can read it. **The loader still cannot resolve the
version**, because every archived file declares itself active and reinstating one
would give a platform two active versions. Recorded as DEF-18; see
`docs/adr/0030-...` and `docs/adr/0031-a-durable-archive-for-superseded-packs.md`.

**PDF rendering works here, and refuses where the runtime is absent.** A report
for `corpus/cisco/dev/sw-access-02.cfg` renders to **seven A4 pages** carrying
seven findings, two failures with their cited configuration lines, and five
disclosures. HTML reporting is complete and has no native dependency; the PDF
endpoint needs the WeasyPrint/GTK stack, and where that is absent it answers 503
naming the missing libraries rather than substituting another engine or
returning the HTML document under a `.pdf` name.

**DEF-16's guard had never detected anything, and now does.** The defect that
actually bit this project — an administrator confirming lines from an
evaluation-split file through the interface, contaminating the measurement — has
a guard that scans `packs/trained/`, which is gitignored and empty on every
checkout. It skipped every time it ran, and the contamination was found by
tracing examples back to files by hand. It is now driven against a pack the real
training loop writes from the actual offending line, with the clean case beside
it. **This does not close DEF-16**: the loop still has no notion of a corpus
split, and an administrator can do exactly what they did before.

**The analyser has now corrected its own test data twice.** At P16 it declined
to flag an entry a corpus remark called unreachable, and was right — an ACL
evaluates top-down, so a rule below cannot shadow one above. At P18 it reported
two permits as redundant beneath a term named `allow-established` that matched
all TCP; the configuration was what it appeared to be and the *name* was the
error. Both times the fixture was written by somebody who believed it was
correct, and both times the tool disagreed on evidence. The term was renamed
rather than given a state match, because writing the JunOS keyword for one would
be vendor syntax this repository cannot source.

**The suite refuses to run if a test is shadowed.** Two functions with one name
in one module is not an error in Python — the second replaces the first, and the
first stops existing before pytest sees it. It happened here, and the suite
reported green. A collection-time check reads each module's source (the only
place both definitions still exist) and aborts with exit 4. In a project whose
argument rests on its tests, a test that silently stops running is the one
defect the suite cannot report on itself.

**Every self-description is derived from what it describes, or reconciled
against it.** `/health` reported `phase: "P12"` from P12 until P18 — the
endpoint declared it, the interface displayed it, and a test asserted it, so the
suite was actively defending a claim that had been false for six phases. It is
removed rather than corrected: a phase label has no runtime source, so the next
correct value would have the same lifespan as the last. Three declarations that
could not be derived are now reconciled instead — a pack's version against its
own filename, the engine version against `pyproject.toml`, and the rulepack
version against a checksum of the rules and framework indexes it contains. Since
ADR 0056 that last binding is enforced **at load**, not only in the test suite:
`rules/rulepack.yaml` declares version and checksum, the loader refuses rules
that do not match, and every run records the checksum — so a report shows
today's control identifiers beside a stored verdict only when the same rules
decided it, not merely the same label.

**Every skip guard is paired or registered.** A test that skips is a test that
does not test: four PDF tests skipped wherever the runtime worked, so the
endpoint was exercised by nothing for ten phases. An audit of all fourteen
guards found two more of the same shape — `embed()` producing 384-dimension
vectors that nothing asserted, and a training queue ranking suggestions that
nothing asserted — plus a contamination guard that had **never run**, because it
scans a gitignored directory that is empty on every checkout. All three are
covered now, and `tests/architecture/test_skip_guards.py` fails the build if a
new guard appears without something covering its other state.

Until P17 three documents said this was blocked. It was not: the GTK runtime is
installed here and the live probe had been reporting so on every request. **No
test asserted the positive path**, so a working endpoint and three documents
calling it blocked sat side by side for ten phases. Both levels are asserted
now — `render_pdf` returning `%PDF-` bytes, and the endpoint returning
`application/pdf` from a persisted run.

`Dockerfile` and `docker-compose.yml` are the supported way to get it working
regardless of the host, and the build fails rather than producing an image whose
PDF endpoint 503s. **The image has not been built or run from this repository**
— the Docker daemon was not available on the machine where it was authored — so
it is reviewed work, not verified work. See
`docs/adr/0006-weasyprint-gtk-probe.md` and
`docs/adr/0039-a-container-where-the-pdf-endpoint-works.md`.

**Nine known advisories sit in locked third-party dependencies** — seven in
`starlette`, one in `lxml`, one in `pytest` — found by `make audit` the first
time it ran. None is a defect in this repository and none is fixable without a
version bump that needs its own testing: `starlette 0.47+` requires a FastAPI
major bump. `make audit` exits non-zero on them deliberately, and is wired into
`make verify` rather than `make test`, so a third-party CVE does not make every
unrelated change look broken. Recorded rather than silenced.

See `docs/CORPUS_PREREQUISITES.md` and `docs/SOURCING_BACKLOG.md`.

Held-out generalisation, top-3 mapping accuracy and confidence calibration
remain **unmeasured**, each for a reason recorded in `docs/adr/0017-similarity-layer.md`;
the PAN-OS holdout has still not been parsed or studied, and the experiment
remains unspent. `docs/ui_reference.html` remains
the untouched visual specification the P13 interface was translated from. See `docs/adr/` for the decisions taken so far,
and `docs/SOURCING_BACKLOG.md` for the eight gaps that cannot be closed by writing
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

# 3b. WeasyPrint, for PDF reports. Install it always: the test suite expects it.
#     What is optional is the GTK3 runtime below. Without GTK, report.pdf answers
#     503 naming what is missing, HTML reports work, and the suite still passes.
pip install -e ".[report]"

# 3c. For AI mapping suggestions (optional): the [ai] extra, then the model once.
pip install -e ".[ai]"
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

# 4. Verify — expect 0 failed. The number skipped depends on whether GTK3 and
#    the model are present, because each capability is tested in the state this
#    machine is actually in.
pytest
ruff check .
```

**GTK3 on Windows**, for 3b: install [MSYS2](https://www.msys2.org), run
`pacman -S mingw-w64-x86_64-pango mingw-w64-x86_64-cairo` in its shell, and add
`C:\msys64\mingw64\bin` to `PATH` — the route the verifying machine uses;
`GET /health` then reports `pdf_reporting.available: true`.

**Without 3c, the mapping screen works and suggestions do not**: an
administrator can still map an unknown line by hand, but no ranked candidates
are offered, and `/health` says the model is unavailable. On the verifying
machine the `[ai]` stack occupies about 0.7 GB installed (torch alone 531 MB)
and the model weights 92 MB in the Hugging Face cache; the download is smaller
than the installed size, and needs network access once (ADR 0018). One case
still shows test failures: skipping 3c on a machine that already holds the
`all-MiniLM-L6-v2` weights from another project. Two model-refusal tests then
expect a message about missing weights and get one about the missing package
(ADR 0060); installing 3c, or removing the cached model, clears it.

Dependency groups are installed as the phases need them:

| Group      | Installed at | Contents                                        |
| ---------- | ------------ | ----------------------------------------------- |
| *(core)*   | P0           | FastAPI, parsing, YAML, schema validation       |
| `[dev]`    | P0           | pytest, ruff                                    |
| `[report]` | P8, always   | WeasyPrint; the system GTK3 runtime is optional |
| `[ai]`     | P10, optional| sentence-transformers, torch (CPU), FAISS — installed, not yet imported: retrieval is exact cosine similarity (`api/learn/suggest.py`) |

The machine-learning stack is deliberately deferred so the first nine phases
install quickly and stay within the 8 GB target hardware budget.

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
`scripts/create_admin.py`; **there is no self-registration**, and the role comes
from the server rather than from anything the login form offers.

**The Report tab is gated, deliberately.** It opens once every configuration line
no pack recognised has been decided in *Needs review* (13 on
`corpus/cisco/dev/rtr-core-01.cfg`; "not security relevant" counts) and every
vetted command has been marked reviewed — a careless confirmation enters a
vendor pack permanently, so the interface makes the operator look first. In the
device's *Needs review* tab, choose each line and either map it to a field or
press **Not security relevant**; in *Remediation*, press **Mark reviewed** on each
command. The gate is the interface's; `report.html` and `report.pdf` on the API
are not gated.

To verify the interface build:

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
| GET | `/compliance/audits/frameworks` | Sourced benchmarks, each edition and sha256 | public |
| GET | `/compliance/audits/frameworks/device/{file_id}` | Which benchmarks describe this device, and why not | user |
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

**Everything except `/health` and `/compliance/audits/frameworks` requires
authentication** (HTTP Basic). Those two expose no user data: liveness and
settings, and the sourced benchmark catalogs' names, editions and digests. A user sees
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
   snippet library, keyed by vendor, OS family and rule ID. Twenty snippets ship
   across Cisco IOS, Juniper Junos and Arista EOS, each naming the person who
   checked it and the vendor document they checked it against. A platform or
   rule with no vetted entry resolves to *"No vetted remediation is available"*,
   which is the correct output rather than a gap.
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
