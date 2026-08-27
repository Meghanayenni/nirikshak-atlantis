# ADR 0015 — Remediation resolution and evidence-linked reporting

- **Status:** Accepted
- **Date:** 2026-08-27
- **Phase:** P8
- **Decisions:** D26 (resolution happens downstream of the engine), D27 (the
  snippet library ships empty), D28 (HTML is the reporting path; PDF stays behind
  the ADR 0006 adapter), D29 (the report states what it cannot claim), D30 (the
  template follows the UI reference selectively)
- **Closes:** R5, open since P0
- **Defects addressed:** none new. DEF-3 still deferred and now explicitly
  surfaced in the report.

## Context

P8 completes the pipeline the Concept Report describes:

```
Ingest → Parse → Normalise → Comply → Prioritise → Remediate → Report
```

Two capabilities land: remediation **resolution** from the vetted snippet
library, and the evidence-linked report that an operator actually reads.

There was no standalone P8 plan document. The scope was fixed by six sources that
agree with each other — `README.md`, ADR 0006, ADR 0014's "Not built at P7",
`docs/data-contracts.md` §9 and its closing section, and the `# P8` marker in
`api/routers/audits.py`. This ADR is that plan, written down.

## D26 — remediation is resolved downstream of the engine, not inside it

`api/comply/engine.py` carried this comment from P6:

```
# Remediation is P8. RemediationRef points into a vetted snippet library
# that does not exist yet, and a pointer to nothing is worse than None.
remediation=None,
```

It reads as though the engine would fill the field in once P8 arrived. **It
cannot.** `comply → remediate` is a forbidden import edge — *"a verdict is
decided before anything is proposed to fix it"* — and populating
`Finding.remediation` inside the engine would mean acquiring one.

So `Finding.remediation` is `None` when the engine emits it, `None` when
`api/db/findings.py` stores it, and `None` when it is read back. Resolution
happens on the far side of the boundary: in `api/report/model.py`, and at the API
edge in `api/routers/audits.py` and `api/routers/reports.py`. The comment has
been corrected to say so.

**The cost, stated rather than discovered.** A report can now resolve against a
library newer than the audit run that produced its findings — the drift D23 was
written to prevent for verdicts. It is accepted here for one reason: a verdict is
a claim about the past ("this was the configuration"), while remediation is a
claim about the present ("this is how to fix it"). Re-resolving is *correct* for
the second, where re-evaluating would be wrong for the first.

It is made visible rather than left implicit. `ReportProvenance` records
`snippet_library_version` alongside the engine and rulepack versions, the report
footer prints it, and the `REPORT_GENERATED` chain entry carries it. The document
says which library produced its commands instead of implying the audit knew.

## D27 — the snippet library ships empty

**Zero snippets ship.** `snippets/` contains a JSON schema and a README
explaining why it contains nothing else.

Rule 4 requires commands come from a vetted library.
`docs/CONTENT_POLICY.md` requires each snippet cite the document it was checked
against. `RemediationSnippet.vetted_by` and `reference` are both mandatory in the
contract *and* in the JSON schema, so a snippet cannot load without naming a
person and a document.

No vendor documentation has been sourced for this project. Writing
`transport input ssh` from general knowledge would produce a command that is
probably correct, attributed to nobody, checked against nothing — and pasted by
an operator into a production device on NIRIKSHAK's authority. That is the single
most damaging output this system could produce, and "probably correct" is not the
standard a remediation command has to meet.

This is the **fourth consecutive phase** to ship correct machinery with no data
behind it: platform defaults (P5), framework mappings (P6), access lists (P7),
snippets (P8). Each refusal was right and the cumulative effect is now large
enough to state plainly rather than rediscover: the pipeline is end-to-end
complete, and the remediation section of every report on every device is empty.
`docs/SOURCING_BACKLOG.md` gains a sixth gap for it.

### What was built anyway, and why that is not waste

Everything except the data:

| Component | State |
| --- | --- |
| JSON schema | `snippets/schema/snippet.schema.json`, extras forbidden |
| Loader | three gates — schema, contract, library consistency |
| Consistency check | duplicate ids, missing dependencies, dependency cycles |
| Resolver | keyed lookup, four typed outcomes, no fallback |
| Ordering | topological, then lockout risk ascending, then `order_hint` |
| Report integration | renders commands, rollback, preconditions, impact |
| API integration | `/findings`, `/remediation`, and the report |

All of it is exercised against **constructed** fixtures in
`tests/fixtures/snippets.py`, following the P7/D21 precedent. Those fixtures use
the vendor `fixture-vendor`, a `vetted_by` reading `NOBODY - constructed test
fixture, not vetted`, and commands like `fixture-command-alpha` that are
deliberately **not** plausible device syntax — a fixture containing
`transport input ssh` would be one careless copy-paste from becoming a shipped
snippet and would look identical to a vetted one in a diff.

**What P9 may and may not say.** It may state that the resolver and the ordering
logic are correct on the cases tested. It **may not** state a remediation
coverage figure, or that NIRIKSHAK produces device-specific remediation for any
platform, because it has never resolved a real snippet.

### The sentence

Every failing finding with no snippet carries exactly this, in the report, in the
API payload, and in the remediation plan:

> No vetted remediation is available for this platform and rule.

It lives once, as `NO_REMEDIATION_STATEMENT` in `api/remediate/resolver.py`, and
is rendered from there. A test asserts the template does **not** contain the
literal text: two copies of an operator-facing sentence drift, and the copy in
the document is the one the operator reads.

An empty panel was the alternative and is worse. It is indistinguishable from a
panel that failed to render, and it invites the reader to assume the fix is
obvious and type it themselves.

### Four outcomes, not a boolean

`ResolutionOutcome` distinguishes cases a boolean would flatten:

| Outcome | Meaning |
| --- | --- |
| `RESOLVED` | A vetted snippet exists |
| `NO_SNIPPET` | The library holds nothing for this platform and rule |
| `PLATFORM_UNKNOWN` | Vendor or OS family was never identified — nothing to look up |
| `NOT_ACTIONABLE` | The finding is not a FAIL |

`NOT_ACTIONABLE` gets a **different** sentence. *"We have no fix for this"* and
*"this does not need fixing"* are opposite messages, and a report that renders
them identically teaches the reader to ignore both.

`PLATFORM_UNKNOWN` shares the operator-facing sentence with `NO_SNIPPET` — from
the operator's chair both mean no command — but stays distinct in the API so an
interface can explain the difference without the two ever disagreeing about
whether a command exists.

### The resolver carries no verdict vocabulary

`resolve()` is *told* whether a finding is actionable; it does not work it out.
`api/remediate/` cannot import `api.comply` and an architecture test greps the
package for `Verdict`, `ComplianceRule`, `Rulepack` and `evaluate_device`. The
caller reads `Finding.is_actionable`, which is the one place that decision lives.

This is the same separation `api/analyse/` has, for the same reason: remediation
must not become a second place where something shaped like a compliance decision
gets made.

### Ordering, and which way round lockout risk goes

`order_snippets` sequences by dependency first, then **lockout risk ascending**,
then `order_hint`, then `snippet_id`.

High-risk last is the load-bearing choice. Disabling an insecure management
protocol before its replacement is verified is precisely how an operator is
stranded outside their own device — so `transport input ssh` (were it ever
vetted) is applied before telnet is removed, not after.

A declared dependency **outranks** lockout risk. The dependency was stated by
whoever vetted the snippet; the lockout ordering is our heuristic, and the
explicit statement wins.

A cycle **raises** rather than truncating. An operator counting six fixes and
receiving five has no way to know which one is missing, or that anything is.

A dependency pointing outside the supplied set is **ignored**, not treated as
unsatisfied: a per-device plan resolves only the rules that failed on that
device, so a snippet may legitimately depend on one whose rule passed there.

## D28 — HTML is the reporting path; PDF stays behind the ADR 0006 adapter

ADR 0006 left R5 open for the project owner: install GTK, use WSL2/a container,
or substitute the engine. The probe was re-run at P8 and the answer has not
changed — all eight native libraries absent, no GTK runtime in any conventional
location, `weasyprint` not installed.

**The resolution: HTML reporting is complete and needs none of it; PDF is a thin
adapter behind a live probe.** The engine is not substituted. R5 is closed by
building so the choice among ADR 0006's three options changes *when* `.pdf`
returns bytes, not whether P8 delivers a report.

`GET /compliance/audits/{id}/report.html` works everywhere. It has no native
dependency, no external stylesheet, no script and no web font — one
self-contained file an operator can save, mail, or open air-gapped (Rule 6).

`GET /compliance/audits/{id}/report.pdf` answers **503** here, naming the eight
missing libraries and pointing at ADR 0006.

**There is no fallback, and that is asserted structurally.** `render_pdf` returns
bytes or raises; an architecture test parses its AST and requires exactly one
`return`, and greps the module for `render_html`, `return html` and `text/html`.
A second engine appearing in `api/report/` fails another test that names
`reportlab`, `fpdf`, `pdfkit`, `wkhtmltopdf`, `xhtml2pdf` and `playwright`.

Returning the HTML document under a `.pdf` name would tell a caller the request
succeeded when it did not, and would put a file on disk whose extension lies
about its contents.

**The probe is not cached.** GTK can be installed while the service runs, and a
cached negative would keep reporting the absence of something now present until
someone restarted the process. `/health` gained a `pdf_reporting` block so an
operator can distinguish *"unavailable on this machine"* from *"reporting is
broken"*.

**Authorise, then probe.** The PDF route checks ownership before probing. Probing
first would make a non-owner's answer depend on the environment — 404 where GTK
is installed, 503 where it is not — and an access-control answer must not vary
with what happens to be on the machine.

## D29 — the report states what it cannot claim, by measuring itself

`Report.disclosures` is **computed from the report's own content**, not written
as fixed prose. Each sentence is produced by a condition over the actual findings:

| Condition | Sentence |
| --- | --- |
| every finding has `frameworks == ()` | no CIS/NIST/STIG/ISO coverage is claimed |
| the library is empty | no finding carries a command, and why |
| any `exposure_score is None` | no exposure scoring was performed |
| any `CAPABILITY_UNKNOWN` abstention | a documentation gap, not a device fault |
| always | the subject is a file content hash, not a device |

A disclosure maintained by hand is a disclosure that eventually describes the
previous release. These stop being emitted on their own when the underlying gap
closes — tested in both directions, so the framework sentence provably disappears
when a mapping is present.

The `CAPABILITY_UNKNOWN` sentence carries one extra clause deliberately: it says
the gap is **not** something administrator training can resolve. `Finding.needs_training`
already excludes it (P5), but an operator reading UNKNOWN and concluding their
device is misconfigured has been misled by the report rather than by the device.

**Ordering is stated, not implied.** Findings are ordered verdict → severity →
rule id, and `ORDERING_BASIS` says so in the document, including the words *"not
an exposure ranking"*. `docs/ui_reference.html` heads its device table *"ranked by
exposure, not severity alone"*; printing a severity-ordered list under that
heading would be the report claiming an analysis it did not perform.

**The subject is named for what it is.** `Report.config_file_id`, never
`device_id` — a test asserts the string `device_id` appears nowhere in the
template, and the report explains that editing the configuration produces a
different identifier (DEF-3).

## D30 — the template follows the UI reference selectively, and says which parts

`docs/ui_reference.html` is the design specification for the P13 React interface.
It was **not modified**, and nothing in `api/` reads it — asserted by a test that
walks the AST for non-docstring string constants, so referring to it in prose
stays allowed and treating it as an input does not.

**Followed:** the colour tokens, the type hierarchy, the verdict chip treatments,
the evidence block with its line-number gutter, and two decisions that carry
meaning rather than taste — UNKNOWN rendered slate-and-dashed rather than amber,
because abstention is off the severity axis and an amber chip reads as a weaker
FAIL; and every verdict carrying a glyph as well as a colour, so the document
survives greyscale printing and colour-blind readers.

**Not followed, and each omitted rather than blanked:**

| In the reference | Why the report omits it |
| --- | --- |
| `CIS 1.2.3 · AC-17 · V-215807` | Every rule ships `frameworks: []` (D16) |
| "ranked by exposure, not severity alone" | `priority_rank` is unset until P12 |
| A populated remediation block | The library is empty (D27) |
| A fleet table of six devices | Peer baselines are P12 |

A column of empty cells reads as missing data *about the device*. The absence of
the column, plus a disclosure saying why, reads as what it is. Three tests
enforce this: the template may contain no framework identifier, no device
command, and none of the phrases "ranked by exposure", "exposure score" or
"priority rank".

**Rule titles are not shown.** The persisted `Finding` carries `rule_id` and
`expected`, not the rule's title. Fetching the title would mean loading the
current rulepack and printing today's wording over a historical run, which is the
drift D23 exists to prevent. The report shows the rule id and the expectation
recorded at evaluation time.

**Autoescaping is on and `StrictUndefined` is set.** Every evidence line is
verbatim text from an uploaded configuration; a banner containing `<script>` must
render as characters, and Rule 2 requires the raw line be shown exactly.
`StrictUndefined` makes a template typo raise instead of rendering blank — in a
compliance report the silent version is the dangerous one, because a remediation
block that renders empty looks exactly like a control with nothing to fix.

## The API surface

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/compliance/audits/{id}/report.html` | The report |
| GET | `/compliance/audits/{id}/report.pdf` | The same, or 503 |
| GET | `/compliance/audits/{id}/remediation` | The plan, in application order |

All authenticated and ownership-scoped under D25; a run the caller may not see
answers 404, not 403.

The remediation plan lists **every** failing finding, resolved or not. A plan
that silently omitted the ones with no snippet would understate the work by
exactly the amount nobody has vetted — currently all of it. Resolved steps carry
an `apply_order`; unresolved ones carry `null`, because a numbered step with no
command implies there is something to do at that point in the sequence.

`api/report/` performs **no I/O**. It may import `api.models` and `api.remediate`
and nothing else — notably not `api.db`. The router reads the run, its findings
and the file's detected platform, and hands the view model plain data. That is
what lets the whole package be tested without a database and keeps it off every
path that could reach a stored configuration.

## The audit chain

`REPORT_GENERATED` was already in `AuditAction` from P1 and is now written. The
payload is identifiers, counts and versions: audit id, config file id, format,
rules reported, verdict counts, engine/rulepack/library versions, and how many
remediations resolved. **No finding value, no cited line, no configuration text**
— the D4 boundary holds at the newest writer, and a test proves it by searching
the payload for every non-trivial line of the audited file.

The payload field is `config_file_id`, not `device_id`. The AUDIT_RUN payload
from P6 uses `device_id` and was left alone; introducing a *new* record type was
the moment to name the field for what it holds rather than propagate a misleading
name for symmetry. Correlation between the two is by `audit_id`, which is present
in both.

Rendered first, recorded second — the ordering ingestion and compliance already
use, so the log never attests to a document that then failed to produce.

## Consequences

Fourteen new forbidden import edges. `report → comply` and `report → db` are the
two carrying weight; `remediate → comply` completes the pair whose other half has
existed since P1.

`tests/architecture/test_rule_content_policy.py` now reads `snippets/`. The
content policy has named that directory since P0 and nothing enforced it until
now.

**Not built at P8:**

- **Any actual remediation command** — sourcing, gap 6.
- **A fleet-level report** — needs peer baselines and exposure, both P12.
- **Framework columns, exposure ranking, ACL observations in the report** — the
  first two have no data; the third is a separate rail (D22) and folding it into
  the findings table would blur the distinction that ADR deliberately drew.
- **The React/Tailwind UI** — P13. `docs/ui_reference.html` remains the
  specification and remains untouched.
- **Report persistence** — a report is regenerated from the persisted run each
  time. Storing rendered documents would create a second copy of findings that
  could drift from the first, which is the argument D23 already made about
  evidence.

**DEF-3 remains deferred, and is now visible.** `device_id` is still the ingested
file's content hash. Rather than waiting for P12 to fix it quietly, the report
states it in prose to the operator, names its own field `config_file_id`, and the
chain payload does the same.
