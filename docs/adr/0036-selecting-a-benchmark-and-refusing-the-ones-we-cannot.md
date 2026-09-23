# ADR 0036 — Selecting a benchmark, and refusing the ones we cannot

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D94 (an unsourced framework is refused, never answered empty),
  D95 (a rule outside the selection produces no finding, not an UNKNOWN one),
  D96 (the selection is persisted; control mappings are resolved at render time)
- **Affects:** `api/comply/frameworks.py`, `api/comply/engine.py`,
  `api/models/rule.py`, `api/db/findings.py`,
  `api/db/migrations/operational/0004_framework_selection.sql` (new),
  `api/routers/audits.py`, `api/routers/reports.py`, `api/report/model.py`,
  `api/report/templates/report.html.j2`

## Context

Problem Statement 26155 asks for evaluation against **user-selected
benchmarks**. ADR 0035 made one framework selectable by sourcing its catalog;
this is the selection itself.

The whole of the difficulty is in one sentence: **three of the four frameworks
the problem statement names have no catalog.** A selector that offered them
anyway would answer a request to audit against ISO/IEC 27001 with zero findings,
and zero findings reads as a clean bill of health.

## D94 — an unsourced framework is refused

`resolve_selection` raises `UnsourcedFrameworkError`; the route answers **400**.

```
no catalog has been sourced for iso, so no rule maps to it and evaluating
against it would report zero findings — which reads as compliance.
Available: nist
```

An unknown *name* is refused with a different message, because the two send the
caller to different places: a typo is theirs to fix, a missing catalog is
`SOURCING_BACKLOG` gap 4.

`GET /compliance/audits/frameworks` lists only what has a catalog, and each
entry names the document, its edition, the number of identifiers indexed and the
**sha256 of the catalog** — so a reviewer can obtain the same file rather than
trusting the label. The response carries one standing sentence: a catalog
publishes controls, not mappings.

This is the same distinction ADR 0035 turned on, one layer up. There it was
*"an identifier must exist in a document"*; here it is *"a benchmark must have a
document before it can be selected"*. Both exist because the cheap failure — a
plausible identifier, an empty result — looks exactly like the expensive
success.

## D95 — a rule outside the selection produces no finding

`Rulepack.applicable_to` gained a `frameworks` filter, alongside the platform
selector it already had, and for the same stated reason: *"this check was never
relevant here" and "we could not determine this check" are different statements,
and only the second belongs in an operator's queue.*

An operator auditing against one benchmark should not be handed abstentions
about checks that benchmark never asked for.

**An empty selection means no filter** — NIRIKSHAK's own seven checks — and is
not the same as a selection that matched nothing. A caller cannot reach the
second state, because `resolve_selection` refuses a framework with no catalog
before the engine ever sees it.

One path remains reachable in principle and is guarded: a *sourced* framework
that no rule maps to. The route answers **409** rather than persisting an empty
run, because `save_run` would refuse it anyway as a 500 naming nothing, and
because "zero findings" must never render as "nothing wrong":

> no rule maps to the selected framework(s), so this audit would report zero
> findings. That is a coverage gap, not a compliant device.

## D96 — persist the selection; resolve the mappings at render time

These are opposite decisions about two things that look similar, and the
difference is what each one *is*.

**The selection is a property of the run**, so migration 0004 adds
`audit_run.framework_selection`. Without it a stored run recording three
findings gives a later reader no way to tell a narrowed scope from a device that
produced fewer results. The column is nullable and `NULL` means *no filter*,
which is what every run before the migration was; backfilling a value would
assert a selection nobody made. It holds a JSON array rather than one value,
because a selection is a set and a column that could hold `nist` but not
`nist and stig` would have to grow a second time.

**The control mappings are rulepack data**, so they are not stored per finding.
They are resolved when the report is rendered, exactly as remediation snippets
already are, and become part of the *report's* provenance rather than the
audit's.

That distinction was not free. `_to_finding` rebuilds a `Finding` from the
database and does not restore `frameworks`, so a report rendered from a
persisted run would have shown **no control identifiers at all** — silently,
which is the failure mode this project keeps finding in its own work. The route
now supplies the mappings, keyed by rule id.

**And only when the run's rulepack version matches the active one.** Showing
today's mappings beside a verdict produced under a different rulepack would cite
a document that did not decide it. When they differ the report carries no
identifiers, which is visibly less rather than quietly wrong.

The mappings are passed *in* rather than looked up, because `report -> comply`
is a forbidden import edge: a report renders persisted findings and must not be
able to reach the layer that evaluates them.

## What the report now says

Each finding shows its mapped controls as plain metadata — identifier, edition
and `project asserted` — never as a verdict-coloured chip. A mapping is a
cross-reference, and giving it semantic colour would put a second colour scale
on a screen whose verdict signal depends on there being one (DEVELOPER_GUIDE.md §10).

Provenance gains **Benchmark scope**, which says either which frameworks were
selected or, explicitly, *no benchmark filter — every applicable NIRIKSHAK check
was evaluated*. Saying it beats leaving a reader to infer it from a count.

Two disclosures are emitted by condition, the way every disclosure in this
report is:

- identifiers were validated against the catalog named in each citation, the
  mapping is asserted by this project and not taken from a published crosswalk,
  and **this is not a certification of compliance**;
- no mapping is present for CIS, STIG or ISO, no catalog for them has been
  sourced, and **the absence of a finding is not a passing result**.

The older disclosure — *"No framework control mappings are present"* — was left
in place untouched. It is guarded by `all(not f.finding.frameworks ...)` and
simply stopped firing, which is what the condition-driven design in ADR 0015 was
for: a sentence retires itself when the gap it described closes.

## Tests

`test_the_report_claims_no_framework_coverage` asserted that **no** identifier
appears in a rendered report. It was correct for as long as none did, and is
replaced here by a test asserting that identifiers appear **and** that the
document bounds what they mean in the same breath — plus that no identifier for
an unsourced framework appears anywhere.

`tests/integration/test_framework_selector.py` covers the rest, including the
one that matters most: `cis`, `stig` and `iso` are each refused rather than
answered, and are absent from the selector rather than present and empty.
