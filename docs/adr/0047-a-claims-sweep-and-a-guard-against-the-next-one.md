# ADR 0047 — A claims sweep, and a guard against the next one

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D121 (a pack that extracts structure is not detection-only),
  D122 (every prose document is held to the framework boundary, keyed off what
  is sourced)
- **Affects:** `api/models/pack.py`, `README.md`,
  `docs/SOURCING_BACKLOG.md`, `eval/report.py`,
  `tests/architecture/test_framework_claims.py` (new)

## Why a sweep

Five sessions of work moved the code faster than the prose. ADR 0041 found three
documents calling PDF blocked while it worked; ADR 0044 found a deliverable
described as undelivered when it was mis-framed. Both were the same failure —
**a sentence that was true when written and was never revisited** — and neither
was caught by a test, because nothing tested prose.

## D121 — a pack that extracts structure is not detection-only

`VendorPack.is_detection_only` returned `bool(detect) and not patterns`.

By P18 `juniper/junos` read firewall filters in both surfaces and four identity
fields, and still reported itself detection-only. **A pack was describing its
own capability inaccurately**, which is the same class of error as a document
doing it and worse for being machine-readable: `docs/SOURCING_BACKLOG.md` and
`README.md` both said "Arista and Juniper remain detection-only" and were
repeating what the code told them.

Structure counts as parsing. The property now requires no canonical-field
pattern **and** no structure extraction, and two narrower properties were split
out because the old name was carrying two questions:

- `reads_no_canonical_field` — the one the evaluation harness cares about. A
  pack can read access lists and identity and still have every compliance check
  abstain, which is exactly Juniper's state and exactly what recall 0 measures.
- `reads_structure` — whether access lists or interfaces are extracted.

The prose was corrected to match: Arista is detection-only, Juniper is not, and
**neither reads a canonical security field** — which is the fact recall 0 rests
on and the one the old phrasing obscured by conflating it with reading nothing
at all.

## D122 — hold every document to the boundary, keyed off what is sourced

`tests/architecture/test_framework_claims.py` checks seven prose documents:

- **no identifier for an unsourced framework** — a CIS recommendation number, a
  STIG `V-` identifier, an ISO Annex A reference. Keyed off
  `sourced_frameworks()`, so it tightens by itself if a catalog is withdrawn and
  relaxes only when one is added. The defect register lost exactly that property
  by being maintained by hand (ADR 0046);
- **no claim of certification or full coverage**, for *any* framework including
  the sourced one. A validated identifier says *this check evidences that
  control, in our judgement*. It does not say anybody certified anything;
- **the unsourced three are named somewhere**, because silence would read as
  coverage by omission. The problem statement names four frameworks; mapping one
  and quietly dropping the others leaves a reader to assume.

A denial is not a claim, so the check skips a match whose neighbouring lines
carry a negation — *"none of the four supports a claim of certified
compliance"* has to be allowed to say the word it denies. The window spans
adjacent lines because these documents are hard-wrapped and a negation
routinely sits one line above the word it governs.

Verified failing: appending *"NIRIKSHAK provides full coverage of CIS 1.2.3 and
is certified against ISO A.9.4.2"* to `README.md` fails two of these tests.
Before this file, it failed none.

### What the sweep found

`docs/SOURCING_BACKLOG.md` carried a specimen CIS identifier, in a paragraph
headed *"What must not happen"* and warning against writing exactly that. The
intent was pedagogical and the guard flagged it anyway, correctly: **a
realistic-looking fabrication sitting in a document is the thing somebody
copies**, and its being framed as a warning does not change what a search hit
looks like. Replaced with a description of the failure rather than a specimen.

`README.md` still said the vetted snippet library was *"currently empty, so no
command is offered for anything"*, beside a section describing the twenty
snippets that ship. Two sentences in one document contradicting each other.

`eval/report.py` printed *"no parsing pattern has ever been written"* for Arista
and Juniper into every regenerated evaluation report. The claim it supports —
that neither carries the label/pattern author conflict — is still true, and the
reason given for it had stopped being.

## What was added rather than corrected

Several things were true and unstated, which is its own kind of inaccuracy in a
document a reviewer uses to judge the work. `README.md` gains a short table:
four packs, two reading canonical fields, six access lists analysed across three
packs with none dropped, the observation counts, one framework of four sourced
and pinned by sha256, twenty snippets each with a rollback and preconditions,
and both report formats.

Every row is bounded in the same paragraph by what it does not mean — Juniper
and Arista read no canonical field, the mappings are `project_asserted`, the
corpus is synthetic, six access lists is not a detection rate. A number without
its limit is the overclaim this project spends most of its effort avoiding, and
putting the two together is cheaper than putting them on different pages.

## The limit

This checks what documents say against what the code reports, and it cannot
check whether either is true of the world. `test_exactly_one_framework_is_sourced`
is the hinge: it pins the fact every other assertion here is measured against,
and it is expected to change — deliberately, by somebody who comes here and
says so, because adding a catalog relaxes the identifier guard across seven
documents at once.
