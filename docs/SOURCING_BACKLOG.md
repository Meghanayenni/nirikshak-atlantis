# Sourcing backlog

**Eight gaps that cannot be closed by writing code.** Each is blocking a capability
the Concept Report promises, each needs material obtained from outside this
repository, and none may be closed by inventing data.

P11 changed the *shape* of gap 7 without closing it: the loop that would generate
the missing labels now exists and is tested end to end, so the gap is waiting on
operators rather than on engineering. Every other gap on this page is exactly
where P10 left it.

This document exists because four consecutive phases have now shipped correct,
well-tested machinery that produces nothing observable — an absence engine with
no platform defaults (P5), a compliance engine with no framework mappings (P6),
an ACL analyser with no ACLs (P7), and a remediation resolver with no snippets
(P8). Every one of those refusals was right. The cumulative effect is still a gap
between what the system can do and what it can be *shown* doing, and closing it is
a sourcing task, not an engineering one.

**Nothing here is assigned.** That is the point of writing it down.

---

## 1. ACL-bearing configurations

**Blocks:** ACL extraction, and therefore anything the analyser could say about a
real device. Also blocks exposure-aware prioritisation at P12, which needs ACLs
*and* interfaces.

**State.** The corpus contains **zero** access lists in any split — verified by
searching every file for `access-list`, `access-group`, `ip access`, `firewall`,
`filter`, `security-policy`, `policy-map` and `class-map`. The nearest line is one
Juniper `set security policies …` statement with no destination, protocol, port or
action, on a vendor whose pack is detection-only.

The P7 analyser is built and exhaustively tested against constructed `ACL`
objects. It has never seen a parsed one.

**Now blocking a second built feature.** P12 shipped the Prioritise stage, and it
abstains on every finding of every device: exposure needs interfaces *and* access
lists, and the corpus holds **zero interfaces and zero ACLs** across all ten
non-holdout devices. `exposure_score` and `priority_rank` are `None` everywhere
and the audit response reports `no_interface_data` as the blocker. Two phases of
machinery — P7's interval logic and P12's ranking — now wait on this one gap.

**What would close it.** Development-split configurations containing real access
lists, sanitised to `docs/CONTENT_POLICY.md`, ideally including a shadowed entry,
a redundant entry, an overly permissive entry, a partial overlap that is none of
those, a clean list, one list applied to an interface with a direction, and one
object-group reference.

**What must not happen.** Writing ACL parsing patterns from general vendor
knowledge. The P4 corpus-provenance test would reject them, and it should.

---

## 2. Vendor capability and default documentation

**Blocks:** absence-aware evaluation — the Concept Report's headline
differentiator.

**State.** **Zero** platform defaults and **zero** capability claims ship, across
all four packs. Every absent field on every corpus device therefore resolves to
`UNKNOWN / capability_unknown`, and the `AbsenceAction.EVALUATE` branch **never
fires on real data**. Roughly a quarter of the checks on
`corpus/cisco/dev/sw-access-02.cfg` abstain for this reason alone.

This is the backlog that `capability_unknown` findings belong to, and it is
**deliberately not the administrator training queue**. `Finding.needs_training`
excludes it on purpose: no amount of administrator training will teach the system
what a vendor documents as a default. Training fixes parsing; this needs a
librarian.

**What would close it.** For one platform, one field at a time: a vendor
configuration guide, command reference, hardening guide or release note stating
the default — obtained and read — recorded as `PlatformProvenance` with a document
identifier and a locator into it. Per `CONTENT_POLICY.md` that is identifiers and
locators only, never transcribed vendor prose.

**Smallest useful step.** Two sourced defaults on one platform would make the
branch fire on real data for the first time. This is the highest value-per-hour
item on the list.

**Now measured.** The P9 harness reports absence as branch coverage:
`absent_default` is **0** across every scored file, so the `EVALUATE` branch has
never executed against a real configuration. That is no longer an assertion in a
document; it is a line in `eval/reports/evaluation.txt`.

**What must not happen.** Manufacturing a default from general knowledge, or
citing a corpus file. A corpus file is a claim about a device *we wrote* and can
never be evidence about a vendor's documented behaviour — a test asserts that no
platform claim cites a corpus path.

---

## 3. XML samples that do not compromise the PAN-OS holdout

**Blocks:** `SyntaxMode.XML` and the `xpath` match primitive.

**State.** The only XML in the corpus is `corpus/holdout/panos/`, and PAN-OS is
the held-out vendor for the P9 generalisation experiment. `build_tree(..., mode=XML)`
raises rather than returning an empty tree.

**What would close it.** A legitimately sourced XML configuration **independent of
the holdout** — a different vendor, or a genuinely different device — sanitised,
recorded in the manifest with honest provenance, and assigned to `dev` if patterns
are to be authored from it.

**What must not happen.** Reading the holdout to build a parser. That destroys the
experiment the holdout exists for: top-3 accuracy on files we have already studied
measures memory, not generalisation. Nor is a self-authored XML fixture
sufficient — a parser built for a shape we invented is wrong in exactly the ways
only the real thing reveals.

**Now the binding constraint on the headline metric.** P9 deferred held-out
generalisation to P10 because the similarity layer did not exist. P10 built it,
and found this gap underneath: the metric is defined over the held-out vendor's
commands, and they cannot be read without the parser this entry blocks. The
dependency is circular and no code closes it. Until an independent XML sample is
sourced, **the Concept Report's generalisation figure cannot be produced at all** —
see decision D37 and ADR 0017.

---

## 4. Framework control-ID sources

**Blocks:** any claim of CIS, NIST SP 800-53, DISA STIG or ISO/IEC 27001 coverage.

**State.** Every rule ships `frameworks: []`. NIRIKSHAK evaluates its own seven
checks and maps them to nothing.

This is the most visible gap against the problem statement, which asks explicitly
for evaluation against user-selected benchmarks. It is also the one most tempting
to close by writing plausible-looking identifiers, which is why the empty state is
asserted by a test written to fail when the first mapping appears.

**What would close it.** A benchmark edition obtained and read, so a mapping can
name a control **and its source document**. `FrameworkRef` already carries
`version`, `citation` and `mapping_provenance` for exactly this.

**What must not happen.** Writing `CIS-1.2.3` or `AC-17(2)` from memory. Using
`project_asserted` provenance to make the product appear to have coverage is
specifically excluded (D16). Until a source exists, **no document, report or
presentation may claim coverage against any of the four frameworks.**

---

## 5. Broader vendor and configuration diversity

**Blocks:** compliance-rule validation, and any P9 accuracy claim beyond the
narrowest.

**Now measured.** Arista and Juniper score **recall 0** in the P9 report — three
and four fields respectively that a human reads off the page and the system
cannot, because neither platform has a parsing pattern. Reported per vendor and
never pooled (decision D34), so the gap is visible rather than averaged into a
fleet figure.

**State.** Two Cisco development devices, eight canonical fields, seven rules. That
is enough to validate the *evaluator* — the two files disagree, so PASS, FAIL and
UNKNOWN all arise from real data. It is **not** enough to validate a *rule*: a
check that passes on two devices from one vendor has been tested against a sample
too small to say anything about the check.

Arista and Juniper packs remain detection-only, so their devices produce a valid
canonical model with zero fields and full residue.

**What would close it.** More Cisco devices with genuine variation rather than
near-copies; at least one further vendor with a real parsing pack; and devices
that legitimately **lack** controls, so absence-aware evaluation has something real
to reason about.

**Now measured as a cohort size.** P12's peer baselines group devices by platform
and refuse to claim a deviation below `MIN_COHORT_SIZE` (5). The corpus forms
three cohorts of 4, 3 and 3, so **no baseline is established for any field on any
platform** and no device is called an outlier. One more Cisco device would make
the Cisco cohort comparable for the first time — the cheapest single addition on
this page, and the only one that would make a built feature produce output.

Note what a fifth Cisco device would and would not buy: the cohort would become
*comparable*, not *representative*. Five hand-written devices by one author can
demonstrate the arithmetic; they cannot support a claim about fleet drift.

**What must not happen.** Growing the corpus by templating the two existing files.
Near-identical devices inflate the file count without adding evidence, and they
make the fleet-cache and peer-baseline numbers look better than the data supports.

---

## 6. Vendor remediation documentation

**Blocks:** every remediation command in the product. Added at P8.

**State.** `snippets/` contains a JSON schema and a README. It contains **zero**
snippets, so the resolver returns `NO_SNIPPET` for every rule on every device and
every failing finding in every report reads:

> No vetted remediation is available for this platform and rule.

The loader, schema, resolver, dependency ordering, lockout-risk sequencing and
report integration are all built and tested against constructed fixtures
(decision D27). None of them has ever handled a real snippet.

**Why it cannot be closed by writing YAML.** `RemediationSnippet` requires
`vetted_by` and `reference`, in the contract and in the JSON schema, and
`tests/architecture/test_rule_content_policy.py` refuses a vetter whose name
looks automated. A snippet therefore cannot exist without a **person** who read a
**document** and checked the commands against it.

**What would close it.** For one platform, one rule at a time: a vendor
configuration guide, command reference or hardening guide — obtained and read —
with the exact commands, their rollback, their preconditions and their service
impact checked against it. `reference` records the document identifier and a
locator; per `CONTENT_POLICY.md` that is identifiers and locators only, never
transcribed vendor prose.

**Smallest useful step.** Two vetted snippets for the two rules that fail on
`corpus/cisco/dev/sw-access-02.cfg` would make the remediation path fire on real
data for the first time, and would let a report show a command end to end.

**What must not happen.** Writing `transport input ssh` from general knowledge.
The command would probably be correct, attributed to nobody, checked against
nothing — and pasted into a production device on NIRIKSHAK's authority. Nor may
`vetted_by` name a model, a placeholder or the project generically: the field
exists to name the person who is accountable for the commands.

---

---

## 7. Line-level ground truth for the similarity layer

**Blocks:** top-3 mapping accuracy on any population, and confidence calibration.

**State.** The similarity layer ships at P10 and works. What does not exist is
ground truth of the form *this unknown line means `ssh_version`*. P9 labelled
canonical **fields**, not lines, so its labels cannot score a retrieval layer.

Decision D39 declined to author line labels for the purpose of making the metric
computable, and that was the right call: manufacturing evaluation data to fill a
metric is the failure this project has refused at every phase. The arithmetic
lives in `eval/similarity.py`, is tested against constructed observations, and
reports `NOT MEASURED` with its reason.

**Calibration is blocked twice over.** It needs the same labels, *and* enough of
them: `api/learn/calibration.py` refuses to fit below 200 observations, while the
development split holds roughly a dozen security-relevant unknown lines. Until
both are true, every suggestion stays `UNCALIBRATED_SIMILARITY` and the field
abstains (decision D42).

**What would close it.** Real administrator confirmations.

**The mechanism now exists.** P11 shipped the confirmation loop: every decision
records a `TrainingExample` holding what was proposed and what the human chose,
and `/training/examples` reports the population. That is precisely the labelled
data both metrics need — and P11 produced **none of it**, because building a
recorder is not the same as having something recorded. The gap closes through
*use*, one confirmation at a time, which is the whole argument for measuring
top-3 accuracy in production rather than only on a benchmark.

Note what will still be missing when confirmations do accumulate: they are drawn
from whatever devices a deployment happens to ingest, so the population is
representative of that fleet and of nothing else. A top-3 figure computed from it
must say whose fleet it came from.

**What must not happen.** Authoring line labels to produce a number, or lowering
the calibration floor to fit the data available. Both would turn a refusal into a
claim without changing what is known.

---

## 8. A corpus written by more than one author

**Blocks:** nothing. **Affects:** any claim that coverage compounds across vendors.

**State.** Every corpus file was hand-written by the same author, so idioms repeat
verbatim across platforms: `ntp server 192.0.2.20` appears in both the Cisco and
Arista configurations, character for character. A similarity layer will retrieve
across those vendors flawlessly for a reason that has nothing to do with
embeddings.

The Concept Report's claim that *"teaching vendor A measurably improves the
suggestions offered for vendor B"* cannot be tested on data where A and B were
written by one person using one vocabulary.

The single case in the corpus that genuinely tests it is Juniper's
`set system services ssh protocol-version v2` against Cisco's
`ip ssh version 2` — different vocabulary, no string overlap. One case is a
demonstration, not a measurement.

**What would close it.** Configurations from different origins, ideally real and
sanitised (gap 3 above), so cross-vendor retrieval is scored on genuine syntactic
distance rather than on a shared authorial habit.

---

## What P9 claims, now that it has run

The harness exists and has produced numbers (ADR 0016). What it measured, on a
synthetic corpus of four labelled evaluation files:

- vendor detection correct on 4 of 4;
- Cisco field extraction — precision 100% over 11 assertions, recall 73.3% over
  15 determinable fields, **wrong-confident rate 0**;
- Cisco evidence integrity 11 of 11 — every asserted value cited the line the
  labeller read;
- Cisco compliance verdicts — FAIL precision 100% (3/3), **FAIL recall 50%
  (3/6)**;
- Arista and Juniper recall **0** — no parsing pattern exists for either, which
  this measures honestly rather than averaging away.

Every one of those gaps traces to an entry on this list. The harness turned the
backlog from an argument into an arithmetic.

Written here so the evaluation report inherits it rather than re-deriving it:

- **May** state per-field precision and recall for the eight parsed Cisco fields.
- **May** state that the compliance evaluator, the ACL analyser and the abstention
  rules are correct on the cases tested, naming which were corpus-derived and
  which were constructed.
- **May not** claim absence-aware evaluation accuracy — the branch never fires on
  real data.
- **May not** claim ACL detection rates — no real access list has been seen.
- **May not** claim remediation coverage, or that NIRIKSHAK produces
  device-specific remediation for any platform — no snippet has ever resolved.
- **May not** claim any top-3, generalisation or calibration figure — all three
  are blocked, and the report says so with the reason rather than a zero.
- **May not** claim exposure-aware prioritisation of anything. The stage exists
  (P12) and abstains on every finding for want of interfaces and ACLs. A
  severity-ordered list is specifically not offered in its place.
- **May not** claim peer-baseline outlier detection on real data. Every cohort is
  below the minimum size, so the feature reports refusals; its arithmetic is
  tested against constructed observations only.
- **May not** claim that coverage compounds across vendors; see gap 8.
- **May not** describe its ground-truth labels as independent. They are
  unreviewed, and the Cisco labels share an author with the Cisco patterns
  (decision D35). A second reader clearing `review_status` is a data change, and
  it is the cheapest item on this page.
- **May not** claim coverage against CIS, NIST, DISA STIG or ISO/IEC 27001.
- **May not** claim universal vendor coverage, or present any result from the
  synthetic corpus as real-world accuracy.
