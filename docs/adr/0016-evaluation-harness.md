# ADR 0016 — The evaluation harness, and what it is allowed to claim

- **Status:** Accepted
- **Date:** 2026-08-28
- **Phase:** P9
- **Decisions:** D31 (labels authored from the configuration), D32 (a failing
  evaluation device), D33 (generalisation and calibration deferred to P10),
  D34 (detection-only vendors never pooled), D35 (authorship conflict declared
  rather than hidden), D36 (evidence integrity is its own metric)
- **Defects:** DEF-6 (fixed), DEF-7 (closed by D32), DEF-8 (recorded, not fixed)

## Context

The Concept Report §6 states the requirement in one line:

> Accuracy is reported as a measurement, not a claim.

P9 builds the harness that produces the measurement. It adds no pattern, no
rule, no pack and no snippet — a harness that edits what it measures is not a
harness, and that constraint is asserted by a test rather than remembered.

There was no standalone P9 plan. Scope was fixed by the Concept Report §6 and
§4, DEVELOPER_GUIDE.md §13, and ADR 0010's ground-truth clause; this ADR is that plan
written down and the result of running it.

## What the harness found before it could run

Three things, all discovered by reading and measuring rather than from
documentation. Two changed the phase's scope.

### DEF-6 — the manifest claimed labels that did not exist

`corpus/MANIFEST.yaml` carried `labelled: true` on five files from the day the
corpus was committed. `corpus/labels/` contained one file: `.gitkeep`.
**Zero ground-truth labels existed**, and no test read the flag, so the manifest
asserted a property the repository did not have for three phases.

**Fixed.** Four label files now exist, the two holdout entries are
`labelled: false`, and `test_the_labelled_flag_matches_the_filesystem` compares
the flag against the filesystem so it cannot drift again.

### DEF-7 — the evaluation split contained no FAIL verdict

Measured across the three original eval files: **6 PASS, 15 UNKNOWN, 0 FAIL.**
The corpus's only two FAILs sat on a *development* file, which the harness may
not score.

FAIL precision and recall were therefore undefined for the class that matters
most — a compliance auditor that had never been measured on a failing device.
**Closed by D32.**

### DEF-8 — a rule passes the worst case its own rationale names

`NRK-TIMEOUT-001` states in its rationale:

> A timeout of zero means the session never expires and is therefore the worst
> case, not the best.

Its condition is `{ op: lte, value: 600 }`. So `exec-timeout 0 0` scores
`0 <= 600` and returns **PASS**. A device whose management sessions never expire
is reported as compliant with the timeout control.

**Recorded, not fixed.** The fix is a one-line rule edit, and making it inside
the evaluation phase would mean the harness improving its own score. The new
evaluation device uses `exec-timeout 30 0` so no metric depends on the defect
either way.

## D31 — a label is authored from the configuration, never from parser output

ADR 0010 stated the rule. P9 makes it structural, in four layers.

**The contract has nowhere to put a prediction.** `FieldLabel` has no
`predicted_value`, no `confidence`, no parsed `state`, and forbids extra keys. A
pipeline result cannot be written into a label by a caller trying to.

**The loader cannot reach the pipeline.** `eval/labels.py`, `eval/corpus.py`,
`eval/metrics.py` and `eval/errors.py` may import `api.models` and each other,
and nothing else. A loader with a route to the parser could, one refactor later,
fill a missing label in from it. An architecture test asserts the whitelist, and
a second asserts the loader performs no writes at all.

**Every citation is verified against the file.** A label for a present field
records the line number *and the verbatim line text*, and the loader raises
`LabelIntegrityError` if that line does not read that way. This is the discipline
Rule 2 imposes on findings, applied to the labels that score them.

**The labels are bound to exact bytes.** `file_sha256` pins each label set to the
configuration it was written against. A file edited after labelling is refused
rather than scored against ground truth describing a file that no longer exists.

### The determinability doctrine

`Determinability` is the distinction the whole harness turns on. A field the
system declined to answer is a **correct abstention** only when the control
genuinely could not be established from the file; when a human reads it straight
off the page, the same silence is a **miss**.

The doctrine applied, recorded in `corpus/labels/README.md` so a reviewer can
disagree with it:

- **Absence is determinable for fields that exist by being configured** — a
  banner, a list of logging hosts, a list of NTP servers. No `banner` directive
  means no banner, and that is readable.
- **Absence is not determinable for anything else.** An unset SSH version, an
  unmentioned HTTPS listener, an absent password policy — each is a question
  about documented platform behaviour, which NIRIKSHAK has not sourced. Both the
  system and the labeller correctly abstain.
- **No inference chains.** A configured logging host is not labelled as proof
  that the logging subsystem is enabled. A label states what the file says.

Collapsing miss into correct abstention would turn missing parser coverage into a
success rate: a system with no patterns would score perfectly. The arithmetic
prevents it — `correct_abstention_rate` divides by *every* abstention, misses
included, and `test_a_parser_that_reads_nothing_scores_badly` is the assertion
that keeps it honest.

## D35 — the authorship conflict is declared, not hidden

The approved decision asked for **independent human-authored** labels and for a
mechanism ensuring pattern authorship and ground-truth authorship are *not
silently conflated*.

The first clause cannot be satisfied literally in this phase. The Cisco parsing
patterns and the Cisco labels share an author, and no amount of care makes an
author independent of themselves. Correlated error between parser and ground
truth is therefore invisible in the Cisco numbers: a field misunderstood while
writing the pattern would be misunderstood the same way while writing the label,
and the measurement would come out clean without proving anything.

So the conflict is made **loud** rather than silent:

| Mechanism | Effect |
| --- | --- |
| `labelled_by` | Records the author honestly. No label claims a human wrote it. |
| `pattern_author_conflict` | Declared true for both Cisco files, with a mandatory note |
| `review_status` | Every label ships `unreviewed` |
| `is_independent` | Requires **both** a review and no conflict |
| Report section 2 | Prints `NOT INDEPENDENT GROUND TRUTH` and explains why |

Arista and Juniper carry no conflict: no parsing pattern has ever been written
for either platform, so there is nothing the labeller could have been influenced
by. That asymmetry is real and the report shows it.

**Clearing the flag is a data change.** A reviewer reads the configuration,
checks each label, and sets `review_status: reviewed` with `reviewed_by`. Once a
label is reviewed by someone other than its author, `is_independent` becomes true
and the harness reports it in the independent population. No code changes.

## D32 — a failing evaluation device

`corpus/cisco/eval/sw-dist-11.cfg`, 33 lines, written fresh rather than templated
from an existing file.

**No pattern was authored from it.** It uses only directives the shipped
`cisco/ios` pack recognised at P4. The constraint was verified rather than
asserted: both corpus-separation guards still pass, and the one line that is also
a pack example — `transport input telnet ssh` — already appears in
`corpus/cisco/dev/sw-access-02.cfg:17`, so the example remains dev-sourced.

| Directive | Field | Rule | Verdict |
| --- | --- | --- | --- |
| `transport input telnet ssh` | `telnet_enabled = true` | NRK-TELNET-001 | FAIL, critical |
| `ip ssh version 1` | `ssh_version = 1` | NRK-SSH-001 | FAIL, high |
| `exec-timeout 30 0` | `idle_timeout = 1800` | NRK-TIMEOUT-001 | FAIL, medium |
| `ip http server` | *no pattern exists* | NRK-HTTP-001 | UNKNOWN — a labelled miss |

The last row is the most useful observation in the corpus. The pack deliberately
has no pattern for the affirmative HTTP form (`packs/builtin/cisco_ios/1.1.0.yaml`
lines 108–111), because it appears in no development file. A human reading line
12 determines the value immediately; the system cannot. That is a **miss**, and
it is exactly the recall loss the three-state label exists to expose.

Adding a pattern to close it is forbidden by D32 and would destroy the case.

`exec-timeout 15 0` under `line con 0` is present and correctly excluded from the
vty scope — a console timeout is not a management idle timeout, and the scoped
pattern proves it on data it was not authored from.

## D33 — generalisation and calibration are P10

Both metrics the Concept Report names are defined over the similarity layer.
Generalisation is *"the proportion of its commands for which the similarity layer
proposes the correct field within its top three suggestions"*; calibration is
similarity scores *"calibrated against a hand-labelled corpus"*.

`api/learn/` holds only `__init__.py`. `sentence_transformers`, `faiss`, `torch`
and `numpy` are absent — the `[ai]` extra installs at P10 by design. This is a
phase-ordering inconsistency in the project's own plan, not a fault in any phase.

**Consequence, and it is the good one:** the PAN-OS holdout is not opened at P9 at
all. The harness has no feature that needs it, which is a stronger seal than any
discipline. Reinforced by `SEALED_SPLITS`, a `SealedSplitError` raised before any
file handle opens, and a test that greps `eval/` for path fragments that could
locate those files.

Calibration is separately impossible: every field carries `DETERMINISTIC`
confidence at a constant `1.00`, and R7 forbids reading that as a probability.
There is one population and nothing to calibrate.

## D34 — detection-only vendors are never pooled

Arista and Juniper ship zero parsing patterns. A fleet-wide recall figure would
be dominated by "no pack was written", which is a coverage statement wearing an
accuracy statement's clothes.

Every metric therefore carries its vendor and its pack status, and the report
computes no combined figure anywhere. `has_parsing_pack` travels with each
observation so the renderer labels the row without re-deriving it.

## D36 — evidence integrity is its own metric

A field can hold the right value and cite the wrong line. Rule 2 makes that a
failure rather than a rounding error: a security fact carrying a citation that
does not support it is worse than no claim at all, and nothing measured it before.

Scored in its own population, in its own column, never folded into precision.
Only where a citation can be checked — the system asserted a value *and* the
labeller read it off a specific line. A label resting on the absence of a
directive has no line to point at and is excluded rather than counted as a
missing citation.

## Results

Measured at `e93d656` + P9, over the four labelled evaluation files. **The PAN-OS
holdout was not opened.**

| Vendor | Pack | n | correct | wrong | miss | correct-abstention | precision | recall |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| cisco | yes | 26 | 11 | 0 | 4 | 11 | 100% / 11 | 73.3% / 15 |
| arista | **no** | 13 | 0 | 0 | 3 | 10 | n/a | 0% / 3 |
| juniper | **no** | 13 | 0 | 0 | 4 | 9 | n/a | 0% / 4 |

- **Vendor detection:** 4 / 4 correct.
- **Wrong-confident rate: 0 of 11 assertions.** A zero here is *not* evidence of
  accuracy — the system asserts a value only where a deterministic pattern
  matched, and it holds patterns for one platform. A system that asserts little
  cannot assert much wrongly. The report says so in the same block as the number.
- **Evidence integrity (Cisco): 11 / 11.** Every asserted value cited the line the
  labeller read.
- **Compliance verdicts (Cisco):** FAIL precision 100% (3/3), FAIL recall
  **50% (3/6)**. Every missed failure abstained rather than passing — a FAIL
  reported as UNKNOWN is an honest gap; a FAIL reported as PASS would be a device
  presented as compliant when it is not. A test asserts no verdict ever
  contradicts its label in that direction.
- **Absence branch coverage:** `unknown` 5, `absent_default` **0**. The
  `AbsenceAction.EVALUATE` branch has never fired on real data.

The three missed Cisco failures are the two absent banners and the enabled HTTP
server — all cases where a human reads the file and the parser has no pattern.

## Consequences

`eval/` is a new top-level package with a hard internal boundary: four modules
that may not import the pipeline, three that may. `api/models/label.py` is a new
leaf contract.

`tests/integration/test_corpus_policy.py` now separates *configuration files*,
which the manifest tracks, from *label files*, which it does not — a label
recording its own checksum would be circular. Labels remain inside every
sanitisation scan, because they quote configuration lines verbatim and a
credential laundered through a citation is still a credential in the repository.

**Not built at P9:**

- **Generalisation and top-3 accuracy** — P10 (D33).
- **Calibration** — P10; there is nothing to calibrate (D33).
- **Any fix to DEF-8** — it belongs to whoever owns the rule.
- **Any new pattern, rule, pack or snippet.** Asserted by a test.
- **A fix for the Arista and Juniper recall of zero.** That is missing pack
  coverage, measured honestly and reported as such, not a harness problem.

**What P9 may not claim** is unchanged from the plan, minus the FAIL line that
D32 closes: no real-world accuracy, no broad vendor coverage, no absence-aware
accuracy, no calibration, no generalisation, no ACL or framework or remediation
coverage — and **not that its labels are independent ground truth**, because they
are unreviewed and for Cisco share an author with the patterns being scored.
