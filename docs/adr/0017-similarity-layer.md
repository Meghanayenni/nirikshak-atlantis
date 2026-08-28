# ADR 0017 — The similarity layer, and what it is not allowed to conclude

- **Status:** Accepted
- **Date:** 2026-08-28
- **Phase:** P10
- **Decisions:** D37 (generalisation deferred), D38 (seed from development packs
  only), D39 (no line labels authored for a metric), D41 (DEF-9 fixed), D42
  (ship uncalibrated), D43 (the learn layer reads no corpus)
- **Defects:** DEF-9 (fixed), GAP-1 (closed), OBS-4 (recorded)
- **Related:** ADR 0018 (model acquisition)

## Context

P10 introduces the only advisory branch in a deterministic system. The Concept
Report describes it as clustering unrecognised lines, ranking three candidate
mappings, and asking an administrator — *"it does not guess — it asks the
administrator, and permanently learns the answer."*

The engine is buildable in full. Two of the three measurements it exists to serve
are not, and this ADR is mostly about being precise on which is which.

## What was built

| Module | Responsibility |
| --- | --- |
| `signature.py` | Token-shape signatures. Pure string handling |
| `cluster.py` | Deterministic grouping by shape, ranked by frequency |
| `embedding.py` | The model adapter, behind an availability probe |
| `index.py` | Labelled examples, seeded from development packs only |
| `suggest.py` | Top-3 retrieval, and the gate that keeps a score a score |
| `calibration.py` | Fitting machinery, and the refusal to use it |

Nine forbidden import edges for `api/learn/` have guarded an empty package since
P1. Five more were added for the reverse direction, and the package now honours
all fourteen.

## D42 — a similarity score never becomes a confidence

Every `Suggestion` leaves the package carrying
`ConfidenceMethod.UNCALIBRATED_SIMILARITY`. The contract has treated that as
forcing the field to UNKNOWN since P1: *"the score may be recorded and shown to
an administrator, but it can never support a claim."*

The property is structural, not a convention:

- `normalise` may not import `learn`, so a suggestion has no path into a
  canonical field.
- `comply` may not import `learn`, so it has no path into a verdict.
- `Suggestion` has no `value` field. It proposes what a line *means*, never what
  the device is configured to — so even a confirmed suggestion is a mapping, not
  a fact.
- The contract refuses `CALIBRATED_SIMILARITY` without a calibrated value, and
  refuses a raw score stored in the calibrated slot.
- `assert_never_confidence` raises at the package boundary rather than returning
  a flag a caller could ignore.

`test_a_perfect_score_is_still_not_a_confidence` is the argument in one
assertion: a similarity of exactly 1.0 — an identical line already in the
index — produces a suggestion that still abstains.

Coverage therefore grows one way only:

```
administrator confirms → pattern enters the pack → re-parse → DETERMINISTIC match
```

**No calibrator is fitted and none ships.** `active_calibrator()` returns `None`,
and `fit()` refuses below 200 observations. That floor is not a statistical
derivation and is not presented as one — it is set plainly above what this corpus
can supply so the refusal is unambiguous rather than marginal. A curve fitted on
a dozen points is a claim about how often the system is right, made from a sample
too small to support one: an unsourced platform default wearing a probability.

## D37 — generalisation is blocked, and it is not the similarity layer's fault

P9 deferred held-out generalisation to P10 because `api/learn/` was empty. P10
fills it, and finds a different obstacle underneath.

The metric is defined over **the held-out vendor's commands**. Reading them means
parsing its configuration format. That parser raises
`UnsupportedSyntaxModeError`, and its own deferral note — written at P4 — says it
waits for *"an XML sample independent of the PAN-OS holdout"*, because building it
from the held-out files would destroy the experiment they exist for. No
independent sample exists.

The dependency is circular and no code closes it. **The holdout was not opened at
any point during P10**, and the evaluation report renders the metric as
`NOT MEASURED — BLOCKED` with the reason rather than as a zero.

Top-3 accuracy on any *other* population is separately blocked: it needs
line-level ground truth, P9 labelled fields rather than lines, and D39 declined
to author line labels for the purpose of making a metric computable. The
arithmetic exists in `eval/similarity.py` and is tested against constructed
observations; it has no population it is allowed to run on.

## D38 — the index is seeded from what already exists

Eleven `(line, canonical field)` pairs, eight fields, one vendor — every one a
pattern example already declared in a shipped pack, and already required by
`test_every_pack_example_comes_from_the_development_split` to appear verbatim in
a development file.

Nothing was authored for the index. Identity patterns are excluded: a hostname is
not a canonical security field, and indexing one would let the layer propose
`hostname` as the meaning of a security directive.

`corpus/seed_examples/index.yaml` is a readable projection of what the code
builds, so the contents are reviewable without running anything.

**The index is small and the code says so.** `ExampleIndex.describe()` returns
the count, the field coverage and the vendor coverage, and that sentence is what
the report and the P11 training screen print.

### A caveat that will matter at P11

The corpus was written by one author, so `ntp server 192.0.2.20` appears verbatim
in both Cisco and Arista files. Cross-vendor retrieval will look excellent for a
reason that has nothing to do with embeddings. The one genuinely interesting case
is Juniper's `set system services ssh protocol-version v2` against Cisco's
`ip ssh version 2` — different vocabulary, no string overlap to cheat on. One
case is a demonstration, not a measurement, and no document may present it as
evidence that coverage compounds.

## D41 — DEF-9, the Arista comment prefix

The Arista pack declared `comment_prefixes: ()`. Arista EOS uses `!` exactly as
Cisco IOS does, and the Cisco pack has declared it since P4. So every `!` line
became a parse node and landed in the unknown-line queue: **23 of 57 residue
lines, 40% of the queue**, none of it configuration.

`api/normalise/residue.py` states the invariant that broke, in its own docstring:
*"a queue full of `!` and banner prose is impossible by construction rather than
by filtering."* For Arista it was neither.

Fixed as pack version `1.0.1`, one line changed, `1.0.0` deprecated. Authored
from the development files, which use `!` as a section separator throughout — a
reading of the corpus, not general vendor knowledge. **No parsing pattern was
added**; the pack remains detection-and-identity only.

**Why identity still works**, verified rather than assumed: `detect` and
`identity` are applied to raw lines at ingestion, before a parse tree exists, so
the `! device: …` signature and the `os_version` pattern that reads it are
unaffected by comment stripping. Arista residue fell from 57 to 34 with detection
and identity intact on all three files.

This mattered little before P10 and matters now: the queue is the input to
clustering, and at P11 it is what an administrator reads one line at a time.
Making a person page through `!` twenty-three times is how careless confirmations
happen, and a careless confirmation enters a vendor pack permanently.

### An observation left alone

Pack checksums are declared and never verified against file bytes — the existing
values match no computable digest, which `tests/unit/test_rulepack_loading.py`
already records as *"a mistake worth not repeating"*. The new pack's checksum is
reproducible (sha256 of the file with the `checksum:` line removed) and the
convention is stated in the file. The older packs are left alone; recomputing
them is not P10's business.

## GAP-1 — the evaluation boundary now excludes the similarity layer

`tests/architecture/test_eval_boundaries.py` forbade the label side from
importing five pipeline packages. `api.learn` was not among them, because the
package was empty when the list was written.

That omission was harmless exactly as long as it stayed empty. It is now the most
important entry: a label loader that can reach the similarity layer is a label
that could be **suggested by the model it scores** — subtler than reaching the
parser, because a suggestion looks like a judgement rather than like output.

Closed in the same change that populated the package, and verified transitively:
the four label-side modules reach no pipeline package through any chain of
`eval.*` imports.

## D43 — the learn layer reads no corpus

`index.py` originally read `corpus/*/dev/` at runtime to verify seed provenance.
An existing P3 guard caught it: `test_no_configuration_text_is_split_with_splitlines`
flagged the `.splitlines()` call, and looking at why exposed the real problem —
**production code depending on a development data directory that no deployment
has**.

`verify_provenance` now takes the corpus as an argument and the tests supply it.
The guarantee is unchanged: every entry originates in a pack pattern example, and
the P4 test has guarded those at source since they were written.

## OBS-4

`TrainingExample.top3_hit` is documented as *"Feeds the P9 metric"*. It was
deferred to P10 and is now blocked beyond it. Corrected to name the metric rather
than a phase.

## Consequences

**Measured at P10:** nothing new. P10 adds no metric to the evaluation report
because every metric it exists to serve is blocked on data. What it adds is the
engine, the gate, and the report wording that says so.

**The P9 numbers are unchanged** except for Arista residue counts, which fell
with the DEF-9 fix. No field or verdict metric moved: no comment line carried a
canonical field. The wrong-confident rate remains **0**, and structurally cannot
move at P10 — a suggestion has no path to a value.

**Not built at P10:**

- **The training GUI and confirmation workflow** — P11.
- **Compiling a confirmed mapping into a pack** — P11.
- **Any fitted calibrator** — D42.
- **Any generalisation number** — D37.
- **Line-level labels** — D39.
- **Ollama or any local LLM** — no consumer exists.
- **Any pack, rule or snippet change** beyond the approved DEF-9 fix.
- **Any fix to DEF-8**, which remains recorded and unfixed.
