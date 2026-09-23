# ADR 0042 — A test that skips is a test that does not test

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D110 (every `skipif` is paired or registered), D111 (a skip
  whose subject cannot be reached is exercised on constructed input instead)
- **Affects:** `tests/architecture/test_skip_guards.py` (new),
  `tests/architecture/test_train_boundaries.py`,
  `tests/integration/test_similarity_offline.py`,
  `tests/integration/test_training_api.py`

## Context

ADR 0041's finding was not that PDF works. It was that four tests carrying
`skipif(availability().available)` meant the PDF endpoint was exercised by
nothing on a machine where it worked — for ten phases, with a green suite and
three documents calling it blocked.

At 2,060 tests, two or three more of those were plausible. This is the audit.

## The audit — all fourteen guards

| Guard | Skips here? | Opposite asserted? | Verdict |
| --- | --- | --- | --- |
| `test_pdf_adapter` ×4 — GTK present | yes | **now yes** (ADR 0041) | fixed |
| `test_reporting` ×2 — GTK present | yes | yes (ADR 0041) | ok |
| `test_reporting` ×1 — GTK absent | no | is the positive | ok |
| `test_similarity_offline` ×3 — model present | yes | **no** | **gap** |
| `test_training_api` — model present (inline) | yes | **no** | **gap** |
| `test_train_boundaries` — no trained pack (inline) | yes | **no** | **gap** |
| `test_no_device_libraries` — `telnetlib` (inline) | yes | yes, elsewhere | ok |
| `test_eval_boundaries` — module missing (inline) | no | defensive only | ok |

**Three gaps, and one near miss worth recording.** The similarity guards read
`skipif(availability().available)` with the reason *"the [ai] extra is installed
here"* — the same spelling as the PDF guards. That looked like a copy-paste
defect until the imports were checked: `availability` there is
`api.learn.embedding.availability`, a different function of the same name. The
guard is correct. Verified rather than reported.

### Gap 1 — `embed()` was asserted by nothing

The model is installed here, weights and all:

```
availability: available=True, weights_present=True
embed(["ip ssh version 2", "transport input telnet"]) -> 2 vectors, dim 384
```

Three tests covered the refusal and skipped. Nothing covered the entry point to
the entire similarity layer. Exactly ADR 0041's shape, in a different package.

Three tests added, and what they assert matters as much as that they exist:
shape rather than values (an embedding is not reproducible across model
versions, and pinning numbers would make a legitimate upgrade look like a
regression), determinism for one line (a queue an administrator cannot recreate
is a queue they cannot confirm against), and — on real vectors rather than
constructed ones — that a suggestion is **still** `UNCALIBRATED_SIMILARITY` and
still not evidence. The last is the Rule 1 gate, proven for the first time on
the path a deployment with the `[ai]` extra actually takes.

### Gap 2 — the ranked queue was asserted by nothing

`test_an_unavailable_model_is_never_an_empty_suggestion_list` walks the queue
for a `model_unavailable` entry and skips when the model works. The only other
assertion about suggestions in the suite was `== []`, in that same refusal path.

So the queue state a deployment reaches — `ranked`, with up to three
candidates — had no test. One added, asserting that ranking *happens* and stays
labelled `is_probability: false`, never which suggestion wins: the ordering
comes from an uncalibrated model and pinning it would turn a model change into a
failure.

### Gap 3 — the contamination guard had never run

`test_no_trained_pack_quotes_an_evaluation_or_holdout_line` scans
`packs/trained/` for a pattern example taken from the evaluation split. That
directory is gitignored deployment state (D45), so it is **empty on every
checkout and on CI**, and the scan has skipped every time it has ever run.

This is the guard for DEF-16 — the defect where an administrator working the
review queue compiled two patterns out of `edge-rtr-11.cfg`, a file whose whole
purpose is to be a regression fixture nobody authors from. The detection for the
repository's own contamination incident had never executed against real input.

**D111**: the detection is extracted to `contaminated_examples()` and driven
with a constructed pack carrying the real line —
`ip ssh server algorithm encryption aes128-cbc`, which appears in
`corpus/cisco/eval/edge-rtr-11.cfg` and in no development file, and which is
quotable today only because ADR 0031 committed the deleted trained packs to
`packs/archive/`. A second test feeds it a development-split example and expects
silence, so the detector is not simply flagging everything.

The repository scan stays, and still skips. What changed is that it is no longer
the only thing standing between a recurrence and nobody noticing.

## D110 — make the recurrence structurally impossible

`tests/architecture/test_skip_guards.py` enforces two rules across every test
module:

1. **Every `skipif(C)` has a `skipif(not C)` in the same module**, or the pair is
   listed in `PAIRED_BY_HAND` with a written reason.
2. **Every inline `pytest.skip()` call site is listed in `INLINE_SKIPS`** with a
   written reason.

A new unpaired guard fails the build until somebody writes down what covers the
other state. The registry cannot drift, because drifting is the failure.

Two further checks keep the registries honest in the other direction: an entry
describing a guard that no longer exists fails (stale justification is how the
defect register rotted, ADR 0046), and a reason shorter than twelve words fails,
because a registry of empty strings would satisfy everything above and mean
nothing.

And the detector is made to fail on purpose. `test_the_pairing_detector_actually_fires`
runs the helpers over constructed module sources — one unpaired, one paired, one
inline — because `test_every_skipif_has_its_opposite` would pass just as
happily if `_skipif_conditions` returned nothing, which is the same failure
mode one level up. The repository already makes this argument about its import
detector; it applies here for the same reason.

## What this does not claim

It does not assert the recorded reasons are *good* ones. It asserts somebody had
to write one, beside the guard, in a file a reviewer opens. Four reasons are
recorded today and each names the test that covers the other state.

It also does not make skipping wrong. Skipping where GTK or the model is
genuinely absent is correct, and the refusal tests are the reason the 503 path
and the `ModelUnavailableError` path still have coverage. The defect was never
the skip — it was the **absence of its opposite**.
