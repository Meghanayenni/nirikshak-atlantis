# Evaluation reports

`evaluation.txt` is the current measurement, committed so the numbers are
reviewable without running anything.

## Regenerating

```bash
make evaluate            # print and write eval/reports/evaluation.txt
python -m eval.run       # print only
```

On unchanged inputs the only line that differs between runs is `Generated`.
Everything else is deterministic, which is what makes the report diffable —
a parser change shows up as a diff in the numbers rather than as a silently
different document.

## What the exit code means

The harness exits non-zero only when the measurement **could not be made
honestly**: a label whose citation no longer matches its file, a configuration
edited after labelling, a sealed split touched, a manifest that disagrees with
the labels.

It does **not** exit non-zero when the numbers are bad. A harness that fails the
build on a low score invites the score to be improved by editing the harness.

## Reading it

Two habits the report follows, and one figure that is easy to misread.

**Every rate carries its denominator.** `100.0% / 11` is precision over eleven
observations. A rate printed alone invites the reader to assume a larger sample
than exists.

**Populations are never merged.** Vendors with a parsing pack and detection-only
vendors appear in separate rows, and no combined figure is computed anywhere
(decision D34).

**The wrong-confident rate is currently zero, and that is not a good result on
its own.** The system asserts a value only where a deterministic pattern matched,
and it holds patterns for one platform. A system that asserts little cannot
assert much wrongly. Read it beside the miss counts, never instead of them.

## What it is measured on

A synthetic corpus of hand-written configurations, scored against labels that are
**unreviewed** — and, for Cisco, written by the author of the Cisco parsing
patterns. These are synthetic-corpus results and are not real-world accuracy.

See `docs/adr/0016-evaluation-harness.md` and `corpus/labels/README.md`.
