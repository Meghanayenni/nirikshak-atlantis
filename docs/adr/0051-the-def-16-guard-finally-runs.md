# ADR 0051 — The DEF-16 guard finally runs

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D130 (build the fixture with the training loop, not by hand),
  D131 (scan the live directory without skipping)
- **Affects:** `tests/integration/test_contamination_guard.py` (new)
- **Defects:** DEF-16 — **still open**

## The guard that had never detected anything

DEF-16 is the defect that actually bit this project. An administrator uploaded a
configuration, worked the Needs-review queue, and confirmed what two lines
meant. Both came from `corpus/cisco/eval/edge-rtr-11.cfg` — a file whose entire
purpose is to be a regression fixture nobody authors from — and the patterns
compiled from them went into the active Cisco pack, teaching the parser answers
from the split it is measured on.

**Nobody misused the interface.** The loop did exactly what it is built to do.

`test_no_trained_pack_quotes_an_evaluation_or_holdout_line` exists to catch
exactly that, and it scans `packs/trained/` — gitignored deployment state (D45),
empty on every checkout and on CI. It has skipped every time it has ever
executed. The contamination that caused the P15 reset was found by tracing pack
examples back to corpus files **by hand**, which is the thing the guard was
built to make unnecessary.

ADR 0042 gave the detection *function* constructed input, which proved the
arithmetic. It did not give the guard a populated directory, so the scan itself
had still never run against anything.

## D130 — build the fixture with the loop, not by hand

The pack under test is produced by `compile_pattern` →
`draft_with_pattern` → `validate` → `activate`, writing into a temporary trained
root, from a `TrainingExample` carrying the real line:

```
ip ssh server algorithm encryption aes128-cbc
```

That line is in `corpus/cisco/eval/edge-rtr-11.cfg` and in no development file.
It became `p-weak-ciphers-admin-002` in `cisco/ios` 1.1.4 through 1.1.6, and it
is quotable today only because ADR 0031 committed the deleted trained packs to
`packs/archive/`.

**A hand-written YAML fixture would have proved the wrong thing.** The question
is whether the guard catches what an administrator's confirmation *turns into*,
and only the loop produces that — the pattern id, the retained example, the
provenance block and the version bump are all its doing. A fixture written by a
test author proves the guard catches what a test author writes.

Run end to end, the loop mints `1.3.1.yaml` and the scan reports:

```
1.3.1.yaml:p-weak-ciphers-admin-001 quotes
  'ip ssh server algorithm encryption aes128-cbc'
```

The negative case is the same loop over `ip ssh version 2`, from
`corpus/cisco/dev/rtr-core-01.cfg`, and reports nothing. Without it the first
test would prove only that the guard flags everything, and a guard that flags
everything has to be ignored to get any work done.

Two further properties are covered because the original incident had both: the
loop must still **retain** the confirmed example (D44) or the guard would find
nothing to object to and report clean for the wrong reason; and the scan must
take **every** pack in the directory rather than the newest, because the
contamination was in three consecutive versions and checking only the active one
would have reported clean on a directory holding the answer three times over.

`outcome=CORRECTED`, not `ACCEPTED_RANK_1`: the contract refuses an accepted
rank unless a suggestion was shown at it, and no model was running when this
happened. The administrator supplied the field themselves, which is precisely
that outcome — a detail the contract enforced and the fixture had to match.

## D131 — scan the live directory, and do not skip

`test_the_repository_itself_is_still_clean` runs the same detection over the
real `packs/trained/` and **asserts rather than skipping**. On a checkout the
directory is empty and the assertion passes with nothing in it, which is true
and worth stating; on a machine somebody has trained, it is the guard actually
guarding.

The architecture-suite scan keeps its skip, because its own registry entry in
`test_skip_guards.py` explains what covers the path it cannot reach — and that
is now this file rather than a constructed-input test.

## This does not close DEF-16

**The training loop still has no notion of a corpus split.** An administrator
can upload `edge-rtr-11.cfg` today, work the queue, confirm a line, and
contaminate the measurement exactly as before. Nothing in `api/train/` consults
`corpus/MANIFEST.yaml`, and for an arbitrary operator upload it cannot — most
deployments have no corpus at all.

What changed is narrower and worth having: the detector is no longer
unexercised. It is shown catching the real line, on a pack the real loop wrote,
with the negative case beside it. Before this, the repository's defence against
its own worst incident was a scan that had never once looked at anything.

The fix remains a guard inside the confirmation loop — a check, in *this*
repository's deployment only, that a confirmed line does not come from a file
the manifest marks `eval` or `holdout`. That is a change to the training
workflow with its own decision, and it is not made here.
