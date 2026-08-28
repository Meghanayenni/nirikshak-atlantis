# ADR 0019 — The confirmation loop, and where trust actually originates

- **Status:** Accepted
- **Date:** 2026-08-28
- **Phase:** P11
- **Decisions:** D44 (a composition package), D48 (admin-trained provenance),
  D49 (the queue is persisted), D50 (the queue works without a model)
- **Defects:** DEF-10 (fixed), DEF-12 (fixed)
- **Related:** ADR 0017 (the similarity layer), ADR 0018 (model acquisition),
  ADR 0020 (activation and checksums)

## Context

P10 built the advisory branch and stopped exactly where it had to. Every
suggestion left `api/learn/` carrying `UNCALIBRATED_SIMILARITY`, which forces the
field to UNKNOWN, and the ADR said plainly what would lift it:

```
administrator confirms → pattern enters the pack → re-parse → DETERMINISTIC match
```

P11 is that arrow. It is the first phase since P5 whose central deliverable is
not blocked on sourcing, because the data it needs is a person's judgement rather
than a vendor document — and it is the phase that makes Rule 5 demonstrable
rather than merely stated: a new mapping ships as YAML, activated at runtime, no
redeployment and no restart.

## What was built

| Module | Responsibility |
| --- | --- |
| `queue.py` | Residue as one decision at a time, honest about the model |
| `compile.py` | A confirmed line becomes a boring, readable pattern |
| `activation.py` | DRAFT → VALIDATED → ACTIVE, and back again |
| `service.py` | The loop, and the five audit records it writes |

Plus persistence (`api/db/training.py`, migration `0003`) and an admin-only API
(`api/routers/training.py`).

Five audit actions that had existed in the enum since P1 and were emitted by
nothing now fire: `ADMIN_CONFIRMED`, `ADMIN_CORRECTED`, `PACK_CREATED`,
`PACK_ACTIVATED`, `PACK_ROLLED_BACK`.

## D44 — a composition package, so `learn → db` can stay forbidden

`tests/architecture/test_import_rules.py` carried the edge
`("learn", "db", "suggestions are produced, not persisted, until P11 records a
decision")`. That annotation invited P11 to relax it. **The decision recorded was
to keep it.**

An advisory branch that can write is one that can eventually write something
nobody confirmed. So `api/train/` exists as a composition layer that may import
`learn`, `db`, `audit`, `ingest.packs`, `parse` and `models`, and ten new
forbidden edges keep it away from anything that decides: it may not import
`comply`, `report`, `remediate` or `analyse`, and `comply`, `normalise`,
`report`, `learn`, `parse` and `ingest` may not import it.

The last two are the ones worth naming. `parse → train` is forbidden because
parsing applies a pack and must not know one was *learned* — a parser that could
tell would be a parser that could treat the two differently. `ingest → train` is
forbidden because pack loading must not depend on the layer that writes packs, or
a deployment that never trains anything would still carry the training loop.

`api.train` also joins `PIPELINE_PACKAGES` in the evaluation boundary, for the
argument GAP-1 made one step further on: a label loader able to reach the
confirmation layer would be ground truth able to see — or to become — the mapping
it scores.

## D48 — a learned mapping never claims to be a shipped one (DEF-10)

`api/parse/fields.py` hard-coded `source=PatternSource.BUILTIN` on every field's
provenance and `ConfidenceMethod.DETERMINISTIC` on every value. True of every
pattern in the repository until P11, and false the moment the first administrator
confirmed one.

`FieldProvenance.source` is documented as recording *whether a human vetted it*.
Reporting a compiled confirmation as vendor-shipped erases the only distinction
the learning loop creates, and an operator could not tell a mapping NIRIKSHAK
shipped from one their colleague confirmed last Tuesday.

Fixed by reading the pattern that actually fired. A field from an
`ADMIN_TRAINED` pattern now carries `ADMIN_CONFIRMED`, which ADR 0011's
population table has listed since P4 and which `EXACT_CONFIDENCE_POPULATIONS`
already admitted — so **no contract changed and no verdict moved**. Both
populations are floored at exactly 1.0, both are deterministic, and the engine
passes the method through without branching on it. They are kept apart because
they are different *kinds* of claim: one rests on a pack somebody reviewed, the
other on a named administrator's judgement recorded in the chain.

The regression guard is the interesting half: a Cisco field read by a
hand-written pattern must still report `BUILTIN` / `DETERMINISTIC`. A fix that
made everything look admin-trained would have been just as wrong.

## D49 — the queue is persisted

Residue was computed during normalisation and discarded. Adequate while nobody
looked at it; not adequate for a queue a person works through over days.

Clustering is fleet-wide by design — one shape across thirty devices is one
decision worth thirty — so recomputing the queue would mean re-parsing every
configuration each time it is opened. Migration `0003` adds `unknown_line`, keyed
by `(file_id, line_number)`: the position of a line in a file already ingested,
which is durable across sessions and across pack activations.

**Only scrubbed text is stored.** `api/normalise/residue.py` has redacted residue
since P5 (decision D12), and an architecture test asserts that nothing in
`api/train/` reads `ConfigNode.raw_line`. The migration has no column an
unredacted line could be written to.

Recording *replaces* a file's entries rather than merging them. Without that, a
line the new pack now reads would linger in the queue forever — the re-parse
simply would not mention it — and the loop would look ineffective while it was
working.

## D50 — the queue works with no model, and says so

The `[ai]` extra is deliberately uninstalled here (ADR 0018), so on this machine
**no suggestion can be produced at all**. The queue still works, and this is the
decision that matters most in the phase.

A `QueueEntry` never carries a bare tuple of suggestions. It carries a
`SuggestionOutcome` with an explicit state — `RANKED`, `MODEL_UNAVAILABLE`,
`INDEX_EMPTY` or `NOT_CONFIRMABLE` — and every non-ranked state must carry a
reason, enforced in `__post_init__` rather than by convention.

The reason is that an empty list is indistinguishable from *"the model ran and
found nothing similar"*, and those are opposite statements. One means **we could
not look**; the other means **we looked, and the index is unlike this line**. An
administrator who cannot tell them apart is being asked to confirm a mapping
while being misled about what informed the question — and their confirmation is
permanent.

This is DEVELOPER_GUIDE.md §14's *"a mode that silently returns empty output is
indistinguishable from a clean result"*, applied to the one screen where a
mistake cannot be taken back.

Confirming with no suggestion at all remains entirely valid. The administrator
was always the authority; a confirmation made without a ranking is the
`CORRECTED` path the contract has modelled since P1. What is refused is
pretending a ranking happened.

`/health` now reports model availability, which ADR 0018 deferred to *"the phase
that gives it meaning"* — this one.

## The compiler is deliberately unambitious

DEVELOPER_GUIDE.md §4 is a constraint on style, not only on correctness: *"Do not generate
clever regexes. A pattern an administrator cannot read is one they cannot
verify."*

So `compile.py` tokenises, escapes every token but the captured one, substitutes
`(\S+)`, and anchors — at `$` as well as `^`, because the engine matches with
`re.match` and an unclosed pattern for `ip ssh version 2` also fires on
`ip ssh version 2 extra`. Tokens join with `\s+` so alignment differences between
exports do not become mis-parses.

`logging host 192.0.2.10` compiles to `^logging\s+host\s+(\S+)$`. That is the
whole trick, and it is meant to be.

It refuses more than it produces: a blank line, prose beyond 24 tokens, a
single-token line where the one token is the capture (`^(\S+)$` matches
everything), a field outside `CANONICAL_FIELD_NAMES`, a decision that confirmed
nothing, and a decision naming no administrator.

**Scope defaults to the literal confirmed header** (ADR 0011, D9). Numeric
generalisation is an explicit opt-in, because `line vty 0 4` and `line vty 0 15`
are different scopes and quietly matching both is how a console timeout gets
reported as a management idle timeout.

**A `Suggestion` cannot become a pattern.** `compile_pattern` takes a
`TrainingExample` and there is no overload accepting anything else — the
learning loop's entire safety argument, expressed as a function signature and
asserted by a test that reads it.

## Consequences

**Measured at P11:** nothing new, and deliberately so. Top-3 accuracy and
calibration remain `NOT MEASURED` and `NOT FITTED`. P11 builds the recorder that
will eventually supply the population SOURCING_BACKLOG gap 7 needs; it does not
get to decide the population has arrived. `/training/examples` reports a count
and a list, and computes no accuracy from either.

**The first observable capability gain since P8.** On
`corpus/arista/dev/sw-leaf-01.cfg` one confirmation shrinks residue and produces
a `logging_hosts` field with evidence citing the exact line — measured in
`tests/integration/test_confirmation_loop.py`, end to end, with the audit chain
verifying afterwards.

**The holdout is untouched.** PAN-OS has no active pack and no XML parser, so it
cannot enter this path at all; the P10 fragment guard now covers `api/train/`
too, and no test opens, hashes or parses a held-out file.

**Not built at P11:**

- Any fitted calibrator — D42 stands.
- Any generalisation or top-3 figure — D37, D39 stand.
- The training GUI — P13, over this API.
- Exposure-aware prioritisation and peer baselines — P12.
- Any framework id, remediation snippet or platform default.
- Any fix to DEF-8 or DEF-3, both of which remain recorded and open.
