# ADR 0032 — A check may bound a value at both ends

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D83 (conjunction, not a new operator), D84 (an unevaluable
  conjunct dominates a false one)
- **Defects:** DEF-8 (fixed)
- **Affects:** `api/models/rule.py`, `api/comply/conditions.py`,
  `api/comply/engine.py`, `api/comply/rulepacks.py`,
  `rules/canonical/NRK-TIMEOUT-001.yaml`

## The defect, as a verdict

`corpus/cisco/dev/edge-rtr-09.cfg`, before this change:

```
edge-rtr-09.cfg   idle_timeout_seconds = 0, state=present   NRK-TIMEOUT-001: PASS
```

`exec-timeout 0 0` on a vty line means the session never expires. It is the
least secure value the platform offers, and the rule reported it compliant —
with a citation, from the deterministic engine, which is the one place in this
system that is allowed to say PASS.

The rule asked `lte: 600`, and zero satisfies "at most ten minutes" the way it
satisfies every upper bound. Nothing was broken in the parser, the normaliser or
the engine. The rule said less than it meant, and `CheckSpec` had no way for it
to say more: one field, one operator, from a closed set of twelve.

## D83 — a conjunction of conditions, not a thirteenth operator

`CheckSpec` gains `all_of`, mutually exclusive with `condition`:

```yaml
check:
  field: idle_timeout_seconds
  all_of:
    - { op: gt,  value: 0 }
    - { op: lte, value: 600 }
```

The alternative was an `in_range` operator taking a two-part operand. Rejected:
it makes `Condition.value` structured, which `describe()` and `self_check()`
would both need to special-case, and it answers exactly one shape. The next rule
wants the next shape and the closed set stops being closed.

**Conjunction only. No `any_of`, no negation, no nesting.** That is the line
between a conjunction and an expression language, and an expression language in
this layer is where vendor logic and model calls reappear inside something built
to have neither. A rule needing disjunction is two rules, and having to say that
out loud is the feature.

Two smaller constraints, both refusals at load:

- `all_of` requires **at least two** conditions. A conjunction of one is the
  same rule spelled a second way, and a contract with two spellings for one
  meaning gets diffed wrong.
- A repeated `(op, value)` is refused. It is always a copy-paste, never an
  intent.

Callers read `CheckSpec.conditions`, which returns a tuple either way. The
engine, the rulepack self-check and `Finding.expected` never branch on which
form the author used — so a conjunction cannot be half-applied by a caller that
only knew about the singular field. `describe_all` joins with "and", so the
sentence an operator reads names every comparison that actually ran:
`gt 0 and lte 600`.

## D84 — an unevaluable conjunct dominates a false one

`evaluate_all` returns `None` if **any** condition returns `None`, even when
another has already returned `False`.

In Kleene logic `False and unknown` is `False`, and that is the wrong answer
here. `None` in this module does not mean "we do not know the device's value";
it means *this comparison is not meaningful*, which is a defect in the rule.
Returning FAIL from a half-broken rule would deliver a verdict about a device
while hiding an authoring error — and keeping `rule_type_mismatch` separate from
`no_match` exists precisely so a broken rule routes to whoever wrote it instead
of disappearing into a coverage gap.

The case is close to unreachable in practice: the ordered operators abstain on
the same value shapes, so a conjunction over one field evaluates throughout or
not at all. The rule is stated for when it does not.

## What moved, measured rather than assumed

Every Cisco corpus file, before and after:

| File | Value | Before | After |
| --- | --- | --- | --- |
| `edge-rtr-09.cfg` | **0** | **pass** | **fail** |
| `branch-rtr-07.cfg` | 600 | pass | pass |
| `rtr-core-01.cfg` | 600 | pass | pass |
| `edge-rtr-01.cfg` | 3600 | fail | fail |
| `sw-access-02.cfg` | 1800 | fail | fail |
| `dist-sw-03.cfg` | UNKNOWN | unknown | unknown |
| `dc1-leaf-01.cfg` | UNKNOWN | unknown | unknown |
| `edge-rtr-11.cfg` (eval) | 900 | fail | fail |
| `rtr-edge-09.cfg` (eval) | 300 | pass | pass |
| `sw-dist-11.cfg` (eval) | 1800 | fail | fail |

**One verdict moved, and it is the defect.** The 600 boundary still passes, so
the fix bounded the value without narrowing it. No evaluation-split device
carries `exec-timeout 0 0` inside the vty scope — `edge-rtr-11.cfg` has one on
its console line, which the pack's scope correctly excludes — so
`eval/reports/evaluation.txt` regenerates byte-identical apart from its
timestamp. **The harness figures did not move**, which is worth stating: a fix
that changed a measurement would need the measurement re-pinned, and this one
does not.

### `dist-sw-03.cfg` was checked rather than assumed

The brief asked whether it became usable after the per-field merge work. **It
did not, and that is correct.** `telnet_enabled` is `WORST_CASE_TRUE` because a
device is reachable by any path that reaches it; `idle_timeout_seconds` is
`UNDECIDED` because five minutes on one vty range and thirty on another is a
genuine "which did you mean" that nothing in the file answers. The field
resolves to UNKNOWN with `conflicting_evidence`, the rule never sees a value,
and the fixture for this defect had to be a device with no disagreement.

That is D71 working as designed, and it is why `edge-rtr-09.cfg` is the fixture:
console and vty both `exec-timeout 0 0`, no conflict, `0, state=present`. The
finding cites line 66 — the vty line — and not the identical console line on 64,
because the pack scopes the field to `line vty`. A FAIL citing the wrong one of
two identical lines would send an operator to edit a setting that was never
evaluated.

## Consequence

`Finding.expected` for this rule changes from `"lte 600"` to
`"gt 0 and lte 600"`, and `test_idle_timeout_fails_with_its_citation` was
updated to match. That is the contract behaving correctly: the expectation is
rendered from the conditions the engine applied, so a rule cannot describe an
expectation it did not run.
