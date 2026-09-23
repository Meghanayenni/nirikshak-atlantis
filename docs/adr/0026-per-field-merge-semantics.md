# ADR 0026 — Per-field merge semantics, and why "undecided" is not universal

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P16
- **Decisions:** D71 (declare merge policy per field, opt-in), D72 (telnet is a
  reachability boolean), D73 (`snmp_v3_only` waits for its patterns)
- **Defects:** DEF-17 (fixed)
- **Affects:** `api/models/enums.py`, `api/models/csm.py`, `api/parse/fields.py`

## Context

Two lines in one file asserting different values for one canonical field
abstained with `CONFLICTING_EVIDENCE`. That was written as a safety property, and
for most fields it is one: picking a winner invents an answer the configuration
does not give.

It was wrong for `telnet_enabled`, and wrong in the worst possible direction.
`corpus/cisco/dev/dist-sw-03.cfg` carries:

```
line vty 0 4      transport input ssh          -> telnet_enabled false
line vty 5 15     transport input telnet ssh   -> telnet_enabled true
```

and reported UNKNOWN. An operator opens telnet on the high vty range for a
migration and never reverts it — the single most common misconfiguration in this
tool's own problem domain — and the tool said it could not tell.

**An UNKNOWN is a finding an operator dismisses.** A FAIL is one they act on.

## The distinction the fix rests on

These two lines **do not conflict**. Both statements are true. `line vty 0 4`
permits ssh only; `line vty 5 15` permits telnet. Together they say telnet is
reachable, because a device is reachable by any path that reaches it. Abstaining
was not preserving honest uncertainty — it was discarding information the
configuration plainly gives.

That is *not* true of `idle_timeout_seconds` across two vty ranges. Five minutes
on one range and thirty on another is a genuine "which one did you mean"
question, and nothing in the file answers it. Same shape of disagreement,
opposite correct response.

The difference is the **field's semantics**, not the shape of the disagreement.
So the policy is declared per field.

## D71 — a per-field table, defaulting to undecided

`MergePolicy` has three values: `UNDECIDED`, `WORST_CASE_TRUE`,
`WORST_CASE_FALSE`. `FIELD_MERGE_POLICY` in the canonical schema names the
exceptions, and **absence from the table is the safe answer** rather than an
oversight — every field not listed abstains exactly as before.

No global merge rule was introduced, and deliberately so: a rule that applied to
every field would have to be either unsafe for timeouts or useless for telnet.

Opting a field in changes what that field *asserts*, so it is a reviewable act
requiring a decision record and a fixture that exercises it. Two lines of table
are the whole mechanism; the discipline is that they are two lines somebody had
to justify.

### The resolved value cites every contributing line

Including the ones that said the safer thing. `dist-sw-03` now fails
`NRK-TELNET-001` citing both:

```
transport input telnet ssh
transport input ssh
```

An operator closing this gap needs to know *which range* to change, and the line
that refused telnet is half of that answer. A resolution that cited only the
winning line would name the problem and hide its location.

## D72 — `telnet_enabled` is `WORST_CASE_TRUE`

The only field opted in. Verified across every Cisco fixture:

| File | telnet | Note |
| --- | --- | --- |
| `dist-sw-03.cfg` | `True`, 2 citations | **was UNKNOWN** — the defect |
| `edge-rtr-01.cfg` | `True`, 2 citations | unchanged: both ranges already permit telnet |
| `edge-rtr-11.cfg` | `True`, 2 citations | unchanged |
| `rtr-core-01.cfg` | `False`, 1 citation | unchanged |
| `sw-access-02.cfg` | `True`, 1 citation | unchanged |

`idle_timeout_seconds` on `dist-sw-03.cfg` stays UNKNOWN, which is the point:
the same file exercises both halves of the design.

## D73 — `snmp_v3_only` fits, and still waits

`WORST_CASE_FALSE` expresses its semantics exactly: a v1/v2c community is
dispositive evidence that SNMP is not v3-only, however many v3 users sit beside
it. The brief asked whether the semantics genuinely fit, and they do.

It is **not** opted in. No pack declares an SNMP pattern, so the entry would be a
claim nothing could exercise — no test could show it right or wrong on real data,
which is the opposite of a reviewable act. It belongs to the change that authors
those patterns.

The mechanism is proven in both directions regardless:
`test_the_mirror_policy_resolves_to_false` exercises `WORST_CASE_FALSE` on a
constructed pack, so the path is tested even though no shipped field uses it yet.

## Consequences

`NRK-TELNET-001` on `dist-sw-03.cfg` moves from UNKNOWN to **FAIL**. No
evaluation-split file carried a telnet disagreement, so the harness figures are
unchanged — the fix corrects a development fixture's verdict without moving any
measurement.

DEF-17 is closed. `UNDECIDED` remains the default for twelve of thirteen
canonical fields, which is not a partial fix but the design: the defect was that
abstention was applied where the field's meaning ruled it out, not that
abstention was wrong.
