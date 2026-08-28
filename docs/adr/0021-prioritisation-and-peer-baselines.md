# ADR 0021 — The Prioritise stage, and the ranking it declines to produce

- **Status:** Accepted
- **Date:** 2026-08-28
- **Phase:** P12
- **Decisions:** D52 (a package for Prioritise), D53 (exposure abstains rather
  than falling back to severity), D54 (a cohort floor), D55 (DEF-14 fixed here),
  D56 (DEF-15 fixed here), D57 (DEF-3 stays open, and why P12 does not need it)
- **Defects:** DEF-14 (fixed), **DEF-15 (discovered, fixed)**, DEF-3 (open),
  DEF-8 (open)
- **Related:** ADR 0012 (DEF-2, DEF-3), ADR 0014 (D22, the P12 handoff),
  ADR 0015 (what the report omits until P12)

## Context

Five phases have deferred work to this one. `Finding.exposure_score` and
`Finding.priority_rank` have existed since P1 and been `None` since P6; ADR 0014
listed "exposure-aware prioritisation and peer baselines" under *Not built at
P7*; ADR 0015's report omits an exposure column because *"`priority_rank` is
unset until P12"*; the line cache's docstring has pointed at P12 since P3.

The Concept Report asks for two things:

> **Peer-baseline outlier detection.** Across a fleet, the system reports devices
> that deviate from their own peer group — forty-seven switches with a logging
> host configured and three without. This is statistical and fully explainable,
> requires no model.
>
> **Exposure-aware prioritisation.** Severity alone is a poor ranking. A weak
> cipher on a management interface reachable from a user VLAN is not the same
> risk as the same cipher behind a deny-all ACL. Reasoning over the canonical
> model together with parsed ACLs turns a flat findings list into an ordered
> remediation queue.

The second sentence names its own inputs, and P12 measured them before building
anything.

## What the corpus actually holds

Every non-holdout configuration was parsed and normalised, and the result
counted:

| | |
| --- | --- |
| Devices | 10 (3 Arista, 4 Cisco, 3 Juniper) |
| Interfaces, all devices, all splits | **0** |
| Access lists, all devices, all splits | **0** |
| Devices with `peer_group`, `role` or `site` set | **0** |
| Largest cohort | 4 (Cisco) |

So exposure has neither of its inputs, and the largest peer group is four
devices. Both features were built; only one of them can say anything, and it says
that the fleet is too small.

## D52 — Prioritise is a package, not a helper

`api/prioritise/`, named for the pipeline stage the Concept Report already names:

```
Ingest -> Parse -> Normalise -> Comply -> [Prioritise] -> Remediate -> Report
```

Seventeen new forbidden edges. The layer may import `api.models` and itself, and
nothing else — a whitelist, so a package written after P12 is forbidden without
anyone remembering to add it. The two that carry weight are `prioritise -> comply`
and `comply -> prioritise`: a ranking layer that could see verdict logic could
start disagreeing with it, and an operator would have two orderings with no way
to tell which one was the audit.

`Finding` records the rule that produced it, not the field that rule read, so
exposure — a property of the *control* — resolves through the `Rulepack`
contract from `api.models.rule`. Taking the contract rather than importing
`api.comply` is what keeps the edge intact.

## D53 — exposure abstains; it does not fall back to severity

This is the decision the phase turns on.

A one-line severity sort was available. It would have produced an ordered list an
operator could act on, `priority_rank` would have been populated for the first
time in six phases, and ADR 0015's report could have dropped its disclosure and
printed a ranking. It would also have been a lie, and DEVELOPER_GUIDE.md §7 says so in as
many words: **"Severity alone must not determine remediation order."**

A severity sort presented as exposure-aware prioritisation is not a partial
implementation of the feature. It is a claim that reachability was considered
when nothing had been read that could establish it.

So `ExposureAssessment` carries a `determinacy` and the invariant is structural:
**a score exists if and only if exposure was DETERMINED**, enforced in
`__post_init__` rather than by convention. Without it a caller sorting on
`score or 0.0` would rank every undeterminable finding last, which reads as *we
checked and it is safe*.

The abstention names which input was missing, because "undetermined" alone sends
an operator hunting for a bug while the answer is in the sourcing backlog:

| State | Meaning |
| --- | --- |
| `NO_INTERFACE_DATA` | No interfaces, so *where* the control lives is unknown |
| `NO_ACL_DATA` | Interfaces known, but not *who can reach them* |
| `INDETERMINATE_INTERFACES` | Interfaces exist, management status undocumented (DEF-2) |
| `NOT_EXPOSURE_RELEVANT` | A real answer: this control's risk does not vary with reach |

The severity weights only ever multiply a reachability term computed from real
interfaces, so a CRITICAL finding on a device with no interface data scores
exactly what an INFO one does: nothing. That is asserted arithmetically rather
than by reading the code.

**On this corpus every finding is undetermined**, `priority_rank` and
`exposure_score` stay `None`, and the audit response reports the blockers by
count.

## D54 — a cohort below five makes no claim

Among three devices, "one differs from two" is not drift; it is a coin landing.
`MIN_COHORT_SIZE = 5` is set plainly above what this corpus can supply, exactly
as `api/learn/calibration.py` sets its 200-observation floor, so the refusal is
unambiguous rather than marginal. It is not a statistical derivation and is not
presented as one.

A cohort split more evenly than `MIN_MAJORITY_RATIO` reports `NO_MAJORITY` rather
than calling the smaller half outliers — two conventions is a fact about the
fleet, not a fault in a device, and picking a side would be a judgement nobody
made.

### The failure the baseline is built to avoid

"Forty-seven switches have a logging host and three do not" is only true if those
three were **read** and found not to have one. A device whose field abstained is
not a device without logging; it is a device we could not read, and folding it
into the minority would manufacture drift out of our own parsing gaps.

That is DEF-2 arriving by a different route, so `UNKNOWN` is excluded from
`DETERMINABLE_STATES` and the count of abstentions travels with every baseline.
A baseline over four readable devices where six abstained is a different claim
from one over ten, and showing only the four would describe a fleet that was
never read.

An outlier is an **observation**, never a verdict — the separation decision D22
drew between ACL analysis and compliance findings, applied to drift.

## D55 — DEF-14 fixed here

`POST /compliance/audits` never appended `AUDIT_RUN` to the hash chain.
`api/comply/service.run_audit` had appended it since P6 and the HTTP route called
`evaluate_device` directly instead, so the function was dead production code and
the chain never held the one category DEVELOPER_GUIDE.md §9 names alongside suggestions,
corrections and pack changes: **audit results**.

Found at P11, recorded as pre-existing and out of scope there, and fixed here
because P12 is the phase that builds over audit runs. The payload is
`comply.service.audit_payload` unchanged — counts, identifiers and versions,
never a value and never a line — so decision D4's boundary is intact and asserted
by a test that reads the stored payload back.

## D56 — DEF-15, discovered at P12 and fixed

**Newly discovered.** `build_csm` has accepted a `detected_identity` argument
since P5 and **no production caller ever passed one**. Ingestion detects and
stores hostname, model, os_version and serial — `/ingest/devices` returns
`rtr-core-01` — and every canonical model built by the API carried all four as
`None`.

Nothing produced a wrong answer, which is why it survived four phases: vendor and
os_family fall back to the pack so rule applicability was unaffected, and the
report omits identity by design (ADR 0015, DEF-3 honesty). But peer grouping has
to know which device it is looking at, and "the model has no idea" is not a
workable input.

Fixed at the audit route and the fleet route. **`eval/score.py` was deliberately
not changed**: it builds models the same way, and altering the evaluation path
would move a P9 measurement in the phase that is not allowed to.

## D57 — DEF-3 stays open, and P12 explains why it can

ADR 0012 assigned the device-identity lifecycle to *"P12, where peer-baseline
detection must recognise the same switch over time"*. P12 arrives and finds that
its own feature does not need it.

Peer baselines as the Concept Report describes them are **cross-sectional**:
forty-seven switches now, three switches now. That is a comparison across a fleet
at one moment, not the same switch across time. `device_id` being a content hash
distorts it in exactly one way — **a configuration re-uploaded after an edit
counts as a second device** and is double-counted in its cohort.

That distortion is real and is recorded here rather than fixed, because fixing it
means redefining `device_id`, which every `Finding`, every `audit_run` row, every
report and the P9 evaluation already carry. Changing it would alter a measurement
inside a phase that is not the evaluation phase — the same argument that has kept
DEF-8 open.

**DEF-3 therefore remains open, deliberately**, and longitudinal drift ("this
switch lost its logging host last Tuesday") is out of reach until it is closed.
Nothing in P12 presents a content hash as a stable device identity; the fleet
view labels devices by hostname and falls back to a truncated identifier, never
to a guess.

## DEF-8 — open, with a specific reason

`NRK-TIMEOUT-001` passes `exec-timeout 0 0`. The correct check is "≤ 600 **and**
> 0", and `CheckSpec` examines one field with one operator from a closed set:
`lte` cannot express it. Fixing it needs either a new `ConditionOp` or a
multi-condition `CheckSpec` — a compliance-engine contract change belonging to a
rules phase with its own ADR, not to prioritisation.

Left open, unmodified, `rules/` untouched.

## Consequences

**Measured at P12: nothing new.** No metric was added to the evaluation report
and no accuracy is claimed. What P12 adds is the stage, the abstention, and the
sentence that says which input was missing.

**The first stage that runs and reports its own inability.** `/compliance/audits`
now returns a `prioritisation` block reading `ranked: false` with the blockers by
count; `/fleet/baseline` returns cohorts, sizes and the reason each produced no
baseline. A response carrying only comparable baselines would have been an empty
page that reads as a uniform fleet.

**The determined paths are tested against constructed objects only**, and are
named as such — the shape P7 took for ACL analysis and P8 for remediation. No
detection rate, no drift rate and no ranking quality is claimed for anything.

**Not built at P12:**

- **A fleet-level report.** ADR 0015 deferred it to "peer baselines and exposure,
  both P12". Both now exist and both abstain, so a fleet report would render a
  page of refusals. It waits for data, not for code.
- **Longitudinal drift** — needs DEF-3 (D57).
- **`role`, `site` and `peer_group` population** — operator metadata with no
  source. Cohorts fall back to `vendor/os_family`.
- **The React/Tailwind UI** — P13. `docs/ui_reference.html` untouched.
- **Any ACL or interface parsing pattern** — corpus prerequisite, unchanged.
