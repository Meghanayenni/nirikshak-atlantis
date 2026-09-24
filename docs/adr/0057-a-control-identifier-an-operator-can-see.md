# ADR 0057 — A control identifier an operator can see

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D143 (one framework view per stored run, read by the report and
  the findings API alike), D144 (the finding view shows every mapping with its
  edition and provenance, every decline with its reason, and why none are shown
  when none are)
- **Affects:** `api/comply/frameworks.py`, `api/routers/audits.py`,
  `api/routers/reports.py`, `ui/src/components/device/Findings.tsx`,
  `ui/src/types/api.ts`, `ui/src/test/helpers.tsx`, `ui/src/test/honesty.test.tsx`
- **Deletes:** the UI test *"renders no framework identifier while every rule
  ships an empty list"*

## Context

Three frameworks are sourced and every rule maps to at least one (ADRs 0035,
0052). The interface has said **"No framework control is mapped to this check"**
on every finding since P17 — NIST included. Two causes, one after the other:

1. Until ADR 0052 the findings API returned `frameworks: []` on every stored
   finding, because mappings are rulepack data not stored per finding (D96) and
   only the report route re-attached them.
2. After ADR 0052 the data arrived, but only as `framework` + `control_id`: no
   edition, no provenance, no declined mappings, and no reason when a mapping is
   withheld (ADR 0056). A control ID shown bare claims more than the repository
   supports; the declines, which are the clearest evidence mappings were checked
   rather than assembled, were invisible.

**The UI test suite defended the wrong string.** `honesty.test.tsx` asserted
"no framework control is mapped" in a test named *"…while every rule ships an
empty list"*. That premise stopped being true at P17; the test kept passing
because its fixtures kept shipping empty lists. It is deleted here, in the change
that earns it, and replaced by three tests that assert the opposite state.

## D143 — one view, two surfaces

`run_framework_view` in `api/comply/frameworks.py` resolves, for one persisted
run: whether its mappings may be attached (checksum, ADR 0056), the mappings
true of the device, each rule's **declined** mappings for frameworks that
describe the device, why each absent framework is absent, and the selection's
scope. The report route and the findings route both call it. Before this, each
route carried its own copy of the logic — the same drift that let the findings
API return nothing for a phase.

Declines are shown only for frameworks that describe the device. On a JunOS
router the STIG says nothing, so its declines say nothing either; the absence
explains itself ("written for cisco/ios with a release matching '^17\\.'").

## D144 — what the finding view shows

Every value comes from `/findings`; the interface resolves nothing.

- **Mapped controls** — framework, identifier, `edition …`, and *project
  asserted — our judgement, not a published crosswalk*. Plain metadata, never a
  verdict-coloured chip (ADR 0036, DEVELOPER_GUIDE.md §10).
- **Declined mappings** — e.g. *STIG not mapped — CISC-ND-000720 requires five
  minutes or less; this rule passes up to ten.*
- **Not applicable to this device** — each absent framework with the API's
  reason: unsourced (ISO) or not described.
- **Withheld** — when the run's rules are not the active rules, the API's reason,
  ending *re-run the audit to see them*. The old string is not said by default
  anywhere.

## Verified

Backend: tests that every mapping carries edition, citation and
`project_asserted`; that the timeout rule's STIG decline arrives with its
reason; that declines are empty on JunOS while the absence names the STIG; that
a NULL-checksum run returns `attached: false` with a reason. Interface: three
vitest cases for mapped, declined and withheld. In the browser: see ADR 0058,
which exercised this view on a live backend.

## Not done

The six TypeScript errors `tsc --noEmit` reports are in `report.test.tsx` and
`review.test.tsx`, predate this change (verified by stashing it), and are
recorded, not fixed here.
