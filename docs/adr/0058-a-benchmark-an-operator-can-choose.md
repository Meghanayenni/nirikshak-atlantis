# ADR 0058 — A benchmark an operator can choose

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D145 (the API says, per device, which sourced benchmarks
  describe it and why not; the interface renders that and decides nothing),
  D146 (a refused audit is shown where the operator is looking, and an audit
  failure is never silent)
- **Affects:** `api/comply/frameworks.py`, `api/routers/audits.py`,
  `ui/src/components/device/BenchmarkScope.tsx` (new),
  `ui/src/components/device/DeviceWorkspace.tsx`,
  `ui/src/components/device/Findings.tsx`, `ui/src/hooks/useApi.ts`,
  `ui/src/services/api.ts`, `ui/src/services/audits.ts`, `ui/src/types/api.ts`,
  `ui/src/test/benchmark.test.tsx` (new), `ui/src/test/helpers.tsx`

## Context

Problem Statement 26155 asks for evaluation against user-selected benchmarks.
Since ADR 0054 selection existed over HTTP and nowhere an operator could reach.

## D145 — the API decides; the interface shows

`GET /compliance/audits/frameworks/device/{file_id}` returns every sourced
framework with `describes_device` and, when false, the edition's own reason.
An unsourced framework is absent from the list, so ISO is absent from the
selector — not present and unchecked.

The selector sits in the device workspace above the tabs. A benchmark that does
not describe the device is **offered, not disabled**, with *Does not describe
this device — …* beneath it. Disabling it would move the scope decision into
the interface; leaving it selectable leaves the refusal where it belongs — the
audit route's 409 — and lets the operator see it.

A scoped run's findings tab opens with the scope, any selected framework that
was not applied, and every **not assessed** rule with its recorded reason — in
neutral type, never a verdict chip.

## D146 — never silent

Wiring the refusal exposed a defect present since P13. `onAudit` awaited the
mutation and then read `workspace.audit.error` — React state captured by the
handler's closure, still `null` after the await — and returned early. **Every
audit refusal and every audit failure has been silent**: the button reset and
nothing was said, including the unidentified-platform 409 whose sentence the
comments in that function describe at length. No test covered it.

`useMutation` gains `attempt`, which returns the outcome to the caller directly.
A selection-scoped 409 is shown inline, persistently, as *Audit refused —
nothing was run and nothing was recorded*, followed by the API's sentence (both
halves true: the route refuses before touching the queue or the store). The
unscoped 409 and other failures reach their toasts again. A regression test
drives the unscoped 409 and asserts the notice appears.

A second, smaller one: the UI test stubs answered any unmatched
`/compliance/audits…` URL with an audit list, so the new options request got the
wrong shape and crashed the workspace in six suites. `mockApi` now supplies a
realistic default for the options endpoint ahead of those catch-alls.

## Verified in a browser

Against a live backend on an isolated database, headless Chrome was driven over
the DevTools protocol through the real interface — the sign-in form, the
checkboxes, *Run audit*, the Findings tab, the row expander:

| Input | Selection | Seen on screen |
| --- | --- | --- |
| `edge-rtr-01.cfg`, release set to 17.9 (constructed; see ADR 0054) | STIG | `NRK-HTTP-001` **FAIL**, cited line `ip http server`; mapped **STIG CISC-ND-000470**, edition V3R7, *project asserted*; *CIS not mapped —* the disagreement; 3 findings; TIMEOUT, LOGGING, NTP, BANNER listed as not assessed with reasons |
| same | CIS | 6 findings, `NRK-HTTP-001` absent from them and listed as **not assessed** with the CIS reason |
| same | none | `NRK-TIMEOUT-001` shows NIST AC-12, SC-10, CIS 1.2.8, and *STIG not mapped — CISC-ND-000720 requires five minutes or less …* |
| `corpus/juniper/dev/edge-rtr-02.conf` | STIG | CIS and STIG each say *Does not describe this device*; running shows *Audit refused* with the API's sentence |

That run found one defect, fixed here: the scope sentence printed the release
pattern through `repr`, so operators saw `'^17\\.'`. It now prints the pattern
once, as written. It is still a regular expression, not the words "IOS XE
17.x"; a human-readable label would be new index data, changing the rulepack
checksum days before freeze, and is recorded rather than added.

## Not done

The six pre-existing TypeScript errors in `report.test.tsx` and
`review.test.tsx` (ADR 0057) remain. The browser run is a scratch script, not a
committed test: adding a browser-automation dependency to the lock file this
close to freeze is not justified by one demonstration.
