# ADR 0054 — A selector with something to select

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D137 (a selection is resolved against the device; one that
  describes nothing is refused with 409), D138 (a rule the selection leaves out
  is reported as *not assessed*, with the reason the rule records)
- **Affects:** `api/comply/frameworks.py`, `api/routers/audits.py`,
  `api/routers/reports.py`, `api/report/model.py`,
  `api/report/templates/report.html.j2`,
  `tests/integration/test_framework_selector.py`

## Context

ADR 0036 built the selector when one framework was sourced, so it had never been
asked to choose. With three it can be — and re-verifying it found two gaps and a
premise that could not hold.

**The premise.** The demonstration asked for was a device with `ip http server`
failing under the DISA STIG and not assessed under CIS. No Cisco IOS pack had
ever read that line as true; ADR 0053 fixed that. Even so, **no corpus file is
both in the benchmarks' scope and enables the server**: the two IOS XE 17 files
carry `no ip http server`, and the three that enable it are IOS 15.x, which
neither edition describes (ADR 0052, D134). The contrast is therefore shown on a
constructed input — `edge-rtr-01.cfg` byte for byte with its version line set to
17.9 — built inside the test and labelled as such. No corpus file was added.

**Gap 1 — a benchmark applied to a device it does not describe.** After ADR
0052, identifiers were filtered per device, but *selection* was not: asking for
`stig` on a JunOS router ran every rule that maps to the STIG anywhere, and
produced findings under a benchmark that says nothing about JunOS — each
carrying no STIG identifier, because the filter correctly removed them. A run
labelled "STIG" with no STIG in it.

**Gap 2 — "this framework does not cover this control" had no voice.** ADR
0036's D95 made a rule outside the selection produce no finding, which is right:
it is not an abstention. But nothing said it had been left out, or why. An
operator auditing against CIS saw one fewer finding and no reason. For
`NRK-HTTP-001` the reason is the most interesting fact in the framework data —
the two benchmarks disagree — and it was silent.

## D137 — resolve the selection against the device, or refuse

`scope_selection` runs in the audit route immediately after the canonical model
is built, **before** the training queue or the store is touched. For each
selected framework it asks the edition's `covers`; frameworks that do not
describe the device are *excluded*, each with the sentence `explain_coverage`
produces. What remains is the *effective* selection the engine evaluates.

- **Nothing remains → 409**, naming each framework and why:
  `none of the selected frameworks describes this device, so auditing against
  them would report zero findings — which reads as compliance. STIG: … is
  written for cisco/ios with a release matching '^17\\.'; this device is
  juniper/junos, which the edition does not describe.` No run is persisted.
- **Something remains → 201**, and the response carries
  `frameworks_not_describing_device`. The report prints each as *selected and not
  applied*, with the reason.

The run persists the selection *as requested*; the report recomputes the scope
at render time with the same function, under the same rulepack-version condition
as the mappings (D96), so the two cannot disagree.

## D138 — "not assessed" is stated, with the rule's own reason

For a non-empty effective selection, every rule that applies to the platform and
maps to none of the effective frameworks is listed in `not_assessed`, with the
reason the rule records in `not_mapped` (ADR 0052, D135). Not a finding, not an
UNKNOWN — the report lists them under **Not assessed under this scope**, in the
provenance block, in neutral type. "This benchmark does not ask for this" is a
fact about the benchmark, and giving it a verdict chip would put it on the
severity axis where it does not belong (DEVELOPER_GUIDE.md §10).

## What the selector now does, on the input that shows it

Same configuration, three selections:

| Selection | `NRK-HTTP-001` | Rules evaluated | Not assessed |
| --- | --- | --- | --- |
| none | **FAIL** — NIST `CM-07`, `AC-17(02)`; STIG `CISC-ND-000470` | 7 | — |
| `stig` | **FAIL** — cites `CISC-ND-000470` and the line | 3 | TIMEOUT, LOGGING, NTP, BANNER — each "this rule is looser than the STIG control" |
| `cis` | *not assessed* — "CIS … constrains a server assumed to be running. DISA's CISC-ND-000470 says the opposite …" | 6 | HTTP |

On the corpus as it stands:

| Device | `stig` | `cis` |
| --- | --- | --- |
| `rtr-core-01.cfg` (IOS XE 17.9) | 201 | 201 |
| `sw-access-02.cfg` (IOS 15.2) | **409** — release 15.2 not described | **409** |
| `edge-rtr-02.conf` (JunOS) | **409** — juniper/junos not described | **409** |
| JunOS, `nist` + `stig` | 201, NIST applied, STIG named as not applied | — |

**ISO/IEC 27001 remains absent** from `GET /compliance/audits/frameworks` and is
refused with 400, as before.

## What this does not do

- **The interface has no framework selector.** Selection exists on the API only;
  `ui/` never offered one, and building it now is out of scope for a
  demo-frozen build. Recorded, not closed. Related: until ADR 0052 the findings
  API returned no identifier on any stored finding, so the interface's finding
  view had said "No framework control is mapped to this check" on every finding
  since P17 — NIST included. That is fixed at the data; nothing in `ui/` changed.
- **Device role.** Both editions describe routers; an IOS XE 17 switch is
  admitted (ADR 0052, D134).
- **An IOS XE 16.x device** is refused as not described. That is the
  conservative side of a scope no source in hand extends to 16.x.

**Note, appended 2026-09-27.** The table's unscoped row counts 7 rules. ADR 0062
added NRK-CIPHER-001 and -002, which map to NIST only, so an unscoped run now
evaluates 9; the STIG and CIS columns are unchanged at 3 and 6.
ADR 0063's NRK-PASSWD-001 maps to NIST only as well; the unscoped count is 10.
