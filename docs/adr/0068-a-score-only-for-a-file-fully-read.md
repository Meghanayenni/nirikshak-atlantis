# ADR 0068 — A score only for a file fully read

- **Status:** Accepted
- **Date:** 2026-09-28
- **Phase:** P18
- **Decisions:** D172 (the gate is decided server-side from the review queue, the
  decision timestamps and the corpus manifest, and nothing the browser holds),
  D173 (every framework mapping carries a coverage judgement, full or partial,
  with its reason), D174 (the unit is the framework control, rolled up in four
  states, and the headline is a fraction of controls *fully* satisfied), D175
  (coverage is assessed controls over the live controls of the pinned index),
  D176 (the Compliance page and the report show the gate or the posture, and the
  interface decides neither), D177 (a generic-shape entry can be dismissed and
  never mapped), D178 (one definition of "reviewed", read by the gate and the
  Needs-review tab alike), D179 (a line known only from an evaluation or held-out
  corpus file cannot be confirmed or compiled)
- **Affects:** `api/models/posture.py` (new), `api/comply/posture.py` (new),
  `api/routers/posture.py` (new), `api/models/enums.py`, `api/models/rule.py`,
  `api/models/__init__.py`, `rules/canonical/*.yaml`, `rules/rulepack.yaml`,
  `api/db/training.py`, `api/routers/training.py`, `api/routers/audits.py`,
  `api/routers/reports.py`, `api/report/model.py`,
  `api/report/templates/report.html.j2`, `api/report/templates/report.css`,
  `api/main.py`, `ui/src/components/domain/CompliancePosture.tsx` (new),
  `ui/src/pages/Compliance.tsx`, `ui/src/components/device/DeviceWorkspace.tsx`,
  `ui/src/components/device/Findings.tsx`, `ui/src/components/device/Review.tsx`,
  `ui/src/components/device/useDeviceWorkspace.ts`, `ui/src/services/audits.ts`,
  `ui/src/services/training.ts`, `ui/src/types/api.ts`,
  `ui/src/test/baseline.test.tsx`, `DEVELOPER_GUIDE.md` §10,
  `docs/architecture.md`, `README.md`, and the tests named below

## Context

Problem Statement 26155 asks for deviation analysis "against the chosen
framework". Until this change the Compliance section listed each audited device's
latest verdict counts and its non-passing findings, with severity, and never said
how far the device complied with any framework. Mappings existed per finding
(ADR 0057) and a benchmark could be selected (ADR 0058); nothing aggregated them.

A measure invites two failures this project exists to refuse. The first is a
figure over a file that was only partly read: a line no pack recognised is a line
nothing evaluated. The second, found at review of this ADR's first draft, is a
figure that reads a passed check as a met control. That draft rolled a control up
to *satisfied* when every mapped rule passed, and reported `branch-rtr-07` at
"90% NIST". Most mappings test part of a control — `NRK-HTTP-001` is one of about
fifteen services `CISC-ND-000470` lists; `CISC-ND-000140` also requires an
inbound access-class ACL on the vty lines, which `NRK-TELNET-001` does not read;
CM-7 and IA-5(1) are broader than any configuration check. In the FAIL direction
those mappings are sound. In the PASS direction a pass means *our check found no
violation*, not *the control is satisfied*, and 90% was not a figure an auditor
could defend.

## D172 — the gate, from stored state only

`GET /compliance/devices/{device_id}/posture` returns one of five states,
decided in `decide_gate` (`api/comply/posture.py`):

| State | When | What the response carries |
| --- | --- | --- |
| `evaluation_file` | the manifest reserves this exact file (by sha256) for the evaluation or held-out split | "Reserved for measurement — scored by the evaluation harness, not reviewed." No review count, no score |
| `not_audited` | platform unidentified, or no run | the reason; the bootstrap page or the device as the next step |
| `review_pending` | a Needs-review entry has no decision | "Review all unrecognised lines before a compliance score is shown.", reviewed and total, and for a non-admin "An administrator must complete the review." |
| `rerun_required` | every entry decided; a decision is newer than the latest run | "Re-run the audit to include your review decisions." |
| `ready` | every entry decided; the run is newer than every decision | the posture below |

In every state but `ready`, `posture` is null: no fraction, no control count,
nothing a bar could be drawn from. A test asserts no score-shaped key appears in
a gated body.

The inputs are the file's Needs-review entries (`unknown_line`, one entry per
`cluster_id`), the decisions recorded for those shapes on the file's platform
(`training_example.cluster_id`, `vendor`, `os_family`), the newest decision's
`confirmed_at` against the latest run's `evaluated_at`, and the corpus manifest
through `corpus_guard` — the check the bootstrap already used (ADR 0067), which
reads the manifest's hashes and never opens a corpus file.

**The remediation review marks are not an input.** They live in the browser's
`localStorage` and reach no server; `decide_gate` has no parameter they could
arrive through, and a test pins its signature.

**Confirming does not empty the queue.** Residue rows are replaced only on
re-audit (D49), so "queue empty" is read as *every entry decided*.

A report on a run that is not the device's latest gets a sixth state,
`superseded`, and no score; the endpoint never returns it.

## D173 — every mapping says how much of the control it tests

`FrameworkRef` gains `coverage` (`full` | `partial`, default **partial**) and
`coverage_reason`, the project's own words, capped at 600 characters like a
decline's reason. **Full** only where the control is a single configuration
requirement the rule tests completely. Defaulting to partial means a mapping
nobody judged can never make a control read as satisfied. A test requires every
shipped mapping to carry a reason.

Each judgement was made against the source: the NIST OSCAL catalog (fetched from
the index's `source_url` into a scratch directory and verified against the pinned
sha256 `01f37cf9…` before reading; it is still not held — ADR 0035, D93), the
STIG XCCDF held at `docs/sources/disa/`, and the CIS benchmark read from outside
the tree and verified against `e5330afd…`. No text from any of them is stored.

| Rule | Control | Coverage | Why, in short |
| --- | --- | --- | --- |
| SSH-001 | NIST AC-17(02) | partial | version only; not ciphers, MACs or other paths |
| SSH-001 | STIG CISC-ND-001210 | partial | the check also asks for approved encryption algorithms |
| SSH-001 | STIG CISC-ND-001200 | partial | the check also asks for an approved MAC list |
| SSH-001 | CIS 2.1.1.2 | **full** | the recommendation is the version setting alone |
| TELNET-001 | NIST CM-07 | partial | one protocol of everything least functionality covers |
| TELNET-001 | NIST AC-17(02) | partial | one unencrypted path removed; the rest not shown protected |
| TELNET-001 | STIG CISC-ND-000140 | partial | the check also requires an inbound access-class ACL on vty |
| TELNET-001 | CIS 1.2.2 | partial | the rule also passes `transport input none` (ADR 0052) |
| HTTP-001 | NIST CM-07 | partial | one service of many |
| HTTP-001 | NIST AC-17(02) | partial | one plaintext management path |
| HTTP-001 | STIG CISC-ND-000470 | partial | the check lists about fifteen services |
| TIMEOUT-001 | NIST AC-12 | partial | organisation-defined conditions; vty idle timeout only |
| TIMEOUT-001 | NIST SC-10 | partial | every network connection; vty only |
| TIMEOUT-001 | CIS 1.2.8 | **full** | vty exec timeout at most ten minutes, exactly the rule's bound |
| LOGGING-001 | NIST AU-04(01) | partial | frequency and receipt not in a configuration |
| LOGGING-001 | NIST AU-09(02) | partial | whether records are stored there is not in a configuration |
| LOGGING-001 | CIS 2.2.4 | **full** | at least one syslog host |
| NTP-001 | NIST SC-45(01) | partial | authoritativeness and threshold are organisation-defined |
| NTP-001 | CIS 2.3.2 | **full** | the remediation floor is one server (ADR 0052) |
| BANNER-001 | NIST AC-08 | partial | the notice's content and acknowledgement are not tested |
| BANNER-001 | CIS 1.3.3 | **full** | the rule passes only on a `banner motd` line |
| CIPHER-001 | NIST SC-08(01) | partial | SSH encryption list only |
| CIPHER-001 | NIST AC-17(02) | partial | named weak ciphers refused; not all sessions shown protected |
| CIPHER-002 | NIST SC-08(01) | partial | SSH MAC list only |
| CIPHER-002 | NIST AC-17(02) | partial | named weak MACs refused; not all sessions shown protected |
| PASSWD-001 | NIST IA-05(01) | partial | one of eight requirements |

**Five full, twenty-one partial; all five full mappings are CIS.** Every NIST and
every STIG mapping is partial. The CIS full calls rest on what the Cisco pack
reads: `ssh_version` only from `ip ssh version N`; `idle_timeout_seconds` only
inside `line vty N N`, abstaining when ranges disagree; `banner_present` only
from `banner motd`; `logging_hosts` and `ntp_servers` from `logging host` and
`ntp server`. A vty range with no `exec-timeout` runs the ten-minute default,
which 1.2.8 also accepts, so a pass is not overstated there.

The rulepack changed, so it is **1.4.0**, checksum `cbf3368a…`; 1.3.0 moves to
`history`. Every run stored before this commit renders without mappings until it
is re-run (ADR 0056), which is visibly less rather than quietly wrong.

## D174 — the unit is the control, in four states

| Mapped rules | Control |
| --- | --- |
| any FAIL | **violated** — a failed check violates the control whatever share of it the rule tests |
| every one PASS, and at least one mapping to the control is full | **satisfied** |
| every one PASS, and every mapping is partial | **no violation found** |
| otherwise — UNKNOWN, NOT_APPLICABLE, or no verdict | **undetermined** |

A full mapping does not rescue an abstention: PASS(full) with UNKNOWN(partial)
is undetermined. NOT_APPLICABLE is undetermined, not satisfied.

**The headline is a fraction, never a percentage:** "*1 of 10 assessed controls
fully satisfied*". A percentage reads as compliance with the catalog; a fraction
names its own denominator. No-violation-found and undetermined both count
against it, so it can understate compliance and cannot overstate it. The API
sends counts and no percentage anywhere.

**A declined mapping never contributes.** The roll-up reads `frameworks` only;
`not_mapped` is the rule saying it does not evidence that framework. Tested with
`NRK-TIMEOUT-001`, which declines the STIG.

**The review does not clear UNKNOWN.** An absent directive has nothing to
review, and two lines that disagree stay UNKNOWN. The gate proves the file was
fully read, not that every question was answerable; the undetermined share is
shown beside every headline.

A framework whose edition does not describe the device is `not_applicable`, with
the selector's reason, and carries no count — never a zero. A framework a scoped
run left out is `not_in_scope`. When the run's rulepack checksum is not the
active one, mappings are withheld with the findings view's reason and nothing is
scored.

## D175 — coverage from the pinned index

`coverage = assessed ÷ catalog_total`, `catalog_total` being the live controls in
the edition's index under `rules/frameworks/`, read at runtime, never typed:
NIST 1,014 (182 withdrawn, not counted), STIG 42 (index re-derived from the held
XCCDF on every test run), CIS 84 (pinned index; the benchmark is not held). The
brief expected CIS null; review agreed to keep 84 from the pinned index, since
NIST's catalog is not held either. The null path exists for an index with no
controls, which `CatalogIndex` already refuses at load.

## D176 — two surfaces, one decision

The Compliance page lists every device, audited or not; opening a row shows the
posture panel, then the latest run's findings.

- **Gated:** the message, review progress where relevant, and a link — to Needs
  review (administrators), to the device to run or re-run the audit, or to the
  bootstrap page. An evaluation file links nowhere. No number but the review
  count.
- **Ready:** one block per sourced framework. One stacked bar in four segments —
  fully satisfied `#1E6B4F` solid; no violation found in the same pass colour at
  lower weight (outlined on its tint, never a new hue); violated `#9E2B2B`;
  undetermined `#4A5666` dashed — drawn with `flex-grow` set to each count, so
  the interface does no arithmetic, and a one-phrase legend under it. The
  fraction, the other three counts, the legend and the coverage line are one
  component and cannot render apart. *Did not comply* is open by default:
  control and edition, the rule, the cited line linking to the finding's evidence
  (`/devices/{id}?tab=findings&finding={finding_id}`), and the vetted command
  with its rollback, or the resolver's plain statement that none exists. *No
  violation found* follows, collapsed: each control with "partial check:
  NIRIKSHAK tests only part of this control" and every mapping's reason. *Could
  not be determined* is collapsed, with each rule's UNKNOWN reason. No severity
  on the panel; severity is unchanged everywhere it already appears.

The HTML/PDF report's *Compliance posture* section is built by the same function
and uses the same phrases. Gated, it states the reason in place of a score. Each
finding's mapped controls now also say `full check` or `partial check`, in the
report and in `/findings`.

DEVELOPER_GUIDE.md §10 said "no decorative visualisation of pass/fail ratios".
It now says "no visualisation of pass/fail ratios without the counts it
represents beside it" — the rule this screen follows, stated rather than
departed from silently.

## D177 — a generic shape can be dismissed

A cluster whose shape has no command vocabulary (`<IP> <IP>`) is not
confirmable, and the review screen used to disable it entirely while the gate
counted it: a device with one could never leave `review_pending`, and a judge's
own configuration could hit that. It can now be selected and marked **not
security relevant**, which compiles nothing; *Confirm mapping* stays disabled,
and `POST /training/confirm` refuses any other outcome on such a shape with 422.
Tested on a constructed configuration carrying one generic line, driven from
`review_pending` through `rerun_required` to `ready`.

## D178 — one count for "reviewed"

`decided_clusters` (`api/db/training.py`) is the only definition. The gate reads
it through `review_progress`; `GET /training/queue` now returns `decided` per
entry and `reviewed` overall, computed by it, and the Needs-review tab and the
report tab's blocker read those. The tab used to match an example's line text,
across platforms, over the first 500 decisions (237 are recorded locally); it
now reads no decision list at all. The *Recorded decisions* table still lists up
to 500 of them beside the total — a display, no longer a count.

## D179 — the measured data is never reviewed (DEF-16)

A score that requires reviewing every line is pressure to review evaluation
files, which is how DEF-16 happened. Three guards, all on `corpus_guard`:

- `/training/confirm` refuses (409) a line when the file it is being reviewed
  from is an evaluation or held-out corpus file, or when every file whose queue
  holds that line is one. The interface sends the file under review.
- `/training/compile` refuses a recorded decision whose line is known only from
  such files.
- The gate returns `evaluation_file` for them, and `GET /training/queue?file_id=`
  returns the reason, which the review tab shows in place of the queue.

A line that also appears in a development file or an operator's own upload is
not refused: that is the corpus policy suite's own condition for a pack example
(no example exclusive to measured data).

**What remains open, so DEF-16 stays open:** a deployment without
`corpus/MANIFEST.yaml` cannot run the check at all; decisions recorded before
this change are untouched; and a shape decided from a development line still
counts as reviewed on an evaluation file's identical shape (harmless now that
evaluation files are neither reviewed nor scored).

**What was on record locally.** Of 237 decisions in the development database,
**12 rest on lines that exist only in `cisco/eval/edge-rtr-11.cfg`** (all dated
2026-09-12): nine "not security relevant" and three mapped to `weak_ciphers`. A
further 31 rest on lines present in that file and elsewhere. None of the twelve
is an example in any active or archived pack (a substring check found only
longer, different lines), and the trained tree holds only the MikroTik pack, so
**no pattern derives from them**. What they still touch: the three mappings are
in the similarity index, so they can shape suggestion rankings, which are
advisory; and a shape dismissed from an `edge-rtr-11` line counts as reviewed on
any Cisco IOS file carrying that shape. Neither changes a verdict. They were not
deleted — a decision is a recorded event (ADR 0019).

## What was measured

On the development database as it stands: `edge-rtr-01`, `edge-rtr-09` and
`dist-sw-03` are `rerun_required`; `branch-rtr-07` is `ready`, and its latest run
was made under rulepack 1.3.0, so its mappings are withheld until it is re-run;
the MikroTik fixture is `review_pending`, 0 of 29; `edge-rtr-11` is
`evaluation_file`.

On a scratch copy with the four Cisco files re-audited (all IOS 15.x, so the
IOS XE 17 STIG and CIS are not applicable and only NIST is scored):

| Device | Fully satisfied | No violation found | Violated | Undetermined | Coverage |
| --- | --- | --- | --- | --- | --- |
| `edge-rtr-01` | 0 of 10 | 4 | 5 | 1 | 10 of 1,014 |
| `branch-rtr-07` | 0 of 10 | 9 | 1 | 0 | 10 of 1,014 |
| `edge-rtr-09` | 0 of 10 | 0 | 4 | 6 | 10 of 1,014 |
| `dist-sw-03` | 0 of 10 | 4 | 3 | 3 | 10 of 1,014 |

`branch-rtr-07` was "90% NIST" under the first draft. It is now nine controls
where NIRIKSHAK found no violation, none shown satisfied, and one violated.

Two corpus files are IOS XE 17.x: `cisco/dev/rtr-core-01.cfg` (17.9, 13 queue
entries, none generic) and `cisco/eval/rtr-edge-09.cfg` (17.6, evaluation). Only
the first can reach `ready`. With its 13 entries dismissed and a re-run, it
reads CIS 5 of 6 fully satisfied (1.2.2 no violation found), STIG 0 of 4 (all
four no violation found), NIST 0 of 10 (7 no violation found, 3 undetermined).
