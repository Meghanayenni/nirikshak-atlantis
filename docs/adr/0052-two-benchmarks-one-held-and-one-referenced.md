# ADR 0052 — Two benchmarks, one held and one referenced

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D132 (the STIG is content-addressed *in* the repository; the CIS
  Benchmark only *by* it), D133 (a rule maps to a control only if nothing it
  passes is something the control calls a finding — four prepared rows refused),
  D134 (a platform benchmark's identifiers hold only on the platform its edition
  describes), D135 (a declined framework is recorded as data, with its reason)
- **Affects:** `rules/frameworks/` (two new indexes), `docs/sources/disa/` (new),
  `rules/canonical/*.yaml`, `api/models/rule.py`, `api/comply/frameworks.py`,
  `api/comply/engine.py`, `api/comply/rulepacks.py`, `api/routers/reports.py`,
  `api/report/model.py`, `scripts/fetch_framework_catalog.py`, `.gitignore`,
  `.gitattributes`, `docs/CONTENT_POLICY.md`
- **Supersedes in part:** ADR 0035's "What could be obtained" table for DISA STIG
  and CIS

## Context

ADR 0035 sourced one framework of four. DISA's download index could not be
resolved from this environment and CIS distribution is behind registration, so
both stayed out of the selector. Both source documents have since been obtained
by hand:

| Artifact | Edition | sha256 |
| --- | --- | --- |
| `U_Cisco_IOS-XE_Router_Y26M04_STIG.zip` (DISA bundle) | April 2026 bundle | `01900ad03d8972698160db7c1fdfc71b64a3c7188ee53c4f1047fc827986f36d` |
| ↳ `U_Cisco_IOS-XE_Router_NDM_STIG_V3R7_Manual-xccdf.xml` | V3R7, 01 Apr 2026 | `748fab27a38ba2e980250338c8140bdc0eb00fc19cc269bc326a60185b8dd956` |
| ↳ `U_Cisco_IOS-XE_Router_RTR_STIG_V3R5_Manual-xccdf.xml` | V3R5 | `12e3637e7c03278881ed45d4c8aedb205d67ee8aefda3bf809b1db65b542c941` |
| `U_Cisco_IOS-XE_Router_NDM_V3R5_STIG_SCAP_1-3_Benchmark.zip` | NDM V3R5 SCAP | `111d6fdde80ce1a4a7de13144a7311106900c702a13c323ceee34b04fdea87a5` |
| `CIS_Cisco_IOS_XE_17_x_Benchmark_v2_2_1.pdf` | v2.2.1, 17 Jul 2025 | `e5330afdf64cc7a44ba051733e7b3a5b835d7d341610dddb5d5292eabe126b25` |

A prepared worksheet (`docs/FRAMEWORK_MAPPING_WORKSHEET.md`, not committed — see
below) proposed seven STIG rows and six CIS rows. Every hash, edition string,
STIG severity and rule count in it was re-derived from the artifacts and
matched. **Five of its thirteen mappings did not survive being read**, and that
is the substance of this ADR.

## D132 — one framework content-addressed in the repository, the other only by it

The two sources carry opposite terms, and the repository follows them.

**The DISA STIG is a US Government work published for public download.** The
NDM XCCDF file is committed at `docs/sources/disa/`, byte for byte — marked
`-text` in `.gitattributes`, because a digest of a file git has re-ended is a
digest of nothing anyone published. Its index is therefore not trusted but
**re-derived on every test run** from the held file: hash, edition, and all 42
STIG IDs. The zips are not committed; the XML is what is cited and is a
fifteenth the size. Both zip digests are recorded above. The RTR STIG is hashed
and not indexed — no current rule reads a routing-plane control, and mapping
against a document nobody has read is the failure this project exists to refuse.

**The CIS Benchmark's own first page says it is never acceptable to host a CIS
Benchmark in any format on a third-party site**, and asks that CIS Legal be
contacted about using portions of its recommendations. This repository has a
public remote. So the benchmark is **referenced, never held**:

- the PDF lives outside the tree (`D:\sih-sources\` on the development machine);
  `scripts/fetch_framework_catalog.py cis --catalog <path>` reads it and
  **refuses a path inside the repository**;
- the index records the edition, the sha256 and the recommendation **numbers**
  — 84 of them, found as numbered headings followed by `Profile Applicability:`,
  the heading's words read and discarded;
- rule files carry the number and a NIRIKSHAK-authored reason. No CIS title,
  rationale, audit procedure or remediation text is stored anywhere;
- `.gitignore` carries an accident guard, and
  `tests/architecture/test_cis_material_is_not_held.py` walks the **filesystem**
  — not `git ls-files` — for a CIS-named file or any file whose bytes are the
  pinned benchmark. When this work began the PDF was sitting untracked in
  `docs/`, one `git add .` from the remote; that is the state the test exists
  for, and it was moved out before anything else was done.

Its index is verified where an operator supplies the file
(`NIRIKSHAK_CIS_BENCHMARK=/outside/the/tree/…`), and trusted everywhere else,
which is the same position NIST has been in since ADR 0035. Both states are
tested: the verification was run against the real file for this commit, and the
paired test asserts that without it the index says it is referenced, not held.

**No legal claim is made either way** (ADR 0005). The terms were read and the
conservative reading was taken. Whether the team writes to CIS Legal is the
team's decision, not the code's, and nothing here depends on the answer.

The worksheet is not committed, and was moved out of `docs/` to sit beside the
PDF: it quotes the CIS terms of use verbatim, its name does not match the CIS
guard, and it carries rows this ADR refutes. The verified content of it is this
document.

## D133 — no rule may be looser than the control it cites

The worksheet's method was to find the rule's CLI directive in the STIG check or
fix text. That locates the right control; it does not show the rule and the
control agree. **The criterion adopted here: map only when every value the rule
PASSES is a value the control's own check accepts, on the directive the rule
reads.** A control that asks for more than the rule reads — other directives,
other algorithms — is partial coverage, stated in the mapping's comment. A
control that asks for *more of the same thing* is a different requirement, and
printing its identifier beside our PASS is a wrong-confident verdict produced by
a cross-reference rather than by the engine.

| Rule passes | Control requires | Row |
| --- | --- | --- |
| `NRK-TIMEOUT-001`: 1–600 s | `CISC-ND-000720`: five minutes or less | **refused** |
| `NRK-LOGGING-001`: ≥ 1 host | `CISC-ND-001450`: at least two syslog servers | **refused** |
| `NRK-NTP-001`: ≥ 1 server | `CISC-ND-001030`: redundant sources, two shown | **refused** |
| `NRK-BANNER-001`: `banner motd` present | `CISC-ND-000160`: `banner login` with the mandated DoD notice | **refused** |
| `NRK-BANNER-001`: `banner motd` present | CIS `1.3.2`: `banner login` | **replaced by `1.3.3`**, the `banner motd` recommendation |

The worksheet itself noted "requires **two** servers" on the logging row and
mapped it anyway; the timeout row says "STIG requires `exec-timeout 5 0`" beside
a rule whose bound is 600 seconds. A device at `exec-timeout 8 0` would have
shown **PASS — CISC-ND-000720** and failed a STIG assessment. A STIG-strength
rule (`lte 300`, two hosts, two servers) is a different rule, and is not added
here: it would change every default run, and a rulepack that grows a check to
make a mapping table fuller is the tail wagging the dog.

What survived, all `project_asserted`:

| Rule | DISA STIG V3R7 | CIS v2.2.1 |
| --- | --- | --- |
| `NRK-SSH-001` | `CISC-ND-001210`, `CISC-ND-001200` | `2.1.1.2` |
| `NRK-TELNET-001` | `CISC-ND-000140` | `1.2.2` |
| `NRK-HTTP-001` | `CISC-ND-000470` | — declined, see D135 |
| `NRK-TIMEOUT-001` | — declined | `1.2.8` |
| `NRK-LOGGING-001` | — declined | `2.2.4` |
| `NRK-NTP-001` | — declined | `2.3.2` |
| `NRK-BANNER-001` | — declined | `1.3.3` |

Three judgement calls, recorded so they can be disputed:

- **`CISC-ND-001200` was added**; the worksheet listed it as unmapped. Its check
  names `ip ssh version 2` exactly as `CISC-ND-001210`'s does, and SSHv1 carries
  no HMAC at all, so a v1 device is unambiguously a finding under it. Admitting
  one and not the other would be the arbitrary choice. Neither mapping reads the
  algorithm lists that are each control's substance, and both comments say so.
- **`transport input none`.** The pack reads it as telnet-free, so the rule
  passes it. CIS `1.2.2`'s audit asks that the transport "show only ssh". A line
  admitting *no* inbound transport admits no non-SSH one; it is accepted as
  satisfying the recommendation's stated purpose, and no corpus file carries it.
- **CIS `2.3.2`** prefers two or three NTP servers in its rationale and sets the
  floor at one in its remediation; the audit step is a `show` command with no
  count. The remediation floor is taken, which matches the rule.

## D134 — a platform benchmark's identifiers hold only on its platform

NIRIKSHAK's rules are vendor-neutral. A STIG and a CIS Benchmark are each
written for one product. Mapping `NRK-HTTP-001` to `CISC-ND-000470` without
qualification would print a Cisco IOS XE STIG identifier beside a Juniper
finding — a citation to a document that says nothing about Juniper. The
worksheet framed mappings per canonical field and never raised this; it is the
largest single correction here.

Each index now declares `covers`: vendor, OS family and a release pattern, with
a `basis` in our own words. NIST declares none, because SP 800-53 is written
for any system. `refs_for_device` keeps a mapping only where its edition covers
the device, and it is applied in two places that must not disagree: the engine
(so the finding the API returns carries only true identifiers) and the report
route (so a persisted finding re-read later does too).

**Both editions are scoped to `cisco/ios` releases matching `^17\.`.**
NIRIKSHAK's `ios` family holds classic IOS 15.x as well as IOS XE — seven of the
nine Cisco IOS corpus files are 15.x — and neither document covers classic IOS.
The CIS document names IOS XE 17 as its target; the STIG names IOS XE and no
release, and 17.x is the only release family any source in hand ties to IOS XE.
An IOS XE 16.x device is therefore *not covered* — an abstention, not an error.
A device whose release could not be read is **undeterminable** and treated as
not covered, with that reason, because an identifier shown beside a device the
edition may not describe is a citation nobody checked.

**Not determinable at all: device role.** Both documents are written for
routers. NIRIKSHAK has no router-or-switch field, and an IOS XE 17 switch will
be shown these identifiers. The report names the document, so the edition is
visible to whoever reads it. That limit is recorded rather than closed.

The report's standing sentence — *"No catalog for those frameworks has been
sourced"* — would have become false on every non-Cisco device the moment this
landed, because CIS and STIG are sourced and simply do not apply there. It now
names each absent framework with its actual reason: unsourced (ISO), or read
and not describing this device.

## D135 — a declined framework is data

`ComplianceRule.not_mapped` records a sourced framework a rule deliberately does
not map to, and why, in the project's words (capped at 600 characters). A test
requires every rule to answer every sourced framework — a mapping or a reason,
never silence — because silence has two readings and a report cannot tell them
apart.

**The HTTP disagreement is the reason it exists.** CIS Cisco IOS XE 17.x v2.2.1
has no recommendation to disable the HTTP server. It has three that constrain it
(`1.1.5`, `1.2.9`, `1.2.10`), each assuming it may legitimately run; its global
service section disables bootp, DHCP, pad and CDP, and not HTTP. The STIG's
`CISC-ND-000470` lists `ip http server` among commands that must not be present.
Two sourced frameworks disagree about the same control. The rule maps to the
STIG and records the CIS disagreement, rather than forcing a CIS identifier into
the row to make the table look complete.

## The rulepack version moves, and why that matters here

The rules changed, so the version is **1.1.0**. This is not bookkeeping. A
report shows today's control mappings beside a stored verdict only when the
run's `rulepack_version` equals the active one (ADR 0036, D96). The constant had
read `1.0.0` since P6, through DEF-8's changed check and the NIST mappings —
three different rulepacks under one label — so that guard compared nothing.
Runs made before this commit now render without identifiers, which is visibly
less rather than quietly wrong. Thread 3b of this session takes up the binding
itself.

## What is still not claimed

- **Coverage.** Four STIG IDs of 42 and six CIS recommendations of 84 carry a
  NIRIKSHAK mapping. That is evidence about seven checks, not an assessment
  against either benchmark, and no document may call it one.
- **Official mappings.** Every one is `project_asserted`. Neither artifact is a
  crosswalk (ADR 0041, ADR 0045).
- **Any finding on the corpus's in-scope devices that depends on HTTP.** The
  two IOS XE 17 corpus files both carry `no ip http server`.

## Erratum (same day)

As first committed, this ADR and README, `docs/architecture.md` and
`SOURCING_BACKLOG.md` said **five** STIG IDs were mapped by five rules. The
table above was right and the prose was not: three rules carry four STIG IDs —
`CISC-ND-001210` and `CISC-ND-001200` (SSH), `CISC-ND-000140` (telnet),
`CISC-ND-000470` (HTTP). Seven rules less four declined is three. Found by
deriving the figure from the rulepack for the session's closing statement, and
now reconciled by `test_the_mapped_counts_in_prose_match_the_rulepack`, which
did not exist when the wrong number was written.
