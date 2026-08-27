# ADR 0013 — Deterministic compliance evaluation

- **Status:** Accepted
- **Date:** 2026-08-27
- **Phase:** P6
- **Decisions:** D15 (one home for rules), D16 (no framework mappings ship),
  D17 (rulepack container), D18 (type mismatch abstains), D19 (run identity)
- **Defects addressed:** DEF-4 (fixed), OBS-1 (accepted), DEF-3 (still deferred)

## Context

P6 is where NIRIKSHAK first says PASS or FAIL. It is also the layer the whole
safety argument is about: *the compliance engine can only see the typed Canonical
Security Model, so a verdict cannot be influenced by raw vendor syntax or by
model output.*

Both contracts already existed. `ComplianceRule` and `Finding` were written at P1
and needed almost nothing added — the changes below are one validator, one
container and one enum member, each forced by a specific decision.

## The engine is provable; the rulepack is not

This is the phase's central problem and it is worth stating before anything else.

`docs/CORPUS_PREREQUISITES.md` §2 names P6 by name: corpus breadth blocks
*compliance-rule validation*. Two synthetic Cisco devices are enough to build and
verify an evaluator; they are not enough to say a rule is correct. A check that
passes on two devices from one vendor has been tested against a sample too small
to say anything about the check.

So P6 makes exactly one claim and not the other:

- **The evaluator is validated.** Operator semantics, absence policy, verdict
  invariants, applicability, determinism and provenance are all
  corpus-independent. `lte` means `lte` whatever configuration it reads, so it is
  exhaustively testable without inventing anything.
- **The rulepack is not.** Seven checks ship over the eight fields the parser
  actually reads. They exercise the engine. They are not a compliance benchmark,
  and P9 may not report coverage on the strength of them.

The corpus does produce real verdicts, which is why it is still worth running
against: `rtr-core-01` passes all seven; `sw-access-02` produces **two genuine
FAILs** (telnet enabled on line 17, a thirty-minute idle timeout on line 18) and
two honest UNKNOWNs. A rule with its sense backwards fails there rather than
passing on uniform data.

## The verdict table

| CSM field state | Policy consulted | Verdict | Justification carried |
| --- | --- | --- | --- |
| PRESENT | — | PASS / FAIL | the field's own evidence |
| ABSENT_DEFAULT | `on_absent_default` | per policy | `default_ref` as absence citation |
| ABSENT_UNSUPPORTED | `on_absent_unsupported` | NOT_APPLICABLE | the capability citation |
| UNKNOWN | `on_capability_unknown` | **UNKNOWN, always** | the field's `unknown_reason` |
| key absent | — | UNKNOWN · `no_match` | the packs cannot read this control |
| rule not applicable | — | **no finding at all** | the rule was never relevant |

Two obligations hold across every row.

**A verdict needs justification.** PASS and FAIL require the field's evidence or,
for a documented default, the citation it rests on. The `Field` contract already
makes a PRESENT field without evidence unconstructable, so the engine's own check
is belt and braces — but it abstains rather than crashing, which is a result
rather than an outage.

**An unanswerable question stays unanswered.** Nothing here turns UNKNOWN into
PASS because that produces a nicer report, and nothing turns it into FAIL either.
FAIL feels like the safe direction for a security tool and is not: it is a claim
about a device, made without evidence, that an operator will spend time on.

The ABSENT_DEFAULT row is reachable **only with synthetic packs**. No vendor
documentation has been sourced (P5, D11), so no shipped pack produces that state
and the absence-aware `EVALUATE` branch never fires on real data. Its tests say so
where they are written.

## D15 — one home for rule logic

Rules live in `rules/canonical/`, one file each, cross-mapping themselves through
their own `frameworks` list.

`rules/cis/`, `rules/nist/`, `rules/stig/` and `rules/iso/` existed as empty
directories from P0 with no ADR explaining them. They have been **removed**. The
contract was already designed for the inline form, and a second place where a
rule could be defined is a second place where it could be wrong — the same
reasoning that removed `rules/platform/` at P5.

## D16 — zero framework mappings ship

Every rule has `frameworks: []`.

Writing `CIS-1.2.3` or `AC-17(2)` into a rule without having read the benchmark
would be inventing an identifier. That is the same act as inventing a vendor
default and no more defensible for being about a standard rather than a device.

A mapping differs from a platform default in one way that was weighed explicitly:
it cannot produce a wrong PASS. The engine evaluates the canonical check; the
mapping only labels which control the result is reported *under*. So the failure
mode is a wrong **claim of coverage** rather than a wrong verdict — an
audit-credibility failure rather than a correctness one. It is still a failure,
and in a tool whose entire value is that its output can be trusted, it is the
kind that is hardest to recover from.

`project_asserted` mappings are **not** used to make the product appear to have
coverage. The enum member remains for a future sourced-crosswalk workflow.

**Until a benchmark edition is obtained and cited, no document, report or
presentation may claim CIS, NIST SP 800-53, DISA STIG or ISO/IEC 27001 coverage.**
`test_no_framework_mappings_are_claimed` asserts the empty state and is written to
be deleted by whoever adds the first sourced mapping.

## D17 — a versioned rulepack container

`FindingProvenance.rulepack_version` existed from P1 with nothing to fill it. The
new `Rulepack` contract fills it: id, version, status, rules.

Modelled on `VendorPack` but **deliberately without its `checksum` field**. The P4
review established that pack checksums are declared and never verified against
file bytes, and that fixing it belongs to P11. Copying an unverified integrity
mechanism into a second contract would double the problem rather than solve it, so
this contract does not pretend to offer one.

## D18 — a type mismatch abstains, and is caught at authoring time

A rule declaring `lte: "600"` against an integer field, or `contains` against a
boolean, cannot be evaluated. Python would happily compare some of those pairs and
raise on others, and both outcomes are wrong here.

**At runtime** the condition returns `None`, which becomes UNKNOWN with the new
`rule_type_mismatch` reason. Its own reason, not `no_match`: those say opposite
things about where the fault lies. `no_match` means the vendor packs cannot read
this control and it belongs in the training queue; `rule_type_mismatch` means the
packs read it fine and the *rule* is wrong. Collapsing them would hide a broken
rule inside a legitimate coverage gap, abstaining on every device forever while
looking supported.

**At authoring time** `load_rulepack` runs a self-check and refuses to return a
pack containing a condition that could never evaluate against any value shape. So
the safe behaviour is available at runtime and the loud behaviour happens where an
author will meet it.

A related subtlety worth recording: **booleans are excluded from numeric
comparison explicitly.** In Python `True == 1` and `isinstance(True, int)`, so a
boolean field compared with `gt: 0` would otherwise silently evaluate — a
comparison nobody meant to write, producing a verdict nobody meant to make.

## D19 — run identity

`audit_id` is a UUID minted per run and used as the subject of that run's
`AUDIT_RUN` chain entry, so the audit log and the findings it describes share one
key rather than being correlated by timestamp. `engine_version` is a module
constant kept in step with the package version; a verdict is only reproducible if
the code that produced it is identified, not just the data.

## DEF-4 — a documented guarantee, now enforced

`AbsencePolicy`'s docstring stated that abstention on an undocumented capability
was *"deliberately not overridable to PASS or FAIL by accident"*. **There was no
validator.** A rulepack could set `on_capability_unknown: pass` and the model
accepted it.

After P5 that mattered more than it did at P1. No platform defaults ship, so
`capability_unknown` is the reason behind every absent field on every corpus
device — one line of YAML could have turned that entire surface into passes.

It was contained: the `Finding` contract refuses a PASS with no evidence, so such
a rule crashed the audit rather than producing a false verdict. But that is
containment in the wrong place — a mid-audit validation error thrown from a
different contract, naming no rule. A guarantee documented in one place and
enforced three layers away is not a guarantee.

`on_capability_unknown` now accepts **only** UNKNOWN. Not PASS or FAIL, which are
verdicts on evidence we do not have. Not NOT_APPLICABLE either: that asserts the
control does not apply to this platform, and not knowing whether a platform
supports a control is precisely not knowing that. Not EVALUATE, which needs a
documented default that by definition is absent. The other two branches remain
configurable — the fix is narrow.

## OBS-1 — a sourcing backlog, not a training queue

`Finding.needs_training` covers parse gaps — `no_match`, `low_confidence`,
`uncalibrated_confidence`, `unparsed_block` — which the P10 training loop fixes.
It correctly excludes `capability_unknown`, and that exclusion is kept: no amount
of administrator training will teach the system what a vendor documents as a
default.

The consequence is that today's largest abstention category needs a **sourcing
backlog** rather than a training queue: *these controls are undeterminable until
someone reads the vendor documentation and records it with provenance*. That is
recorded in `docs/CORPUS_PREREQUISITES.md` as its own prerequisite, distinct from
needing more devices.

**No platform defaults were manufactured to make the branch reachable.**

## Consequences

`api/comply/` may import `api.models` and `api.audit` and **nothing else** from
`api/` — asserted as a whitelist rather than a blacklist, so layers P7 and P8 have
not written yet are forbidden too. No ML library, no network client, no vendor or
OS-family literal, no canonical field name. The audit edge cannot become
bidirectional: `api.audit` is separately forbidden from importing `comply`.

**No configuration content reaches the audit database.** The `AUDIT_RUN` payload
carries identifiers and counts — which device, which rulepack, how many findings
of each verdict. Never a value, never a raw line. Asserted by a test that reads
every audit row back and searches it for every line of the source configuration.

**Not built at P6, and why:**

- **Remediation.** `Finding.remediation` stays `None`. `RemediationRef` points
  into a vetted snippet library that does not exist, and a pointer to nothing is
  worse than an empty field. P8.
- **Prioritisation.** `exposure_score` and `priority_rank` stay `None`. Exposure
  reasoning needs ACLs, which the corpus does not contain at all. P7/P12.
- **Findings persistence and an HTTP surface.** They belong with the report layer
  that consumes them. `/health` reports `"phase": "P6"` and nothing else changed.
- **A rule for `https_server_enabled`.** The obvious check — require the HTTPS
  server enabled — would fail a device running no web management at all, which is
  the *more* secure configuration. The rule worth writing is conditional on
  another field, and `CheckSpec` examines one field by design. So the field is
  reported and not judged, rather than judged badly.
- **Rules over the remaining five canonical fields.** They have no parser support,
  so a rule would abstain on every device forever while looking supported.

**DEF-3 remains deferred.** `device_id` is the ingested file's content hash, so it
identifies this configuration rather than the physical device over time. Every
finding now carries it, and nothing may present it as a stable device identity
until the P12 identity work.
