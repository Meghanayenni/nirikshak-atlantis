# ADR 0023 — The architecture document, and the tests that keep it true

- **Status:** Accepted
- **Date:** 2026-08-29
- **Phase:** P14
- **Decisions:** D63 (P14 is a documentation phase and its own commit),
  D64 (the document is test-enforced), D65 (P14 owns no defect)
- **Defects:** none fixed, none introduced. DEF-3 and DEF-8 remain open.
- **Related:** every prior ADR; this one indexes them.

## Context

`README.md` has carried a single forward commitment since P8:

> Full architecture: `docs/architecture.md` (written at P14).

A sweep of the repository at P13's HEAD found that line to be the **only** P14
reference anywhere — not in `DEVELOPER_GUIDE.md`, which defines constraints rather than a
phase ladder, not in the twenty-two ADRs, not in code. So P14's scope is exactly
one document, and this ADR records that finding rather than assuming a larger
phase existed.

Every capability the Concept Report describes is now either built or blocked on
sourcing. Inventing a P15 to have something to build would be the failure this
project has refused at every phase, in the one place it would be easiest to
commit — at the end, with the pressure to look finished.

## D63 — a documentation phase, and its own commit

P14 could have been a README section. It was written as its own document and its
own commit for two reasons: the README is already long and is addressed to
somebody deciding whether to run the thing, while the architecture claim is
addressed to somebody deciding whether to trust it; and a reviewer needs a
citable place for "here is what the system actually does".

The document is written for a reader who has not followed P0–P13. That constraint
did most of the shaping: it forced the pipeline diagram to show the advisory
branch *beside* the spine rather than in it, and it forced §7 — *what NIRIKSHAK
does not currently claim* — to be a full section rather than a footnote.

## D64 — the document is test-enforced

`tests/architecture/test_architecture_document.py`.

An architecture document is the easiest file in a repository to leave behind:
written once, read by reviewers who cannot check it, and quietly becoming a
description of the previous release. This project already refuses that pattern —
P8's report disclosures are *computed* from the findings rather than typed, so a
sentence stops being emitted the day its gap closes.

So every structural claim is checked against the thing it claims about:

| Claim | Checked against |
| --- | --- |
| The packages it names | `api/` on disk — **both directions**, so a package added later and never written up fails too |
| The module count it quotes | `len(api.rglob("*.py"))` |
| The forbidden-edge count | `FORBIDDEN_EDGES` itself, not a copy |
| The per-package edge breakdown | the same constant, tallied |
| Every ADR it cites | `docs/adr/` — again both directions |
| DEF-3 and DEF-8 marked open | an explicit `OPEN_DEFECTS` constant |
| No fixed defect claimed open | the complement of that constant |

`OPEN_DEFECTS` is a constant rather than something parsed from the document's own
prose, deliberately: if both sides of the comparison were derived from the same
text the test would pass vacuously. Updating it is a deliberate act, which is
correct — closing DEF-3 or DEF-8 means changing a contract or a measurement, and
whoever does that should have to say so in a second place.

Three further tests refuse content the rest of the system refuses:

- **no framework identifier** — a plausible `CIS 1.2.3` in an architecture
  document would be read as coverage by anyone who did not open `rules/`;
- **no device command** — a command in prose here would be attributed to nobody,
  checked against nothing, and pasteable into a production device on NIRIKSHAK's
  authority (Rule 4);
- **no percentage** — the harness reports measurements in
  `eval/reports/evaluation.txt` where they carry their own caveats; a figure
  quoted here would travel without them.

### One test written and removed

A guard asserting *this module never reads the holdout* was written, and deleted
during review: it matched its own search fragments, and a test that trips on the
strings it searches for is noise rather than a control. The module reads exactly
two things — the document, and the filenames in `docs/adr/` — which its docstring
now states, and the repository-wide holdout guards already cover production code.

Recorded here because deleting a test deserves a reason on the record.

## D65 — P14 owns no defect

No ADR assigns DEF-3 or DEF-8 to this phase, and a documentation phase is the
wrong place to change a contract.

**DEF-3** — `device_id` is the configuration file's content hash. Fixing it
redefines an identifier that every `Finding`, every `audit_run` row, every report
and the P9 evaluation already carry, which would move a measurement. P12
established that peer baselines do not need it: the comparison is
cross-sectional, not longitudinal. The real consequence — a configuration
re-uploaded after an edit counts as a second device in its cohort — is recorded
in the register rather than hidden.

**DEF-8** — `NRK-TIMEOUT-001` passes `exec-timeout 0 0`. The correct check is
"at most 600 **and** greater than zero", and `CheckSpec` examines one field with
one operator from a closed set; `lte` cannot express it. The fix needs a new
`ConditionOp` or a multi-condition `CheckSpec` — a compliance-engine contract
change belonging to a rules phase with its own ADR.

Both are documented with their reasons, which is what P14 owed them.

## Consequences

**The roadmap is complete.** Every phase named in the repository — P0 through
P14 — is implemented, and no phase remains unassigned. What is left is on
`docs/SOURCING_BACKLOG.md`: eight gaps, none of which can be closed by writing
code, and none of which may be closed by inventing data.

**Nothing measured, nothing claimed.** P14 adds no metric, no capability and no
endpoint. It adds a map, and the tests that stop the map drifting from the
territory.

**Not done at P14:**

- Any change to `api/`, `rules/`, `packs/`, `snippets/`, `corpus/`, `eval/` or
  `ui/`.
- Any change to `docs/ui_reference.html`, which remains the untouched visual
  specification.
- Any change to an existing ADR or an existing test.
- Any fix to DEF-3 or DEF-8.
