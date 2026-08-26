# ADR 0005 — Conservative approach to framework content

- **Status:** Accepted
- **Date:** 2026-08-26
- **Decision reference:** R16
- **Affects:** `rules/`, `docs/CONTENT_POLICY.md`, `tests/architecture/`

## Context

NIRIKSHAK evaluates configurations against CIS Benchmarks, NIST SP 800-53, DISA
STIGs and ISO/IEC 27001, and cross-maps one canonical check to control IDs in
all four. The question is how much framework material the repository should
accumulate, given that the repository has a public remote.

An earlier draft of the project analysis characterised the licensing status of
specific standards. Those characterisations have been withdrawn: they were
outside the project's competence to assert, and nothing in the design should
depend on them.

## Decision

Take the conservative engineering approach.

The repository stores framework and control **identifiers**, our own rule
metadata, and **rationale we wrote**. It does not accumulate large amounts of
framework prose.

**No legal assumptions are made beyond that.** Any licensing review is a
separate exercise for the team and its institution, outside the scope of the
implementation plan.

## Consequences

Written down in `docs/CONTENT_POLICY.md` and enforced by
`tests/architecture/test_rule_content_policy.py`:

- No rule file may carry a field intended to hold verbatim framework text
  (`control_text`, `benchmark_text`, `standard_text`, `annex_text`, …).
- Every rule must carry an original `rationale`, capped at 1200 characters —
  generous for an explanation, tight enough to catch wholesale pasting.
- The policy document must exist and be non-empty.

**This costs the product nothing.** The compliance engine matches on
identifiers; control prose is not an input to any verdict. What an operator sees
in a report is the control identifier, our rationale, and the evidence line from
their own configuration — which is what makes a finding actionable in any case.

A related honesty measure, carried separately on each mapping: the
`mapping_provenance` field records whether a control mapping follows a published
crosswalk or is asserted by this project. Claiming less, verifiably, is worth
more in an audit tool than claiming more.
