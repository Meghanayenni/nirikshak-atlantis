# ADR 0056 — A version that means its contents

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D141 (the rulepack declares a checksum in data and the loader
  refuses rules that do not match), D142 (every run records the checksum, and
  mappings are re-attached by content, not by label)
- **Affects:** `rules/rulepack.yaml` (new), `api/comply/rulepacks.py`,
  `api/comply/errors.py`, `api/models/rule.py`, `api/models/finding.py`,
  `api/comply/engine.py`, `api/comply/service.py`, `api/db/findings.py`,
  `api/db/migrations/operational/0005_rulepack_checksum.sql` (new),
  `api/routers/audits.py`, `api/routers/reports.py`, `api/report/`,
  `tests/architecture/test_self_description.py`, `tests/unit/test_rulepack_loading.py`
- **Amends:** ADR 0013 (resolution appended), ADR 0048 D125 (superseded note)
- **Deletes:** `test_the_rulepack_has_no_checksum_field`

## Context — was the last session's finding resolved?

**Half.** ADR 0013 denied `Rulepack` a checksum because pack checksums were
declared and never verified at the time. That reason expired at P11. ADR 0048
(D125) noticed and bound version to digest — **in a test fixture**, and on
terms that said a rule edit could keep its version "with the digest updated and
a reason in the commit".

Two things were still true:

1. **Nothing checked at runtime.** Rules are data (Rule 5). A deployed `rules/`
   edited in place would load, evaluate and stamp every finding `1.0.0`. The
   vendor-pack loader has refused that for packs since D47.
2. **The escape was the failure.** The report shows today's control mappings
   beside a stored verdict only when the run was evaluated under the active
   rulepack (ADR 0036, D96), and it decided that by comparing *versions*. The
   label `1.0.0` had named three different rule sets — P6's, DEF-8's bounded
   timeout (ADR 0032) and the NIST mappings (ADR 0035) — so the comparison
   could not tell them apart. A run evaluated before the NIST mappings would
   have rendered with NIST identifiers the rules that decided it did not have.
   ADR 0052 fixed the label by minting `1.1.0`; this ADR fixes the comparison.

Three documents also disagreed about the reason. ADR 0048 said it had
**expired**. `docs/data-contracts.md` §14 and the docstring of
`test_the_rulepack_has_no_checksum_field` both said it had **"paid off rather
than expired"**, and that test asserted the field's absence "until somebody
makes" the decision about `rules/`. All three were written after P11.

## D141 — declare it in data, verify it at load

`rules/rulepack.yaml` declares `rulepack_id`, `version`, `checksum` and
`history`. The checksum covers every file under `canonical/` **and every
framework index** under `frameworks/`: since ADR 0052 the indexes decide which
identifiers a finding carries and on which platforms, so they are part of what a
version means. The convention is stated once, in `api/comply/rulepacks.py`.

`load_rulepack` recomputes it and raises `RulepackIntegrityError` on a
mismatch. The message says what to do: mint a new version and move the old one
into `history`. `CANONICAL_RULEPACK_VERSION` is gone; the version is read from
the manifest.

A test may build rules in a scratch directory by passing `manifest=None`, which
yields version `0.0.0` with no checksum — visibly not a shipped rulepack, and
opted into by name rather than degraded to silently.

The manifest's discipline is tested: no version repeats, and no checksum
appears under two versions — the first closes D125's escape, the second refuses
the mirror image. A tampered copy of one rule, or of one index, fails to load.

`history` records `1.0.0` honestly: three contents, no checksum recorded while
it was current, and D125's later digest named with its narrower convention.

## D142 — record the content, compare the content

`FindingProvenance.rulepack_checksum` is set by the engine; migration 0005 adds
`audit_run.rulepack_checksum`; the chain's `AUDIT_RUN` payload carries it. Both
routes that re-attach mappings — the report and the findings API — now compare
checksums. A run from before migration 0005 has NULL and never matches: nobody
recorded which rules decided it, and backfilling today's digest would assert
they were today's rules. Such a report renders without identifiers and its
provenance says *content not recorded*.

The test that pins it is the exact case D125 permitted: a run whose version
equals the active one and whose recorded content does not. It renders no
identifiers on either surface.

## The deleted test

`test_the_rulepack_has_no_checksum_field` asserted the field's absence and said
it would stand "until somebody makes" the decision about `rules/` that P11 did
not. This ADR makes it. It is replaced, in the same commit, by
`test_the_shipped_rulepack_carries_a_checksum_it_was_verified_against`.

## Not done

**Runs already stored keep their label.** Every run evaluated before this
commit says `1.0.0` or `1.1.0` with no checksum, and cannot be made to say
more. That is the defect this ADR stops recurring, not one it can repair.
