# ADR 0048 — Derived, or reconciled; never merely declared

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D123 (a self-description is derived or reconciled),
  D124 (remove `phase` rather than correct it), D125 (bind the rulepack version
  to the rules it contains)
- **Affects:** `api/main.py`, `tests/architecture/test_self_description.py`
  (new), `tests/test_health.py`, `ui/src/pages/Status.tsx`,
  `ui/src/types/api.ts`, `ui/src/test/helpers.tsx`

## The pattern, now seen three times

| Where | What it declared | How long it was wrong |
| --- | --- | --- |
| `OPEN_DEFECTS` | which defects are open | 3 phases (ADR 0046) |
| `is_detection_only` | whether a pack parses anything | 2 phases (ADR 0047) |
| `/health` `phase` | which phase this is | **6 phases** |

Each is a fact about the system **declared beside** the thing it describes
rather than **derived from** it. A declaration is correct when written and
cannot stay correct without somebody remembering — and every document, screen
and test downstream repeats it faithfully in the meantime.

## The audit

Every machine-readable self-description in the repository, classified.

### DERIVED — computed from what they describe

`is_detection_only`, `reads_no_canonical_field`, `reads_structure` ·
`frameworks_covered` and `has_official_mapping` (from the `frameworks` tuples) ·
`sourced_frameworks()` (from index files on disk) · `CatalogIndex.describe()` ·
`ExampleIndex.describe()` · `TrainingQueue.describe()` ·
`SnippetLibrary.version` (a digest over the snippet bytes) ·
`AclAnalysisResult.summary()` and `analysed_nothing` · `ParseResult.summary()` ·
`DetectionResult.summary()`/`explain()` · `PdfAvailability.summary()` and
`EmbeddingAvailability.summary()` (live probes) · `ChainVerification.summary()` ·
`CanonicalSecurityModel.describe()` · `Report.failures`/`abstentions`/`total`/
`platform_label` · `ExposureAssessment.describe()`.

**Nothing to do.** `SnippetLibrary.version` is the model the others should be
measured against: the bytes decide the value.

### DECLARED, and already reconciled

- **`VendorPack.checksum`** — verified against file bytes on every load of an
  ACTIVE pack (DEF-13, D47). The reconciliation that works.
- **`FrameworkRef.control_id` / `version` / `citation`** — every identifier must
  exist in the catalog index, must not be withdrawn, and must name the
  catalog's own edition (ADR 0035).
- **Pattern and identity `examples`** — must appear in a development-split
  corpus file (ADR 0010).
- **Architecture-document counts** — module count, ADR index, defect register
  (ADR 0046).
- **`snippet.vetted_by` / `reference`** — gated by the content-policy suite.

### DECLARED, and now reconciled here

- **`pack_version` against its own filename.** The version is written twice —
  once as a filename the loader sorts by, once as a field every stored finding
  cites through `pack_versions`. Only `packs/archive/` checked that they agreed.
  A pack activated under one number and cited under another is DEF-18's shape
  without the deletion: a finding naming a version that does not resolve to the
  bytes that produced it.
- **`status: active` across a platform's files.** `active_packs()` raises on two
  (D46), so this was caught at load — as a deployment that will not start. It is
  caught in the files now, where the fix is a one-word edit.
- **`ENGINE_VERSION` against `pyproject.toml`.** Its docstring said *"kept in
  step with the package version"*, which meant kept in step by somebody
  remembering, in two files. They agreed; nothing made them.

### DECLARED by necessity — external knowledge, gated instead

`PlatformDefault`, `PlatformCapability` and `InterfaceRole` assert what a vendor
documents. **Nothing in this repository can derive them**, and that is the
point: they require typed `PlatformProvenance`, only `SOURCED` is admissible,
and a test asserts all three ship empty. The gate is provenance, not
reconciliation, and it is the right one.

## D124 — remove `phase`, do not correct it

`/health` served `"phase": "P12"`. The UI displayed it on the Status page.
`tests/test_health.py` asserted it.

**A test was defending a claim that had been false for six phases.** That is
worse than an unguarded declaration: the suite, which is this project's entire
argument, was actively holding a wrong answer in place. Correcting it to `P18`
would buy exactly as long as the last correction did.

So it is gone from the endpoint, the type, the interface and the fixture. A
phase label has no runtime source to derive it from — the container does not
ship `docs/`, so even reading the highest ADR phase would work in a checkout and
fail in a deployment. A field that can only ever be declared, in a payload
somebody checks when they suspect they are running the wrong build, is better
absent.

`version` is derived from the installed distribution instead, and the same
literal in the FastAPI constructor — which feeds `docs/openapi.json` — goes with
it. A test reads `api/main.py` for version literals rather than checking the
response, because a literal that happens to be correct today is exactly what
this is for.

## D125 — bind the rulepack version to the rules

`Rulepack` has no `checksum` field. ADR 0013 gave the reason, and it was good:
pack checksums were *declared and never verified* at the time, and copying an
unverified integrity mechanism into a second contract would double the problem
rather than solve it.

**That reasoning expired at P11**, when DEF-13 was fixed and pack checksums
began verifying against file bytes on every load. Nobody revisited it. Since
then the rulepack has been the only versioned artefact in the system with
nothing binding its version to its contents: a rule could be edited, every
stored finding would go on citing `rulepack_version: 1.0.0`, and nothing
anywhere would notice — including the provenance block whose whole purpose is
to say which rules produced a verdict.

`RULEPACK_CONTENT` maps version to a digest over the rule files. Editing a rule
fails the build until somebody decides: a new version with a new digest, or the
same version with the digest updated and a reason in the commit.

> **Superseded at P18 (ADR 0056).** The binding moved from this test fixture
> into `rules/rulepack.yaml`, is verified at load, and is recorded on every run.
> The escape this section allowed — "the same version with the digest updated"
> — is closed: it is exactly the case the report's mapping guard could not
> detect.

It is a test fixture rather than a contract field deliberately. **The version is
a decision, not a fact** — editing a rule without bumping it is sometimes right
— and the reconciliation puts that question in front of a person at the moment
they can answer it. Verified by appending a comment to `NRK-NTP-001.yaml`: the
test fails, and passes again when it is reverted.

## What this does not reach

Prose in documents, beyond the counts already guarded. `pack.detect` weights,
which are tuning rather than description. And the DECLARED-by-necessity group,
which no mechanism in this repository can check because the facts live in
vendor documentation nobody here has.
