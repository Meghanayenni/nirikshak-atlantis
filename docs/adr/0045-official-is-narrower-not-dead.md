# ADR 0045 — `OFFICIAL` is narrower, not dead

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D118 (`OFFICIAL` is unreachable from a control catalog, which
  is not the same as unreachable)
- **Affects:** `api/models/enums.py`, `tests/unit/test_framework_mappings.py`,
  `docs/adr/0035-framework-mappings-against-a-content-addressed-catalog.md`
- **Narrows:** ADR 0035 (D92) — not its decision

## What was over-stated

ADR 0035 established that every mapping this project ships is
`project_asserted`, and the reasoning was right: a control catalog publishes
**controls**. NIST's OSCAL edition of SP 800-53 says `AC-17(02)` exists, what it
requires and where it sits. It cannot say that NIRIKSHAK's SSH check satisfies
it, because it has never heard of NIRIKSHAK. Marking such a mapping `OFFICIAL`
would credit a judgement nobody else made.

The conclusion drawn from it went too far: *"A crosswalk that names our checks
does not exist and is not going to."*

**A crosswalk is a different artefact from a catalog, and crosswalks do exist.**
CIS publishes mappings from its Benchmarks to NIST SP 800-53. NIST publishes
crosswalk material between SP 800-53 and ISO/IEC 27001. Those documents state
*mappings*, which is precisely the thing a catalog cannot state and precisely
what `OFFICIAL` was defined for.

So the accurate claim is: **`OFFICIAL` is unreachable from a control catalog.**
That is narrower, it is what the reasoning actually supports, and it matters.

## D118 — keep the member, and record what it would take

Writing `OFFICIAL` off as permanently unreachable would foreclose a real option,
not a theoretical one. It is the only route to claiming **CIS coverage without
obtaining the CIS Benchmark itself**:

1. our check → a CIS recommendation — this project's judgement,
   `project_asserted`, as every mapping here is;
2. that CIS recommendation → an SP 800-53 control — **stated by a published
   CIS crosswalk**, and `OFFICIAL` for that hop.

The second hop is somebody else's documented mapping, ingested rather than
judged. That is exactly the distinction `MappingProvenance` was drawn to carry,
and it survives the two-hop shape: each hop keeps its own provenance, and the
weaker one governs anything claimed end to end.

This project has obtained none of those documents, so nothing carries
`OFFICIAL` today and `test_no_mapping_is_marked_official` still asserts that.
What changed is the sentence beside it — the assertion holds **until a crosswalk
is obtained**, not indefinitely.

### Keeping a dead-looking value alive honestly

A member nothing uses invites tidying. Two things prevent it:

- the enum carries the explanation **in the source**, naming what a crosswalk
  is, why a catalog is not one, and the CIS route it keeps open. A test reads
  the source rather than `__doc__`, because a `StrEnum` member does not carry
  the literal that follows it — and the file is where somebody deciding to
  delete it would look;
- `test_official_remains_constructible_and_is_not_dead_code` builds a
  `FrameworkRef` and a `ComplianceRule` carrying it and asserts
  `has_official_mapping` is `True`. The path works; nothing shipped takes it.

That is the same shape as D73's `test_the_mirror_policy_resolves_to_false`:
prove the mechanism in both directions on constructed input, and let no shipped
data claim anything it cannot cite.

## What this does not change

No mapping's provenance. No claim of coverage. `sourced_frameworks()` still
offers NIST alone, CIS/STIG/ISO are still absent from the selector rather than
present and empty, and the report still says the mappings are asserted by this
project and are not a certification.

The correction is to a **sentence about the future**, and it is appended to
ADR 0035 rather than edited into it — the same treatment ADR 0006 got when its
environment finding went stale. The reasoning there was sound; one inference
drawn from it was not.
