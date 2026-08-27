# ADR 0012 — Normalisation, and what an absent directive means

- **Status:** Accepted
- **Date:** 2026-08-27
- **Phase:** P5
- **Decisions:** D10 (one home for platform knowledge), D11 (typed provenance),
  D12 (scrubbing at the inference boundary), D13 (platform-default confidence),
  D14 (one CSM per file)
- **Defects addressed:** DEF-1 (fixed), DEF-2 (fixed), DEF-3 (deferred, recorded)

## Context

P4 produces facts about lines that exist. P5 answers the harder question: when a
hardening directive is simply **not there**, what does that mean?

The Concept Report calls this the single distinction separating a usable audit
from a misleading one. A directive may be absent because the platform already
does it by default, or because someone removed it — opposite conclusions from
identical evidence. Getting it wrong in the convenient direction produces a
confident PASS on a device nobody checked.

The `CanonicalSecurityModel` contract was written at P1 and has not changed since.
P5 is the first code that fills one in, and it did so without needing to alter the
CSM — which is the strongest available evidence that the shape P1 chose was right.

## The absence table

The whole phase, in one table. It lives in `api/normalise/absence.py` and is
driven entirely by pack data.

| Parse outcome | Pack capability | Pack default | Result |
| --- | --- | --- | --- |
| matched | — | — | PRESENT, untouched |
| no match | `supported: false` | — | ABSENT_UNSUPPORTED |
| no match | `supported: true` | admissible | ABSENT_DEFAULT |
| no match | `supported: true` | inadmissible | UNKNOWN · `no_match` |
| no match | `supported: true` | none | UNKNOWN · `no_match` |
| no match | undocumented or absent | — | UNKNOWN · `capability_unknown` |
| pack declares no pattern | — | — | key absent, reads UNKNOWN |

Three properties hold across every row.

**Undocumented never becomes "unsupported".** A missing capability entry is
`None`, not `False`. Reading it as `False` would turn every unasked question into
ABSENT_UNSUPPORTED, which a compliance rule may legitimately treat as
not-applicable — so ignorance would silently become a pass. This is the row that
earns the phase, and it has its own test asserting the negative.

**Capability is asked before default.** A pack documenting a default while saying
nothing about whether the platform supports the control has not established
enough to assert. Applying the default anyway would assume support that was never
claimed.

**Nothing in the module knows what any field means.** There is no vendor name, no
OS family and no canonical field name anywhere in `api/normalise/` — asserted by
architecture tests, including a word-boundary scan for twelve vendor literals.
That is Rule 5 made structural: teaching NIRIKSHAK a platform's defaults is a
pack edit.

## D10 — one home for platform knowledge

Platform capabilities and defaults live in `VendorPack.capabilities` and
`VendorPack.defaults`. **There is exactly one authoritative source.**

`rules/platform/` existed as an empty directory created at P0 with no ADR
explaining it. It has been **removed**. Two plausible homes for the same
knowledge is how a second source of truth starts, and an empty directory whose
name implies a design decision is worse than no directory at all.

The pack is the right home because this knowledge is vendor- and
platform-specific configuration knowledge, not compliance content. In the pack it
is versioned with the syntax it accompanies, it travels with the `pack_version`
recorded in `CsmSource`, and a P11 pack activation re-versions it as one unit.
In `rules/` it would sit with framework material governed by a content policy
about a different kind of risk.

## D11 — provenance is typed, and an unsourced claim is unconstructable

The old contract was `citation: str = Constraint(min_length=1)`. The string
`"general knowledge"` cleared that bar. A platform default asserting *"this
platform disables the HTTP server by default"* on that basis would have passed
every test in the repository and injected an unverified security claim straight
into a compliance verdict.

`PlatformProvenance` replaces it, and carries:

| Field | Purpose |
| --- | --- |
| `platform` | Vendor/OS-family the claim is about |
| `source_type` | Vendor documentation · release notes · standards body · project asserted |
| `source_id` | Document identifier or title |
| `locator` | Section, table, page or anchor within it |
| `status` | `sourced` or `project_asserted` |
| `applies_to_versions` | Version range verified against, where narrower |

Three validators make an unsourced claim impossible rather than merely
discouraged:

- a `sourced` claim must name a document — one that cannot be looked up is an
  assertion, and must be labelled as one;
- a `sourced` claim must carry a locator — *"somewhere in the configuration
  guide"* is not a citation, and whitespace does not satisfy it;
- `project_asserted` is a **biconditional** across `source_type` and `status`.
  Marking one without the other would let our own claim be presented as
  externally verified, so both must say it or neither may.

`PlatformCapability` carries the same type, for the same reason. `supported:
false` resolves to ABSENT_UNSUPPORTED, which is a determinable state a rule may
act on — an unsourced claim that a platform *cannot* express a control is exactly
as capable of producing a wrong verdict as an unsourced default.

### `project_asserted` is representable, not admissible

It exists so a claim we cannot yet source can be written down, reviewed and later
sourced, rather than living in someone's head. It is **not** vendor
documentation, must never be presented as externally verified, and **cannot
support a compliance verdict**. A field resting on one abstains.

That reading is deliberate and worth stating plainly, because it is the strictest
of the available readings: `is_admissible` is true only for `SOURCED`. Its own
`cite()` string says *"NIRIKSHAK project assertion (not externally verified)"*, so
it cannot be mistaken for a sourced claim anywhere it is displayed.

Per `docs/CONTENT_POLICY.md`, provenance records **identifiers and locators
only**. There is no field for the document's wording, and a test asserts that no
prose-shaped field name appears on the model.

## Zero platform defaults are shipped

**No vendor documentation has been sourced, so no pack declares a single default
or capability.** Every absent field on every corpus device resolves to UNKNOWN ·
`capability_unknown`.

This is the honest state, and it was the instruction: do not fabricate defaults to
make the pipeline look more complete. The synthetic corpus cannot substitute for
vendor documentation either — a corpus file is a claim about *a device we wrote*,
never about what a vendor documents as its platform's behaviour. A test asserts
that no platform claim cites a corpus path or filename.

The consequence is that the absence engine is fully built, fully tested against
synthetic packs, and currently resolves everything to UNKNOWN in production. That
is Rule 5 working as intended: the moment someone reads a vendor document and
records it, the behaviour changes with no code release.

`test_no_platform_defaults_are_shipped_yet` fails loudly when the first default
appears. It is **expected to be deleted** by that change, so its author has to
look at the provenance tests rather than adding data quietly.

## D12 — scrubbing sits at the inference boundary, never at rest

```
raw configuration          verbatim, byte for byte
    ↓
stored source / evidence   also verbatim — this is what a report cites
    ↓
scrubbed representation    a derived view, built in api/security/scrub.py
    ↓
inference boundary (P10)   the only consumer
```

Redacting at rest would destroy the thing the whole system rests on. *"Your SNMP
community is weak"* beside `<redacted>` is not evidence of anything. `blobs.py`
took this decision at P3 for storage; `scrub.py` is its other half.

The two failure directions are not symmetric. **Under-redaction** puts a
credential into an embedding index, which is irreversible once written.
**Over-redaction** costs the similarity layer some signal on a line that was never
sensitive. So the patterns lean toward redacting, and the replacement preserves
the line's shape — the directive keeps its keyword and its Cisco type tag, and
only the material goes. A type 7 password is trivially reversible and a report
should be able to say so without ever holding it.

**One pattern, one pass.** Sequential passes re-fire on their own output:
`password 7 04585A` would become `password 7 <redacted>` and then
`password <redacted> <redacted>`, silently destroying the type tag. That bug was
written and caught by the idempotency test during P5, which is why the test
exists.

**Known limit, stated rather than papered over.** Every corpus file is sanitised
by policy — `corpus/MANIFEST.yaml` requires no credentials in any form, including
hashed ones — so there is deliberately nothing in the corpus for the scrubber to
catch and its tests are necessarily synthetic. The dangerous direction is exactly
the one synthetic tests are worst at. **P10 must re-scrub at its own boundary
rather than trusting this pass.** Defence in depth, not a single gate.

## D13 — two numbers, and they are not the same number

| Setting | Value | Meaning |
| --- | --- | --- |
| `platform_default_confidence` | **0.95** | What an accepted default is *assigned* |
| `platform_default_min_confidence` | **0.90** | The *admissibility floor* it must clear |

They are deliberately unequal. Setting the assigned value at the floor would put
every default exactly on the boundary, which makes the floor untestable in the
failing direction and reads as a coincidence rather than a decision. Because they
differ, a test can lower the assigned value and watch a field abstain.

**Neither is a calibrated probability.** The platform-default population is not
similarity-derived and is never pooled with model scores when fitting the
calibrator at P9 (R7). `confidence_is_probability` returns False for it.

**A pack author cannot choose it.** `PlatformDefault` has no `confidence` field
and forbids extras, so the number exists in exactly one place. Otherwise it
becomes a dial for making a weak claim look strong — the same failure D6 closed
for deterministic patterns.

**Confidence is applied only after provenance has already qualified the claim.**
The number never rescues a claim that failed admissibility; it is applied to one
that passed.

D6 is unchanged and now reads in full:

| Population | Confidence |
| --- | --- |
| `deterministic` | exactly 1.0 |
| `admin_confirmed` | exactly 1.0 |
| `platform_default` | the configured 0.95, floor 0.90 |
| `calibrated_similarity` | the calibrated threshold |
| `uncalibrated_similarity` | always UNKNOWN |

## D14 — one CSM per configuration file

`build_csm()` takes one `ParseResult`. `build_csm_from_sources()` takes a list, so
a later fleet-grouping layer is a change of caller rather than a change of
contract — but it **raises** on disagreement rather than merging. Two files
claiming different values for the same control is a question for a human, which
is the same reasoning P4 applies to two conflicting lines inside one file.

Multi-device splitting is not built. Ingestion metadata identifies one device per
file today, and inventing grouping without it would be guessing.

## Defects

### DEF-1 — fixed

Two classes were both named `DeviceIdentity`, in `api/models/csm.py` and
`api/models/ingestion.py`, and only the CSM one was exported — so
`from api.models import DeviceIdentity` silently returned the wrong class for
anyone meaning the ingestion one. The ingestion type is now
**`DetectedDeviceIdentity`**.

Nothing external changed: it was never exported from `api.models`, and its three
call sites are all inside `api/ingest/`. P5 is the first layer holding both at
once — `api/normalise/identity.py` converts one into the other — which is exactly
where the ambiguity would have bitten.

### DEF-2 — fixed

`management_interfaces()` was `tuple(i for i in self.interfaces if
i.is_management)`. `is_management` is `bool | None` where `None` means
undocumented, and `None` is falsy — so an interface whose management status was
**unknown** was silently returned as confirmed non-management.

That is the exact substitution Rule 3 forbids, sitting in the one accessor P12's
exposure-aware prioritisation depends on. A management interface we failed to
classify would have been quietly de-prioritised rather than surfaced.

Now `is True` / `is False` / `is None`, with three accessors:
`management_interfaces()`, `non_management_interfaces()` and
`indeterminate_interfaces()`. The indeterminate case has its own accessor so a
caller must decide what to do about it rather than receiving it folded into an
answer. Tests cover all three states and assert they partition the set.

The model was not weakened — `is_management` still accepts all three values.

### DEF-3 — deferred, recorded

`device_id` is the ingested file's content hash, so editing a configuration
produces a different device identity, and the `device` table carries one
`file_id` while `CsmSource.file_ids` is a tuple.

P5 does not redesign this. `device_id` is passed into `build_csm()` as an
argument rather than derived inside it, so the eventual fix is a change at the
call site. The CSM docstring states explicitly that it identifies *this
configuration*, not the physical device across time, so nothing presents it as a
stable device identity. The lifecycle decision belongs to the phase that needs
it — P12, where peer-baseline detection must recognise the same switch over time.

## Consequences

`api/normalise/` may not import `api/comply/`, `api/learn/`, `api/remediate/`,
`api/report/`, any ML library or any network client — all asserted, and the four
forbidden edges out of `normalise` did not exist before P5.

The compliance engine at P6 still consumes the canonical model and nothing else.
Residue reaches the CSM as `UnknownLine`, which carries no value, state,
confidence or evidence — so scrubbed text has no route into a `Field` and cannot
become a verdict. That is asserted rather than assumed.

**Not built at P5, and why:**

- **ACL normalisation.** The corpus contains no ACL in any split. Searching every
  development and evaluation file for `access-list`, `access-group`, `ip access`,
  `firewall`, `filter`, `policy-map` and `class-map` returns nothing. Recorded as
  a fifth entry in `docs/CORPUS_PREREQUISITES.md`.
- **Interface extraction.** Interfaces *are* in the corpus, but no pack declares
  interface patterns and `Interface` is a structured object rather than a
  `Field`, so the P4 pattern machinery does not produce one. Deferred to the
  phase that consumes them.
- **CSM persistence.** No migration. The model is built in-process for P6.
