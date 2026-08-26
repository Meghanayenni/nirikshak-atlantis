# Data contracts

The eleven contracts NIRIKSHAK is built from, defined before the logic that uses
them (`DEVELOPER_GUIDE.md` §14). Implemented as Pydantic models in `api/models/`.

The point of writing these first is that the guarantees which matter are
enforced **at construction**, not by the code that happens to call them. An
unjustified security claim is not discouraged in NIRIKSHAK; it is
unconstructable.

---

## Relationships

```
                    ┌─────────────┐
                    │  Evidence   │  file · line · raw text · sha256
                    └──────┬──────┘
         ┌─────────────────┼─────────────────┬──────────────┐
   ┌─────▼─────┐    ┌──────▼──────┐   ┌──────▼──────┐ ┌─────▼─────┐
   │ ConfigNode│    │  Field<T>   │   │  ACLEntry   │ │  Finding  │
   │ ConfigTree│    │             │   │     ACL     │ │           │
   └─────┬─────┘    └──────┬──────┘   └──────┬──────┘ └─────▲─────┘
    P4 builds              │                 │              │
                    ┌──────▼─────────────────▼──────┐       │
                    │  CanonicalSecurityModel       │───────┘
                    │  device · fields · acls ·     │  evaluated against
                    │  interfaces · residue         │  ComplianceRule
                    └───────────────────────────────┘       │
   ┌───────────┐    ┌───────────────┐    ┌──────────────────┴─┐
   │VendorPack │    │ComplianceRule │    │ RemediationSnippet │
   │ + Pattern │    │ + FrameworkRef│    └────────────────────┘
   └─────▲─────┘    └───────────────┘
         │  compiled from        ┌────────────┐
   ┌─────┴─────────┐             │AuditRecord │  every event above
   │TrainingExample│────────────►│ hash chain │  lands here
   └───────────────┘             └────────────┘
```

---

## The enforced guarantees

| Guarantee | Where | Rule |
| --- | --- | --- |
| A PRESENT field without evidence cannot be built | `Field` validator | Rule 2 |
| Confidence never substitutes for evidence | `Field`, checked independently | R7 |
| Sub-threshold confidence becomes UNKNOWN | `Field` pre-validator | Rule 3 |
| Uncalibrated similarity cannot support a claim | `Field`, `Suggestion` | R7 |
| An UNKNOWN field carries no value and states its reason | `Field` validator | Rule 3 |
| A PASS/FAIL finding needs evidence or an absence citation | `Finding` validator | Rule 2 |
| An UNKNOWN finding carries no remediation | `Finding` validator | Rule 3 |
| A snippet without a vetter cannot be built | `RemediationSnippet` | Rule 4 |
| A service-affecting snippet needs a rollback | `RemediationSnippet` | §8 |
| A rule carrying framework prose is rejected | `extra="forbid"` | R16 |
| A capability claim without a citation is rejected | `PlatformCapability` | §7 |
| An audit record whose hash disagrees with its payload raises | `AuditRecord` | §9 |
| A model actor may only perform `ai_suggested` | `AuditRecord` | Rule 1 |
| Every source line is a node or unplaced, never dropped | `ConfigTree` | R4 |

---

## 1. Evidence

The atom. Nothing else in the system is meaningful without it.

`file_id · file_path · line_start · line_end · raw_line · line_sha256 ·
source_type · locator · block_path`

`line_sha256` is **derived** from `raw_line` rather than accepted on trust. If a
caller supplies one that disagrees, construction fails — that would mean the
evidence and the text it cites had drifted apart, which is worth failing loudly
for.

## 2. ConfigNode / ConfigTree — decision R4

Structure before patterns. `exec-timeout 10 0` means one thing under
`line vty 0 4` and another under `line con 0`, so the enclosing chain is
established before any pattern is allowed to run.

Four invariants, each tested:

1. **Lossless** — `reconstruct()` reproduces the source exactly.
2. **Evidence** — `to_evidence()` yields a complete object with no further lookup.
3. **Total** — every line is a node or an `UnplacedLine`. Silent loss impossible.
4. **Deterministic** — same bytes in, same tree out.

Invariant 1 carries more weight than it appears to. If the tree round-trips to
the original bytes, then every `line_number` and `raw_line` in every piece of
evidence in the whole system is provably real source text. One property test at
the bottom of the stack underwrites the Rule 2 guarantee at the top.

## 3. Field&lt;T&gt; — Rules 2 and 3, decision R7

`value · state · confidence · confidence_method · evidence · default_ref ·
unknown_reason · provenance · raw_score`

**States.** `PRESENT`, `ABSENT_DEFAULT`, `ABSENT_UNSUPPORTED`, `UNKNOWN`.
Collapsing these into a nullable value is what makes other tools produce
misleading audits: *absent because the platform defaults to secure* and *absent
because someone removed it* are opposite conclusions from identical evidence.

**Confidence populations (R7).** `confidence_method` discriminates between kinds
of claim that merely share a numeric range:

| Method | Probability? | Notes |
| --- | --- | --- |
| `deterministic` | No | Confidence in the parser and pattern |
| `admin_confirmed` | No | 1.0 by definition; trust originates here |
| `platform_default` | No | Carries its citation |
| `calibrated_similarity` | **Yes** | The only calibrated population |
| `uncalibrated_similarity` | No | **Forced to UNKNOWN whatever its value** |

The last row is the substance of R7. A raw similarity score is not a confidence,
so a field carrying that method cannot assert anything — the score is retained in
`raw_score` for the training queue and for fitting the calibrator at P9, but it
can never support a claim.

Evidence and confidence are validated **independently**, so a confidence of 1.0
cannot satisfy the evidence requirement.

## 4. CanonicalSecurityModel — the trust boundary

`device · source · fields · acls · interfaces · residue`

The compliance engine accepts a CSM and nothing else, so there is no parameter
through which raw configuration text or model output could reach a verdict.

`fields` is an **open mapping**, not fixed attributes: adding a canonical field
is a data change in a pack and a rule, not an edit to this class (Rule 5).

`state_of()` treats an absent key as `UNKNOWN` — a field the parser never
produced is not determinable, which is the same conclusion as one produced
without confidence. Both abstain; neither becomes "no".

## 5. ACL

Modelled as **intervals** from the outset, because the P7 analysis is interval
logic. Two parallel representations are kept: `kind`/`value` is what the
operator wrote and what the report prints back; `resolved_cidrs` and
`low`..`high` are what the analysis consumes.

Entries must be in sequence order — order is semantically significant for
shadowing detection, so an out-of-order ACL is rejected rather than silently
sorted.

## 6. VendorPack

`vendor · os_family · pack_version · status · parent_version · checksum ·
detect · patterns · defaults · capabilities`

Rule 5 in contract form. Patterns are deliberately boring: regexes must be
anchored with `^`, and `self_check()` runs each pattern against its own positive
and negative examples — the validation the P11 workflow gates activation on.

`PlatformCapability.supported is None` means undocumented, which must produce
abstention. A capability claim without a citation is rejected: a guess wearing a
citation field is worse than abstaining, because it looks authoritative.

## 7. ComplianceRule

One canonical check owns the logic once; each framework contributes only a
mapping to its own control identifiers. Written the other way round, the same
logic would exist four times and drift four ways.

`Condition` uses a **closed operator set** rather than an expression language,
so a rule can never become a place where vendor logic or a model call reappears.

`AbsencePolicy` defaults to `UNKNOWN` for undocumented capability — the safe
answer.

Decision R16 is structural here: `extra="forbid"` means a `control_text` field
is rejected at load, and `rationale` is required and capped.

## 8. Finding

Note what this contract does **not** have: no field accepts model output, an
explanation that could carry a verdict, or a predicted status. A model has
nowhere to write even if something tried — tested explicitly.

`UNKNOWN` findings carry a reason and no remediation, and `needs_training`
distinguishes a parse gap (route to the training queue) from a capability gap
(nothing to teach; the documentation is what is missing).

## 9. RemediationSnippet

`key` is `(vendor, os_family, rule_id)` — remediation is **resolved**, never
generated. `vetted_by` is mandatory: an unvetted snippet is not a snippet.

A service-affecting snippet without a rollback is rejected; the operator must be
able to get back. `lockout_risk` drives dependency ordering at P8, not just
presentation.

## 10. TrainingExample

Records both what the model proposed and what the human decided, which is what
makes top-3 accuracy measurable in production rather than only on the benchmark.

If the administrator changed the field, the outcome is `CORRECTED`, not
`ACCEPTED_RANK_n` — enforced, so the metric cannot quietly flatter itself.

`raw_line_scrubbed` is stored post-redaction; the unscrubbed line never enters
the index, because this text reaches an embedding model (Rule 6).

## 11. AuditRecord

An append-only hash chain. Each record binds `payload_hash` and `prev_hash` into
`entry_hash`, so a retroactive edit anywhere breaks verification everywhere
after.

Canonical JSON — sorted keys, tight separators, UTF-8, no NaN — is required.
Without it the chain fails to verify across Python versions for reasons that
have nothing to do with tampering, which is the worst kind of false alarm in an
integrity mechanism.

A `MODEL` actor may perform `ai_suggested` and nothing else. The audit trail is
where the distinction between a proposal and a decision is made permanent.

---

## What is not here yet

Chain-walking verification (P2), the block parser that builds a `ConfigTree`
(P4), the evaluator that consumes a CSM (P6), and the resolver that reads
snippets (P7–P8). Those consume these contracts; none of them may weaken one.
