# Data contracts

The eleven contracts NIRIKSHAK is built from, defined before the logic that uses
them (`DEVELOPER_GUIDE.md` §14). Implemented as Pydantic models in `api/models/`.

Two further types — `FieldMatch` and `ParseResult`, added at P4 — are documented
in §12. They are carriers for one layer rather than claims the whole system
rests on, so they sit alongside the eleven rather than joining them.

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
| Sub-threshold confidence becomes UNKNOWN, per population | `Field` pre-validator | Rule 3, D6 |
| Deterministic / admin-confirmed confidence must be exactly 1.0 | `Field`, `PatternDef`, `IdentityPattern` | D6 |
| A scope pattern that is not anchored is rejected | `PatternScope` validator | D9 |
| A literal block must declare exactly one terminator style | `LiteralBlock` validator | D7 |
| Uncalibrated similarity cannot support a claim | `Field`, `Suggestion` | R7 |
| An UNKNOWN field carries no value and states its reason | `Field` validator | Rule 3 |
| A PASS/FAIL finding needs evidence or an absence citation | `Finding` validator | Rule 2 |
| An UNKNOWN finding carries no remediation | `Finding` validator | Rule 3 |
| A snippet without a vetter cannot be built | `RemediationSnippet` | Rule 4 |
| A service-affecting snippet needs a rollback | `RemediationSnippet` | §8 |
| A rule carrying framework prose is rejected | `extra="forbid"` | R16 |
| A capability claim without sourced provenance is rejected | `PlatformCapability` | D11 |
| An unsourced platform default is unconstructable | `PlatformProvenance` | D11 |
| `on_capability_unknown` may only abstain | `AbsencePolicy` validator | Rule 3, DEF-4 |
| A rule condition that can never evaluate is refused at load | `load_rulepack` self-check | D18 |
| An undetermined ACL observation must state why | `AclObservation` validator | D24 |
| A shadowing claim must name the entries responsible | `AclObservation` validator | D22 |
| A user object has nowhere to carry a credential | `User`, by omission | D25 |
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

| Method | Probability? | Abstention floor (D6) | Notes |
| --- | --- | --- | --- |
| `deterministic` | No | **must be exactly 1.0** | A pattern matched or it did not |
| `admin_confirmed` | No | **must be exactly 1.0** | A human confirmed or did not; trust originates here |
| `platform_default` | No | its own floor (0.90) | Sourced and trusted, or not used |
| `calibrated_similarity` | **Yes** | the calibrated threshold (0.85) | The only calibrated population |
| `uncalibrated_similarity` | No | always UNKNOWN | **Forced to UNKNOWN whatever its value** |

**Each population is measured against the floor that means something for it**
(decision D6). Before P4 a single threshold applied to all of them, which
contradicted R7's own reasoning: a number calibrated against similarity scores
has no meaning applied to a parser confidence, because the two are not
comparable. The exact-1.0 populations have no floor to fall below — anything
else is rejected outright rather than quietly abstaining, because a fractional
deterministic confidence is a category error rather than a weak result.

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

**Interface management status is three-valued** (P5, DEF-2). `is_management` is
`bool | None`, where `None` means undocumented, so there are three accessors:
`management_interfaces()`, `non_management_interfaces()` and
`indeterminate_interfaces()`. They test `is True` / `is False` / `is None`
explicitly. A truthiness test folded `None` into "confirmed not management",
which converts ignorance into an answer — the exact substitution Rule 3 forbids,
in the one accessor P12's exposure prioritisation depends on. The indeterminate
case has its own accessor so a caller must decide what to do about it rather than
receiving it silently folded into a result.

`DeviceIdentity` here is **not** `api.models.ingestion.DetectedDeviceIdentity`.
This one is flat resolved strings plus a `device_id`; that one is a bundle of
`Field[str]` objects, each abstaining independently. Both were called
`DeviceIdentity` until P5, and only this one was exported — so an ambiguous
import silently returned the wrong class. `api/normalise/identity.py` converts
between them.

`device_id` is currently the ingested file's content hash, so it identifies *this
configuration*, not the physical device across time (DEF-3, deferred). Nothing
may present it as a stable device identity.

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
detect · identity · literal_blocks · comment_prefixes · patterns · defaults ·
capabilities`

Rule 5 in contract form. Patterns are deliberately boring: regexes must be
anchored with `^`, and `self_check()` runs each pattern against its own positive
and negative examples — the validation the P11 workflow gates activation on, and
which `api/train/activation.py` now genuinely gates on.

**As of P11 a pack's `checksum` is verified** on every load of an ACTIVE pack,
against the convention in `api/ingest/pack_checksum.py`: sha256 of the stored LF
bytes with the `checksum:` line removed. Verification fails closed — an
unverifiable ACTIVE pack refuses to load rather than being skipped, because a
skipped pack leaves a platform silently unparsed.

`PlatformCapability.supported is None` means undocumented, which must produce
abstention. A capability claim without a citation is rejected: a guess wearing a
citation field is worse than abstaining, because it looks authoritative.

**`PatternDef.confidence` and `IdentityPattern.confidence` must be exactly 1.0**
(decision D6). A deterministic pattern matched or it did not; there is no partial
match to express. Without this a pack author could encode a hunch as `0.6`, and
that number would travel through the system looking like evidence. Fractional
deterministic confidence would need a new ADR, not a YAML value.

**`PatternScope.block` entries are anchored regexes** (decision D9), matched with
`re.fullmatch` against each element of a node's `block_path`. Validation rejects
any entry not starting with `^`, so the intent stays visible in the YAML rather
than buried in the engine. `None` means root level only; `()` means any depth.
The reason is `line vty 0 4` versus `line vty 0 15`: substring matching cannot
tell them apart, and a scope that quietly matches more blocks than its author
intended is how a console timeout gets reported as a management idle timeout.
Generalising a range is written out (`^line vty \d+ \d+$`), never assumed.

### `LiteralBlock` — decision D7

`name · open · terminator · terminator_group`

A region whose body is free-form text rather than configuration: banner bodies,
certificate blocks, key blocks. Declared as pack data, so handling one is a
vendor-pack change rather than a parser change.

Two things go wrong if such a body is treated as configuration. It floods the
training queue with prose, and — much worse — it becomes reachable by pattern
matching, so a banner reading *"ip ssh version 1 is prohibited"* would produce a
security fact that is not in effect, carrying a citation that makes it look
verified. Declaring the block keeps the body preserved, line-numbered and
reconstructable while putting it beyond the pattern engine's reach.

Deliberately not banner-specific. A terminator is either a fixed literal
(`terminator: 'quit'`, closing a certificate) or a delimiter captured from the
opener (`terminator_group: 1`, the `^C` in `banner motd ^C`). Validation requires
exactly one of the two, requires `open` to be anchored, and rejects a
`terminator_group` naming a capture group the opener does not have.

`comment_prefixes` is the same idea for single lines. A commented-out directive
must never produce a PRESENT field, so these lines never become nodes. Identity
extraction is deliberately unaffected — it runs over raw lines, which is why
`! device: sw-leaf-01 (DCS-7050SX3-48YC8, EOS-4.29.2F)` still yields a model and
an OS version. Metadata legitimately lives in comments; active security
configuration never does.

That asymmetry is only as good as the lines a pack points it at. `cisco/ios`
read its model from `^! model (\S+)` until 1.3.0, and no Cisco device emits
such a line — it matched an annotation somebody wrote into one corpus file. The
Arista header is the opposite case: EOS writes it at the top of every
`show running-config`. Nothing in the repository can tell the two apart
automatically, because "does this platform emit this line" is vendor
documentation (`SOURCING_BACKLOG` gap 2). See ADR 0037.

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
presentation: `order_snippets` applies a high-risk change **last**, after the
snippets it depends on, because disabling an insecure management protocol before
its replacement is verified is how an operator is stranded outside their own
device.

**The library ships sourced** (decision D27, superseded). `vetted_by` and
`reference` are both mandatory, in the contract and in
`snippets/schema/snippet.schema.json`, so a snippet cannot exist without naming
the person who checked it and the document they checked it against. Twenty
snippets now do: seven rules across Cisco IOS and Juniper Junos, six across
Arista EOS, each citing the vendor command reference or configuration guide it
was checked against.

The twenty-first is deliberately absent. `NRK-SSH-001` asks for SSH protocol
version 2, and Arista EOS exposes no protocol-version setting to configure —
so `(arista, eos, NRK-SSH-001)` resolves to `NO_SNIPPET` and the operator reads
the statement rather than a command invented to fill the gap. That is the
resolver behaving correctly on live data, not a hole in the library.

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

## 12. The parsing layer — P4

`api/models/parsing.py`. Two types, both produced by `api/parse/` and consumed by
P5 and P10. They live in `api/models/` because that is the one package every
layer may import: a caller can read what the parser produced without importing
the parser, which is what keeps the boundary in `tests/architecture/` real.

### FieldMatch

`field · pattern_id · raw_capture · value · evidence · node_id`

One pattern firing on one node. Kept as an intermediate rather than collapsed
straight into a `Field` because **a field's outcome depends on all of its
matches**, not on any one of them: two matches agreeing is one value with two
citations, two matches disagreeing is an abstention. Collapsing early would
throw away exactly the information needed to tell those apart.

`pattern_id` and `node_id` are what make a field traceable back to the pack
pattern that produced it and the tree node it came from, which is what the P10
training queue and the P11 pack-version audit both need. At P11 the trace
extends one step further: an admin-trained pattern carries the training example
id and audit sequence it was compiled from, so a field resolves not only to a
pattern but to the person who confirmed it.

### ParseResult

`file_id · file_path · vendor · os_family · pack_version · tree · fields ·
residue`

Everything parsing determined about one file. `pack_version` is recorded on the
result, so a finding can later say which pack version read the line rather than
which pack version happens to be active when the report is generated.

`residue` is every node no pattern matched — the P10 training queue. Comments,
blank lines and literal-block bodies cannot appear in it, because they never
became nodes. That is the point of §6's `LiteralBlock` and `comment_prefixes`: a
residue queue full of `!` and banner prose would bury the lines an administrator
actually needs to look at.

**Abstention is uniform** — no field defines its own special case:

| Situation | Result |
| --- | --- |
| Pattern declared, nothing matched | UNKNOWN, `NO_MATCH` |
| Pack declares no pattern for the field | key omitted entirely |
| One match, or several agreeing | PRESENT, every citation kept |
| Several matches disagreeing | UNKNOWN, `CONFLICTING_EVIDENCE`, **all** citations kept |
| Multi-valued (`cast: list`) | PRESENT, values accumulate in source order |
| Cast failed | no fact — a plausible substitute is worse than a gap |

Key presence carries meaning. *The directive is absent from this configuration*,
which P5 resolves against a platform default, is a different claim from *we
cannot parse this control*, which routes to training. Both read UNKNOWN through
`state_of()`, so the distinction lives in whether the pack declared the field at
all rather than in a new abstention reason.

The disagreement row is the one that matters. Two lines saying different things
is not a tie to be broken by position — picking one would invent an answer the
configuration does not give. The field abstains and carries **both** citations,
so an operator can see exactly what could not be resolved.

**What `ParseResult` deliberately is not** is a Canonical Security Model.
Building one requires the per-OS capability and default model to decide what an
absent directive means, and deciding that in the parser would smuggle a
judgement into a layer that is supposed to have none. That is P5.

---

## 13. Platform knowledge — P5, decisions D11 and D13

`PlatformProvenance · PlatformDefault · PlatformCapability`, all in
`api/models/pack.py`. They live on the vendor pack because platform defaults are
vendor-specific configuration knowledge, versioned with the syntax they
accompany. **There is exactly one authoritative home for them** (D10).

### PlatformProvenance

`platform · source_type · source_id · locator · status · applies_to_versions`

A platform default is the one security claim NIRIKSHAK makes with **no
configuration line to cite** — the premise is that the directive is absent — so
the provenance is the entire justification. It is typed rather than free text
because the previous contract, `citation: str` with `min_length=1`, was cleared by
the string `"general knowledge"`.

Three validators make an unsourced claim unconstructable rather than merely
discouraged: a `sourced` claim must name a document, must carry a locator into it
(whitespace does not count), and `project_asserted` is a **biconditional** across
`source_type` and `status` — marking one without the other would let our own
assertion be presented as externally verified.

`project_asserted` is representable so a claim we cannot yet source can be written
down and reviewed. It is **not admissible**: `is_admissible` is true only for
`sourced`, and its `cite()` string says so wherever it is displayed. A field
resting on one abstains.

Per `CONTENT_POLICY.md` this holds **identifiers and locators only**. There is no
field for a document's wording, and a test asserts no prose-shaped field name
exists on the model.

### PlatformDefault and PlatformCapability

`PlatformDefault` has deliberately **no confidence field**, and forbids extras.
The confidence an accepted default carries is a single configured value (D13),
not a per-entry choice — otherwise the number becomes a dial for making a weak
claim look strong, the same failure D6 closed for deterministic patterns.

`PlatformCapability.supported is None` means undocumented, which must abstain
rather than assume in either direction. It carries the same provenance type, for
the same reason: `supported: false` resolves to ABSENT_UNSUPPORTED, a
determinable state a rule may act on, so an unsourced claim that a platform
*cannot* express a control is as dangerous as an unsourced default.

### The two confidence numbers

| Setting | Value | Meaning |
| --- | --- | --- |
| `platform_default_confidence` | 0.95 | What an accepted default is *assigned* |
| `platform_default_min_confidence` | 0.90 | The *admissibility floor* it must clear |

Deliberately unequal, so the floor stays testable in the failing direction.
Neither is a calibrated probability — this population is never pooled with
similarity scores when fitting the calibrator (R7).

---

## 14. Rulepack — P6, decision D17

`rulepack_id · version · checksum · status · created_by · rules`

`FindingProvenance.rulepack_version` existed from P1 with nothing to fill it. A
report read six months later has to be able to say which rules ran, for the same
reason `CsmSource.pack_versions` records which vendor pack read the line: a
verdict is reproducible only if the data that produced it is identified.

**`checksum` is verified at load** (ADR 0056). Until P18 the contract had none,
for a reason ADR 0013 gave at P6: pack checksums were then declared and never
verified (DEF-13), and copying an unverified mechanism would have doubled the
problem. That reason expired when DEF-13 was fixed at P11. This section then
said it had "paid off rather than expired" while ADR 0048 said it had expired;
meanwhile `1.0.0` named three different rule sets. `rules/rulepack.yaml` now
declares version and checksum over `canonical/*.yaml` and
`frameworks/*.index.yaml`; `load_rulepack` recomputes and refuses a mismatch,
and `FindingProvenance.rulepack_checksum` records it on every run.

`applicable_to()` selects rules whose `AppliesTo` admits a device. A rule that
does not apply produces **no finding at all**, rather than an UNKNOWN one: *this
check was never relevant here* and *we could not determine this check* are
different statements, and only the second belongs in an operator's queue.

### AbsencePolicy — `on_capability_unknown` is not configurable

It accepts **only** `UNKNOWN` (DEF-4). Until P6 the class merely *claimed* this in
prose while nothing enforced it, so a rulepack could set
`on_capability_unknown: pass` and be accepted. With no platform defaults shipped,
`capability_unknown` is the reason behind every absent field on every device — one
line of YAML would have turned that whole surface into passes.

Not PASS or FAIL, which are verdicts on evidence we do not have. Not
NOT_APPLICABLE, which asserts the control does not apply to this platform, and not
knowing whether a platform supports a control is precisely not knowing that. Not
EVALUATE, which needs a documented default that by definition is absent. The other
two branches remain configurable.

### `frameworks` ships empty (D16)

`FrameworkRef` is fully specified and no rule uses it. Writing a control
identifier without having read the benchmark would be inventing it. The field
exists structurally; it stays empty until a benchmark edition is obtained and
cited.

---

## 15. Structural analysis — P7, decision D22

`AclObservation · AclAnalysis · AclAnalysisResult`, in `api/models/analysis.py`.

**An ACL observation is not a compliance verdict**, and this contract exists so it
cannot be mistaken for one. `CheckSpec` reads `CSM.fields[name]` and has no path
to `CSM.acls`, so representing an ACL result as a `Finding` would have meant
widening the one object the whole Rule 1 argument rests on. Two rails instead:

| Input | Producer | Output | Claim |
| --- | --- | --- | --- |
| `CSM.fields` | rule engine (P6) | `Finding` | a device breaches a control |
| `CSM.acls` | analyser (P7) | `AclObservation` | a list does not do what reading it suggests |

Only the first needs a control to exist. `comply → analyse` is a forbidden import
edge, so a verdict cannot become influenceable by analysis performed outside the
canonical model.

Four observation kinds: `shadowed`, `redundant`, `overly_permissive`, and
`undetermined`. Validators enforce two things — an `undetermined` observation must
record *why*, and a shadowing or redundancy claim must **name the entries
responsible**, because an unattributed claim cannot be verified or acted on.

### Unresolved is UNKNOWN, not empty (D24)

`AddrSpec(kind=OBJECT)` may carry no `resolved_cidrs`; its address set is genuinely
unknown. Containment is therefore three-valued — `True`, `False`, `None` — and
`None` propagates. Treating unknown as *empty* would make such an entry match
nothing, so it could neither shadow nor be shadowed, and would drop silently out of
the analysis while the report looked complete.

## 16. Identity — P7, decision D25

`User · Role`, in `api/models/auth.py`.

**`User` carries no credential field at all** — no hash, no salt, no token. That is
structural rather than incidental: a user object cannot leak a credential into a
log line, an API response or an audit payload, because there is nowhere for one to
be attached. Passwords live only in the store, hashed with `hashlib.scrypt`
(RFC 7914), and are read only by `authenticate`.

Two roles. `user` sees only resources they own; `admin` sees the fleet.
`User.may_access(owner_id)` is the whole model, and an **unowned** resource is
admin-only — rows predating ownership have no owner, and defaulting those to
"everyone" would silently expose every earlier upload.

---

## What is not here yet

The prioritisation that scores exposure was built at P12, in `api/prioritise/`.
It consumes these contracts and weakens none of them: `exposure_score` and
`priority_rank` are populated only when exposure was actually determined, which
on this corpus is never — there is no interface and no access list to determine
it from. A score exists if and only if the assessment reached DETERMINED, which
is enforced at construction rather than by convention (ADR 0021, decision D53).

Chain-walking verification (P2), the block parser (P4), the normaliser that builds
a CSM (P5), the rule engine that evaluates one (P6), the ACL analyser (P7) and the
remediation resolver (P8) are now built, in `api/audit/`, `api/parse/`,
`api/normalise/`, `api/comply/`, `api/analyse/` and `api/remediate/` respectively.

**`Finding.remediation` is `None` everywhere, by construction** (decision D26).
`comply → remediate` is a forbidden import edge — a verdict is decided before
anything is proposed to fix it — so the engine has no way to resolve a snippet and
must not acquire one. Remediation is resolved downstream, in `api/report/` and at
the API edge, against a library whose version the report then records. The field
stays in the contract because a *stored* finding may one day carry the reference
that was resolved for it; nothing writes it today.
