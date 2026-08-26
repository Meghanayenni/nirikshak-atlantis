# ADR 0010 — Corpus policy and evaluation separation

- **Status:** Accepted
- **Date:** 2026-08-27
- **Decision reference:** R9
- **Affects:** `corpus/`, `packs/`, the P9 evaluation harness
- **Enforced by:** `tests/integration/test_corpus_policy.py`

## Context

An evaluation is worth exactly its separation guarantees. `DEVELOPER_GUIDE.md` §13
forbids faked evaluation results, and the governing instruction for this corpus
is to prefer **a small auditable corpus over a large unverified one**.

## The honest statement, first

**Every configuration in this corpus is synthetic.** It was written by the team
to be realistic; none of it was captured from a real network. No file here is
real-world configuration data and none may be represented as such. The manifest
records `source_type: synthetic` and `is_real_world_data: false` on every entry,
and a test asserts both.

The P9 evaluation report inherits this. It may report what it measured on eleven
hand-written files across four platforms, and it **may not claim universal
vendor coverage** on that basis. Generalisation to the held-out vendor may be
claimed only to the extent the measured results demonstrate it.

## Four categories

| Category | Location | Purpose | Contributes to metrics |
| --- | --- | --- | --- |
| **A** Unit fixtures | `tests/fixtures/configs.py` | Mechanical edge cases — mixed line endings, binary, empty | **Never** |
| **B** Development | `corpus/<vendor>/dev/` | Vendor packs are authored from these | No |
| **C** Evaluation | `corpus/<vendor>/eval/` | Hand-labelled; only the P9 harness reads them | Yes |
| **D** Held out | `corpus/holdout/` | PAN-OS — generalisation experiment only | Generalisation only |

Category A never migrates. A twelve-line file with deliberate CRLF damage
exercises a splitter and would flatter any parser; those files stay in `tests/`
permanently.

## Vendors

Cisco IOS, Arista EOS, Juniper JunOS, and **PAN-OS held out entirely**.

Arista is included deliberately *because* it resembles IOS. Their overlap is
what exercises the `min_margin` ambiguity rule; without a near-neighbour that
rule would never fire and would be untested decoration.

PAN-OS is the holdout because its XML form is maximally unlike the other three,
making top-3 accuracy on it a real generalisation test rather than a
near-neighbour lookup. It has no vendor pack, appears in no development label,
and no pack file mentions it — all asserted.

## Ground truth

**A label is authored from the configuration, never from parser output.**

Running the parser and accepting its answer as truth measures self-consistency
and nothing else, and it is the easiest way to produce an evaluation that looks
excellent and is worthless.

Each label file records `labelled_by`, `labelled_at` and
`parser_version_at_labelling` — null where the field was labelled before any
pattern for it existed. Where a label was written after the fact, the file says
so, and the P9 report separates the two populations rather than blending them.

Labels must distinguish three states per field, not two: the correct value, and
whether the control is **determinable at all**. The third is what makes
correct-abstention measurable, and no automated process can supply it.

## Sanitisation

- RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`) and RFC 1918 addressing only.
- Hostnames under the reserved `.example` domain.
- **No credentials in any form, including hashed ones.** A type-7 or MD5 hash is
  crackable, so a file containing one is not sanitised.

Checked rather than promised: tests scan every corpus file for credential
patterns, non-documentation addressing and non-reserved domains.

## Separation, enforced mechanically

| Guarantee | Mechanism | Failure it prevents |
| --- | --- | --- |
| Every file accounted for | Manifest completeness + checksum test | An unlisted file quietly entering a metric |
| No file in two splits | Split uniqueness test | Training and evaluating on the same bytes |
| Directory matches declared split | Path/split agreement test | A file drifting between splits unnoticed |
| Packs authored from `dev` only | No `PatternDef.examples` or `IdentityPattern.examples` line appears verbatim in an `eval` or `holdout` file | Memorisation dressed as accuracy |
| Holdout has no pack | No pack for the held-out vendor; no pack file mentions it | The generalisation number being fiction |
| Nothing claimed as real | `is_real_world_data: false` on every entry | Synthetic data presented as captured |

## How P3 fixtures reach P9

They mostly do not, and that is the point.

- **A never migrates.**
- **B may become C only by moving** to the `eval` split and being labelled, with
  the manifest updated. The verbatim-example test then guarantees no pattern was
  authored from it — if one was, the move fails the test rather than passing
  quietly.
- **D is never touched.** Because no pack is ever authored for the held-out
  vendor, there is nothing that could contaminate it. The guarantee is
  structural: absence of a pack file, checked.

## Consequences

Eleven files today: six development, three evaluation, two held out. Small, and
every one auditable — which is the stated preference. Growing the corpus means
adding manifest entries with provenance; the tests fail otherwise.

If legitimately usable real sanitised configurations become available, they may
be added with `source_type` recording their real provenance. Until then the
corpus is synthetic and says so.
