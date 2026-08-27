# Corpus prerequisites

Work that cannot begin until the corpus supports it. Each entry names the phase
it blocks and what would unblock it.

The governing principle, from decision R9: **prefer a small auditable corpus over
a large unverified one**, and never claim accuracy on data that has not been
properly labelled and separated.

---

## 1. XML configuration sample — blocks XML parsing

**Blocks:** implementation of `SyntaxMode.XML` in `api/parse/block_parser.py`,
and the `xpath` match primitive.

**Why it is blocked.** The only XML in the corpus is `corpus/holdout/panos/`,
and PAN-OS is the held-out vendor. Implementing XML parsing now would mean one
of two things, and both are worse than waiting:

- **Testing against the holdout**, which destroys the generalisation experiment
  the holdout exists for. Once we have read those files to build a parser, top-3
  accuracy on them measures memory rather than generalisation.
- **Building against a self-authored fixture**, which lets us claim XML support
  without ever having met a real XML configuration. A parser built for a shape
  we invented is wrong in exactly the ways only the real thing reveals.

**What would unblock it.** A legitimately sourced XML configuration sample that
is:

- independent of the PAN-OS holdout — a different vendor, or a genuinely
  different device and configuration;
- sanitised to the standard in `docs/CONTENT_POLICY.md` — RFC 5737/1918
  addressing, invented hostnames, no credentials in any form including hashed;
- recorded in `corpus/MANIFEST.yaml` with honest `source_type` provenance;
- assigned to the `dev` split if patterns are to be authored from it.

**Until then**, `build_tree(..., mode=XML)` raises `UnsupportedSyntaxModeError`
naming this document. It does not return an empty tree, which would look like a
successfully parsed empty configuration.

**Explicitly not acceptable:** writing an XML file ourselves and calling the
resulting parser "XML support".

---

## 2. Corpus breadth — blocks compliance-rule validation

**Blocks:** P6, where compliance rules are validated.

**Why.** P4 authored eight canonical fields from two Cisco devices. That is
sufficient to build and verify a parser — the two files disagree on five of the
eight fields, so the patterns are genuinely exercised. It is **not** sufficient
to validate compliance rules.

A rule that passes on two devices from one vendor has been tested against a
sample too small to say anything about the rule. The risk is not that the rule
fails; it is that it passes for reasons the corpus cannot distinguish from the
right ones.

**What would unblock it.** Before P6:

- more Cisco devices, with genuine configuration variation rather than
  near-copies;
- at least one further vendor with a real parsing pack, so cross-framework
  mapping is exercised against more than one syntax;
- devices that legitimately **lack** controls, so absence-aware evaluation has
  something real to reason about rather than only present directives.

**What must not happen.** Growing the corpus by templating the two existing
files. Near-identical devices inflate the file count without adding evidence,
and they make the fleet-cache and peer-baseline numbers look better than the
data supports.

---

## 3. Real sanitised configurations — affects what P9 may claim

**Blocks:** nothing. **Affects:** the honesty of every P9 evaluation number.

Every file in the corpus today is **synthetic** — written by the team to be
realistic, not captured from a real network. `corpus/MANIFEST.yaml` records
`source_type: synthetic` and `is_real_world_data: false` on every entry, and a
test asserts both.

The P9 report inherits that. It may state what was measured on hand-written
files across four platforms; it **may not** claim universal vendor coverage, and
it may claim generalisation to the held-out vendor only to the extent the
measured results demonstrate.

If legitimately usable real sanitised configurations become available they can be
added with provenance recording their real origin, and the evaluation gains
correspondingly. Until then the corpus is synthetic and says so.

---

## 4. Further literal-block declarations — affects parse cleanliness

**Blocks:** nothing. **Affects:** residue quality.

The `LiteralBlock` mechanism (ADR 0011, decision D7) handles both delimiter and
fixed-terminator styles and is tested against certificate-shaped input. The Cisco
pack declares only `banner`, because only a banner appears in the development
corpus.

A configuration containing a certificate or key block will therefore have that
body land in residue rather than being recognised as literal content. That is the
safe failure — visible and inspectable rather than silently wrong — but it is
noise in the training queue.

**What would unblock it.** A development-split configuration containing such a
block, from which the declaration can be authored and verified.
