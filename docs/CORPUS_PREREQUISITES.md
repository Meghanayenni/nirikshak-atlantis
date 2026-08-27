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

## 4. An access control list — blocks ACL normalisation

**Blocks:** populating `CanonicalSecurityModel.acls`, and therefore the semantic
ACL analysis at P7 and exposure-aware prioritisation at P12.

**Why it is blocked.** **The corpus contains no ACL at all.** Searching every
development *and* evaluation file for `access-list`, `access-group`, `ip access`,
`firewall`, `filter`, `security-policy`, `policy-map` and `class-map` returns
nothing. The nearest line in the whole corpus is one Juniper statement —

```
set security policies from-zone trust to-zone untrust policy allow-web match source-address any
```

— which carries a source address and no destination, protocol, port or action,
and belongs to a vendor whose pack is still detection-only.

So `CSM.acls` is an empty tuple at P5, and P5 says so rather than shipping ACL
patterns written from general vendor knowledge against zero evidence. That is
precisely what the P4 corpus-provenance test exists to prevent, and it caught five
invented Cisco patterns when it was introduced.

This one is more consequential than it looks. Three of the five capabilities in
the Concept Report's "beyond the base idea" section — semantic ACL analysis,
exposure-aware prioritisation, and a meaningful part of peer-baseline comparison
— rest on structured ACLs. `api/models/acl.py` models them as intervals precisely
so the P7 analysis can be computation rather than pattern matching, and none of
that machinery can be exercised against an empty tuple.

**What would unblock it.** Development-split configurations containing real
access control lists, sanitised to `docs/CONTENT_POLICY.md` and recorded in the
manifest, ideally including:

- a list with **shadowed** entries — a later rule unreachable behind an earlier
  one — since detecting those is the point of interval analysis;
- a list with a **redundant** entry;
- an **overly permissive** entry (`permit ip any any`), which `ACLEntry`
  already has a predicate for;
- at least one list actually **applied** to an interface with a direction, so
  `AclApplication` and exposure reasoning have something to consume.

**What must not happen.** Writing those files ourselves and calling the resulting
analysis validated. A synthetic ACL we authored will contain exactly the shapes we
thought to include, which is the same trap recorded for XML above: the analysis
would be right about a shape we invented and untested against the real thing.

---

## 5. Sourced platform documentation — blocks absence-aware evaluation

**Blocks:** the `AbsenceAction.EVALUATE` branch, and any claim about
absence-aware accuracy.

**This is not the same prerequisite as §2.** §2 asks for more *devices*. This one
asks for *vendor documentation*, and no number of additional configuration files
satisfies it. They are independent, and P6 made the distinction visible.

**Why it is blocked.** Absence-aware evaluation — deciding whether a missing
directive means the platform's documented default or a removal — is the Concept
Report's headline differentiator. It is entirely data-driven, and the data is
`VendorPack.defaults` and `VendorPack.capabilities`, which require typed sourced
provenance (decision D11).

**Zero are populated.** No vendor documentation has been sourced, so:

- every absent field on every corpus device resolves to UNKNOWN ·
  `capability_unknown`;
- no field ever reaches ABSENT_DEFAULT, so the `EVALUATE` branch **never fires on
  real data** — its tests use synthetic packs and say so;
- roughly a quarter of the checks on `corpus/cisco/dev/sw-access-02.cfg` abstain
  for this reason alone.

**The synthetic corpus cannot substitute for it.** A corpus file is a claim about
a device *we wrote*. It is not, and can never be, evidence about what a vendor
documents as its platform's behaviour. A test asserts that no platform claim cites
a corpus path or filename.

**What would unblock it.** For each canonical field, on each platform: a vendor
configuration guide, command reference, hardening guide or release note that
states the default, obtained and read, recorded as `PlatformProvenance` with a
document identifier and a locator into it. Per `docs/CONTENT_POLICY.md` that
records identifiers and locators only — never transcribed vendor prose.

### The sourcing backlog

This is the queue that `capability_unknown` findings belong to, and it is
**deliberately not the administrator training queue**. `Finding.needs_training`
excludes `capability_unknown` on purpose: no amount of administrator training will
teach the system what a vendor documents as a default. Training fixes parsing;
this needs a librarian.

Every field a device abstains on for `capability_unknown` is one backlog item:
*this control is undeterminable on this platform until someone sources the
documentation.* The list is generated by running an audit, not maintained by
hand.

**What must not happen.** Manufacturing defaults from general vendor knowledge to
make the branch reachable, or to make a demo look more complete. An unsourced
default is an unverified security claim that produces a confident PASS, which is
the worst output this system could generate short of bad remediation.

---

## 6. Further literal-block declarations — affects parse cleanliness

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
