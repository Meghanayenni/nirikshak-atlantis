# Sourcing backlog

**Five gaps that cannot be closed by writing code.** Each is blocking a capability
the Concept Report promises, each needs material obtained from outside this
repository, and none may be closed by inventing data.

This document exists because three consecutive phases have now shipped correct,
well-tested machinery that produces nothing observable — an absence engine with
no platform defaults (P5), a compliance engine with no framework mappings (P6),
and an ACL analyser with no ACLs (P7). Every one of those refusals was right. The
cumulative effect is still a gap between what the system can do and what it can be
*shown* doing, and closing it is a sourcing task, not an engineering one.

**Nothing here is assigned.** That is the point of writing it down.

---

## 1. ACL-bearing configurations

**Blocks:** ACL extraction, and therefore anything the analyser could say about a
real device. Also blocks exposure-aware prioritisation at P12, which needs ACLs
*and* interfaces.

**State.** The corpus contains **zero** access lists in any split — verified by
searching every file for `access-list`, `access-group`, `ip access`, `firewall`,
`filter`, `security-policy`, `policy-map` and `class-map`. The nearest line is one
Juniper `set security policies …` statement with no destination, protocol, port or
action, on a vendor whose pack is detection-only.

The P7 analyser is built and exhaustively tested against constructed `ACL`
objects. It has never seen a parsed one.

**What would close it.** Development-split configurations containing real access
lists, sanitised to `docs/CONTENT_POLICY.md`, ideally including a shadowed entry,
a redundant entry, an overly permissive entry, a partial overlap that is none of
those, a clean list, one list applied to an interface with a direction, and one
object-group reference.

**What must not happen.** Writing ACL parsing patterns from general vendor
knowledge. The P4 corpus-provenance test would reject them, and it should.

---

## 2. Vendor capability and default documentation

**Blocks:** absence-aware evaluation — the Concept Report's headline
differentiator.

**State.** **Zero** platform defaults and **zero** capability claims ship, across
all four packs. Every absent field on every corpus device therefore resolves to
`UNKNOWN / capability_unknown`, and the `AbsenceAction.EVALUATE` branch **never
fires on real data**. Roughly a quarter of the checks on
`corpus/cisco/dev/sw-access-02.cfg` abstain for this reason alone.

This is the backlog that `capability_unknown` findings belong to, and it is
**deliberately not the administrator training queue**. `Finding.needs_training`
excludes it on purpose: no amount of administrator training will teach the system
what a vendor documents as a default. Training fixes parsing; this needs a
librarian.

**What would close it.** For one platform, one field at a time: a vendor
configuration guide, command reference, hardening guide or release note stating
the default — obtained and read — recorded as `PlatformProvenance` with a document
identifier and a locator into it. Per `CONTENT_POLICY.md` that is identifiers and
locators only, never transcribed vendor prose.

**Smallest useful step.** Two sourced defaults on one platform would make the
branch fire on real data for the first time. This is the highest value-per-hour
item on the list.

**What must not happen.** Manufacturing a default from general knowledge, or
citing a corpus file. A corpus file is a claim about a device *we wrote* and can
never be evidence about a vendor's documented behaviour — a test asserts that no
platform claim cites a corpus path.

---

## 3. XML samples that do not compromise the PAN-OS holdout

**Blocks:** `SyntaxMode.XML` and the `xpath` match primitive.

**State.** The only XML in the corpus is `corpus/holdout/panos/`, and PAN-OS is
the held-out vendor for the P9 generalisation experiment. `build_tree(..., mode=XML)`
raises rather than returning an empty tree.

**What would close it.** A legitimately sourced XML configuration **independent of
the holdout** — a different vendor, or a genuinely different device — sanitised,
recorded in the manifest with honest provenance, and assigned to `dev` if patterns
are to be authored from it.

**What must not happen.** Reading the holdout to build a parser. That destroys the
experiment the holdout exists for: top-3 accuracy on files we have already studied
measures memory, not generalisation. Nor is a self-authored XML fixture
sufficient — a parser built for a shape we invented is wrong in exactly the ways
only the real thing reveals.

---

## 4. Framework control-ID sources

**Blocks:** any claim of CIS, NIST SP 800-53, DISA STIG or ISO/IEC 27001 coverage.

**State.** Every rule ships `frameworks: []`. NIRIKSHAK evaluates its own seven
checks and maps them to nothing.

This is the most visible gap against the problem statement, which asks explicitly
for evaluation against user-selected benchmarks. It is also the one most tempting
to close by writing plausible-looking identifiers, which is why the empty state is
asserted by a test written to fail when the first mapping appears.

**What would close it.** A benchmark edition obtained and read, so a mapping can
name a control **and its source document**. `FrameworkRef` already carries
`version`, `citation` and `mapping_provenance` for exactly this.

**What must not happen.** Writing `CIS-1.2.3` or `AC-17(2)` from memory. Using
`project_asserted` provenance to make the product appear to have coverage is
specifically excluded (D16). Until a source exists, **no document, report or
presentation may claim coverage against any of the four frameworks.**

---

## 5. Broader vendor and configuration diversity

**Blocks:** compliance-rule validation, and any P9 accuracy claim beyond the
narrowest.

**State.** Two Cisco development devices, eight canonical fields, seven rules. That
is enough to validate the *evaluator* — the two files disagree, so PASS, FAIL and
UNKNOWN all arise from real data. It is **not** enough to validate a *rule*: a
check that passes on two devices from one vendor has been tested against a sample
too small to say anything about the check.

Arista and Juniper packs remain detection-only, so their devices produce a valid
canonical model with zero fields and full residue.

**What would close it.** More Cisco devices with genuine variation rather than
near-copies; at least one further vendor with a real parsing pack; and devices
that legitimately **lack** controls, so absence-aware evaluation has something real
to reason about.

**What must not happen.** Growing the corpus by templating the two existing files.
Near-identical devices inflate the file count without adding evidence, and they
make the fleet-cache and peer-baseline numbers look better than the data supports.

---

## What P9 may claim today

Written here so the evaluation report inherits it rather than re-deriving it:

- **May** state per-field precision and recall for the eight parsed Cisco fields.
- **May** state that the compliance evaluator, the ACL analyser and the abstention
  rules are correct on the cases tested, naming which were corpus-derived and
  which were constructed.
- **May not** claim absence-aware evaluation accuracy — the branch never fires on
  real data.
- **May not** claim ACL detection rates — no real access list has been seen.
- **May not** claim coverage against CIS, NIST, DISA STIG or ISO/IEC 27001.
- **May not** claim universal vendor coverage, or present any result from the
  synthetic corpus as real-world accuracy.
