# ADR 0055 — A sanitisation gate that fails closed

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D139 (every configuration line mentioning `community` must be
  read by a known form, or the gate fails), D140 (the hash placeholder
  convention is the rule, not an accident of a quantifier)
- **Affects:** `tests/integration/test_corpus_policy.py`, `docs/CONTENT_POLICY.md`

## Context — was the last session's finding resolved?

**Half.** ADR 0050 (D129) found that D66's SNMP gate matched only IOS's
`snmp-server community NAME`, so a JunOS file kept a non-default community
because JunOS nests `community NAME {` inside an `snmp` block. It added a second
pattern for that shape and rewrote the file. The *file* was fixed. The *gate*
was still a list of vendor shapes, and a shape nobody listed still passed:

| Form | Vendor | Before this ADR |
| --- | --- | --- |
| `snmp-server community NAME …` | IOS, IOS XE, NX-OS, EOS | caught |
| `community NAME {` | JunOS, brace form | caught (ADR 0050) |
| `community NAME;` | JunOS, brace form with no clauses | **passed** |
| `set snmp community NAME …` | JunOS, flat form — the surface four of the five JunOS corpus files use, though none configures a community today | **passed** |
| anything else | any | **passed** |

D129 said a sanitisation pattern must not be vendor-shaped, and then shipped a
second vendor-shaped pattern. The reasoning was right; the mechanism still had
the property the reasoning condemned: *a check that cannot read a line reports
it clean.*

## D139 — read every community line, or fail

The question is turned round. `community_problems` visits every line that
mentions `community`:

- if one of three **forms** reads it — the IOS-family `snmp-server community`,
  JunOS `set snmp community`, JunOS `community NAME {|;` — the name must be
  `public` or `private`, in configuration *and* in comments, because a secret in
  a comment is still in the repository;
- if **no form reads it** and it is a configuration line that is not a comment,
  it **fails**, with a message telling the next author to teach the gate the
  form.

That last rule means the gate now rejects things that are not secrets — a BGP
`set policy-options community TRANSIT members …` fails today. That is the
intended cost: the gate cannot tell a BGP community from an SNMP one it has not
been taught, and a gate that cannot tell must not pass. When a corpus file needs
a BGP community, its form is added as a named not-a-credential case, which is a
decision somebody makes in a diff rather than a gap somebody finds later.

Label files are YAML whose prose discusses "community strings" in English. They
are held to the first rule (no readable form may name a secret) and not the
second, because a sentence is not a configuration form. The truth table is a
test: thirteen lines across four vendors, including the two unread forms.

## D140 — the placeholder convention is the rule

Checking the neighbouring patterns for the same blind spot found one. The gate
knew Cisco type 5 (`secret 5 $1$`) and `$6$…`. It did not know Cisco **type 8**
or **type 9** — and type 9 is the form eight lines of the Cisco corpus itself use
(`secret 9 $9$SAMPLE$…`), so the gate did not speak the dialect its own files are
written in. `$9$` is also JunOS's *reversible* encoding. And the `$6$` pattern admitted the corpus's own
`$6$SAMPLE$…` placeholders only because `SAMPLE` is six characters and the
pattern wanted eight: an accident doing the work of a rule.

Every hash-shaped value in the corpus is `$N$SAMPLE$…` (checked: sixteen
occurrences, types 5, 6 and 9). That convention is now stated and enforced:
**any crypt-style value (`$1$ $5$ $6$ $8$ $9$`) whose salt is not the literal
`SAMPLE` is a credential.** The older patterns stay; they are stricter where
they apply.

## What changed on the corpus

Nothing. Every file passes: the communities present are all `public` or
`private`, and every hash is a placeholder. The gate's *behaviour* on the
corpus is unchanged; its behaviour on the next file is not.

## Not done

This is still a pattern gate. A secret with no recognisable shape — a
plain-text `key` on a TACACS line in a vendor nobody taught it — is not caught
by any of this. The only complete answer is a person reading each file for
secrets before it is registered; nothing in this repository requires that
today (`CORPUS_PREREQUISITES.md` asks for a second reviewer of *labels*, which
is a different check), and it is recorded here rather than invented as a
process.
