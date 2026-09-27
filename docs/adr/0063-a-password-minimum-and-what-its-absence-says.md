# ADR 0063 — A password minimum, and what its absence does not say

- **Status:** Accepted
- **Date:** 2026-09-27
- **Phase:** P18
- **Decisions:** D155 (Cisco IOS reads `security passwords min-length`), D156
  (NRK-PASSWD-001 requires at least 15, from two sources), D157 (an absent line
  abstains; it is not a FAIL)
- **Affects:** `packs/builtin/cisco_ios/1.6.0.yaml` (new, active),
  `packs/builtin/cisco_ios/1.5.0.yaml` (deprecated),
  `rules/canonical/NRK-PASSWD-001.yaml` (new), `rules/rulepack.yaml` (1.3.0)

## Context

The problem statement's own example of syntactic diversity is "a secure password
setting in a Cisco IOS switch" against the same setting on a Juniper SRX.
`min_password_length` has been a canonical field since P1 and nothing read it.
One development file has carried the line since P15:
`corpus/cisco/dev/branch-rtr-07.cfg:39  security passwords min-length 12`.

## D155 — the pattern

```yaml
- id: p-min-password-length-001
  field: min_password_length
  scope: { block: null }
  match:   { type: regex, pattern: '^security passwords min-length (\d+)$' }
  capture: { value: '$1', cast: int }
  examples: ['security passwords min-length 12']
```

Top level, exact line, integer. Authored from branch-rtr-07 only; no evaluation
file was opened.

## D156 — fifteen, and why the brief's expected PASS does not happen

The brief expected branch-rtr-07 (12) to PASS "above threshold" without naming
the threshold. Two sources were read for one, and both say 15:

| Source | Says | Obtained |
| --- | --- | --- |
| NIST SP 800-63B-4 §3.1.1.2 *Password Verifiers* (https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver) | passwords used as a single authentication factor SHALL be at least 15 characters; 8 only when used solely inside multi-factor | HTML via curl; the document's own change log names §3.1.1.2 as where the minimum was raised |
| DISA Cisco IOS XE Router NDM STIG V3R7, CISC-ND-000550 | a 15-character minimum is required | held in `docs/sources/disa/` |

A device's local passwords — enable secret, local users, line passwords — are a
single factor and the fallback when AAA is down. So the threshold is 15, and
**branch-rtr-07 FAILs**. No source for 12, or for anything between 8 and 15, was
found; writing one would be the number from memory this repository refuses.
The threshold is data: `{ op: gte, value: 15 }`.

Cisco's own command reference (*Security Command Reference: Commands S to Z*,
`security passwords min-length`) was read too. It recommends no length. It is
cited for the command's syntax and its stated default.

**NIST SP 800-53:** IA-05(01) *Authenticator Management | Password-based
Authentication*, active in 5.2.0, title read from the pinned catalog.
**STIG: not mapped.** CISC-ND-000550 asks for the same 15, but its check reads
`min-length` inside an `aaa common-criteria policy`, a different command. A
device meeting the STIG that way is UNKNOWN here, and one meeting this rule is
still a finding there. **CIS: not mapped, not read** — as in ADR 0062.
**No snippet** — nobody has vetted one; the resolver test's
`UNVETTED_CISCO_RULES` now names this rule too.

## D157 — an absent line abstains

The brief framed the choice: FAIL when below a threshold, when the line is
absent, or both — noting that absence here means "policy not enforced", which
differs from `ip http server`, where the absent line may mean the server is on.
Only the first is taken. **An absent line is UNKNOWN**, for two reasons that
each suffice:

1. **The vendor's own page does not settle the default.** Its *Command Default*
   says "The command is not enabled." Its *Syntax Description* for `length` says
   "The default is six characters." Those can be reconciled — six may be the
   argument's default when the command is given — but reconciling them is
   interpretation, and a FAIL resting on an interpretation of an ambiguous
   vendor page is the guess Rule 3 forbids.
2. **This line is not the only way to set a minimum.** The STIG's own check sets
   one inside `aaa common-criteria policy`, which this pack does not read. The
   absence of `security passwords min-length` therefore does not establish that
   the device enforces no minimum — only that it does not enforce one *this
   way*. Absence-aware evaluation (DEVELOPER_GUIDE.md §7) exists for exactly this: a
   missing directive is not automatically a FAIL.

So the brief's premise — absent means not enforced — is true of the command and
not of the device, and the field is about the device. Mechanically nothing new
is needed: no `PlatformDefault` or `PlatformCapability` is declared for
`min_password_length`, so an absent line resolves to `capability_unknown`, and
`test_password_policy.py` pins that no default is declared and that three
development devices without the line abstain with no evidence.

The contrast with `ip http server` stands, in the other direction: there, the
absent line might hide an *enabled* listener, so the right answer is also to
abstain until a sourced default says otherwise.

When a FAIL on absence would be right: once the common-criteria policy is read
too, and a vendor document states unambiguously what minimum applies when
neither is set. Then it is a sourced `PlatformDefault`, not a rule change.

## What moved

| Device | `min_password_length` | NRK-PASSWD-001 |
| --- | --- | --- |
| branch-rtr-07 | 12 (line 39) | **FAIL** |
| every other Cisco IOS development device | — | UNKNOWN (`capability_unknown`) |

Rulepack 1.3.0, ten rules. Cisco IOS peer baselines: eleven, no outlier. The
similarity index gains one seed (26 over 12 fields). Evaluation: unchanged —
every evaluation label for `min_password_length` is *not determinable* under the
label doctrine ("a missing password policy … is a question about what the
platform does by default"), and no evaluation file carries the line, so nothing
new is scored and wrong-confident stays 0.

The JunOS half of the problem statement's example is still undemonstrable: no
JunOS development file sets a password policy, so there is no line to author a
pattern from.
