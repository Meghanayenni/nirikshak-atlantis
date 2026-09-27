# ADR 0062 — The algorithms a server offers, and who calls them weak

- **Status:** Accepted
- **Date:** 2026-09-27
- **Phase:** P18
- **Decisions:** D152 (the offered SSH algorithms are read as two lists,
  `ssh_ciphers` and `ssh_macs`; `weak_ciphers` is not filled), D153 (a `tokens`
  cast and a `contains_none` operator), D154 (NRK-CIPHER-001 and -002, their
  sources, and their framework answers)
- **Affects:** `packs/builtin/cisco_ios/1.5.0.yaml` (new, active),
  `packs/builtin/cisco_ios/1.4.0.yaml` (deprecated), `rules/canonical/NRK-CIPHER-00{1,2}.yaml`
  (new), `rules/rulepack.yaml` (1.2.0), `api/models/enums.py`,
  `api/parse/casts.py`, `api/parse/fields.py`, `api/comply/conditions.py`,
  `api/models/rule.py`, `api/models/csm.py`, `api/prioritise/exposure.py`,
  `ui/src/components/device/Review.tsx`, `eval/reports/evaluation.txt`

## Context

The problem statement names "enforcing strong cryptographic suites" as a
hardening requirement. `docs/PS26155_COMPLIANCE.md` recorded it as ABSENT:
`weak_ciphers` sat in `CANONICAL_FIELD_NAMES` and nothing read or judged it.

The development corpus has carried the evidence since P15:

| File | Line | Text |
| --- | --- | --- |
| `cisco/dev/edge-rtr-01.cfg` | 44 | `ip ssh server algorithm encryption 3des-cbc aes128-cbc` |
| `cisco/dev/edge-rtr-01.cfg` | 45 | `ip ssh server algorithm mac hmac-md5 hmac-sha1` |
| `cisco/dev/branch-rtr-07.cfg` | 54 | `ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr` |
| `cisco/dev/branch-rtr-07.cfg` | 55 | `ip ssh server algorithm mac hmac-sha2-256` |
| `cisco/dev/dist-sw-03.cfg` | 55 | `ip ssh server algorithm encryption aes128-cbc 3des-cbc` |

## D152 — read what is offered; do not fill `weak_ciphers`

The brief for this change asked for a `weak_ciphers` pattern of type list, and a
rule failing when a weak value is in it. Those two requests pull against each
other. If the pack puts the *offered* algorithms into `weak_ciphers`,
branch-rtr-07's report reads `weak_ciphers: aes256-ctr, aes192-ctr, aes128-ctr` —
three strong ciphers under a label calling them weak, on the device that passes.
If the pack puts only the *weak* ones there, the pack is deciding weakness: a
compliance judgement in vendor syntax, repeated in every pack, and changed by
editing every pack when the policy changes. Rule 1 and Rule 5 put that
judgement in the rule.

So the pack reads what the configuration says — the algorithms the SSH server
offers — and the rule says which are unacceptable. Two fields, not one:

- `ssh_ciphers` from `ip ssh server algorithm encryption …`
- `ssh_macs` from `ip ssh server algorithm mac …`

**Two, because each list can be absent alone.** dist-sw-03 sets encryption and
writes no MAC line, so its MACs are the release default, which nobody has
declared. One combined field would pass a device whose MAC offer was never read
as long as its cipher line was clean — a PASS resting on half the evidence.

`weak_ciphers` stays in `CANONICAL_FIELD_NAMES`, unread, because the evaluation
labels name it. Its name is a verdict; retiring it and migrating the labels is
a separate decision, not taken here.

## D153 — a cast and an operator, both closed-set additions

**`tokens` cast.** `LIST` accumulates one value per matching line. One SSH
directive names several algorithms, so a line must yield several values. The
cast splits the capture on whitespace and interprets nothing; the field builder
flattens tokens in source order, keeping every line's citation. An empty capture
raises rather than producing `[]`, which would claim "offers nothing".

**`contains_none` operator.** The policy is "none of these", over a collection.
The closed set had `contains` (one value) and no negation to build the rest
from, so eight algorithms would have needed eight conditions that cannot be
written. Both operands must be collections, enforced at rule load and again at
evaluation, where a scalar abstains as a rule defect. Membership is exact:
`hmac-sha1` does not match `hmac-sha1-96`. The set is now thirteen operators.

## D154 — two rules, their sources, and their framework answers

| Rule | Field | Fails on | Severity |
| --- | --- | --- | --- |
| NRK-CIPHER-001 | `ssh_ciphers` | `3des-cbc`, `aes128-cbc`, `aes192-cbc`, `aes256-cbc` | medium |
| NRK-CIPHER-002 | `ssh_macs` | `hmac-md5`, `hmac-md5-96`, `hmac-sha1`, `hmac-sha1-96` | medium |

Every source below was obtained and read in this session; none is from memory.

| Claim | Source | Obtained |
| --- | --- | --- |
| CBC SSH methods are vulnerable to chosen-plaintext attacks; CTR methods replace them | RFC 4344 §6.2, https://www.rfc-editor.org/rfc/rfc4344 | plain text via curl |
| The compliant cipher list is aes256-ctr aes192-ctr aes128-ctr | DISA STIG V3R7 CISC-ND-001210, check and fix text | held in `docs/sources/disa/` |
| SHA-1 is compromised for remote-session integrity; compliant MAC hmac-sha2-256 | DISA STIG V3R7 CISC-ND-001200, check text | held in `docs/sources/disa/` |
| MD5 is not an approved hash | FIPS 180-4, announcement §3 (lists SHA-1 through SHA-512/256) | PDF via curl, text inflated locally |
| HMAC-MD5 has no demonstrated practical attack; removal "may not be urgent"; new designs should not use it | RFC 6151 §2.3, https://www.rfc-editor.org/rfc/rfc6151 | plain text via curl |
| Command syntax, algorithm names, and IOS's default encryption list includes the CBC methods | Cisco IOS Security Command Reference: Commands D to L, `ip ssh server algorithm encryption`, https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-i3.html | cisco.com refused curl; read through a rendering fetcher |

RFC 6151 is recorded because it cuts *against* calling HMAC-MD5 broken. The
rule's rationale says so: refusing MD5 and SHA-1 MACs is NIRIKSHAK's policy,
anchored on the STIG and FIPS 180-4, not a report of a broken construction.

**The rules take no position on a device with no algorithm line.** Cisco's
command reference lists the default encryption set, and it includes CBC
methods — but the default varies by release and the page does not bound it, so
no platform default is declared and such a device abstains
(`capability_unknown`). rtr-core-01 and sw-access-02 now abstain on both.

**NIST SP 800-53:** SC-08(01) *Transmission Confidentiality and Integrity |
Cryptographic Protection* and AC-17(02) *Protection of Confidentiality and
Integrity Using Encryption*, both active in the 5.2.0 catalog. The titles were
read from the catalog itself, fetched from the index's `source_url` and matched
to its pinned sha256 (`01f37cf9…`).

**STIG: not mapped**, each with its reason. CISC-ND-001210 asks for FIPS-approved
algorithms; NRK-CIPHER-001 fails FIPS-approved AES-CBC and would pass a non-FIPS
CTR-like method, so it differs in both directions. NRK-CIPHER-002 is looser
than CISC-ND-001200. ADR 0052's rule applies: a check that disagrees with its
control does not print the control's identifier.

**CIS: not mapped, and the reason says nobody looked.** The Benchmark is
referenced and never held, and it was not read for this change. The reason
records exactly that — "unanswered rather than answered no" — which is the
distinction `test_every_rule_answers_every_sourced_framework` exists to force.

**No remediation snippet.** A snippet names the person who checked its commands
against a document. Nobody has, so none ships, and the resolver returns
`NO_SNIPPET`. `test_remediation_resolver.py` now holds an explicit
`UNVETTED_CISCO_RULES` set that must resolve to nothing; it fails, and must be
shrunk, the day a snippet lands.

## What moved

On the development corpus:

| Device | `ssh_ciphers` | `ssh_macs` | CIPHER-001 | CIPHER-002 |
| --- | --- | --- | --- | --- |
| edge-rtr-01 | 3des-cbc, aes128-cbc (l.44) | hmac-md5, hmac-sha1 (l.45) | **FAIL** | **FAIL** |
| branch-rtr-07 | aes256-ctr, aes192-ctr, aes128-ctr (l.54) | hmac-sha2-256 (l.55) | PASS | PASS |
| dist-sw-03 | aes128-cbc, 3des-cbc (l.55) | — | **FAIL** | UNKNOWN |
| rtr-core-01, sw-access-02, … | — | — | UNKNOWN | UNKNOWN |

The rulepack is 1.2.0. Peer baselines for Cisco IOS rise from eight to ten, still
with no outlier. The similarity index gains five seed examples over two fields
(25 over 11). **Evaluation:** field precision, recall and the wrong-confident
rate (0) are unchanged. The new fields carry no labels, so they are not scored;
`weak_ciphers`, which is labelled, is still unread and still abstains.

NX-OS `dc1-leaf-01.cfg` carries the same two lines. The NX-OS pack is not
changed here, so that device abstains on both rules.

**Note, appended 2026-09-27 — NX-OS.** The last paragraph above no longer holds.
`cisco/nxos` 1.1.0 reads the same two lists with the same patterns, authored
from `dc1-leaf-01.cfg` after checking the file: lines 39 and 40 are the IOS
commands verbatim at top level, and line 38 (`ip ssh server algorithm
authentication publickey password`) is a different command neither pattern
reads. dc1-leaf-01 offers aes256-ctr, aes192-ctr and aes128-ctr, and
hmac-sha2-256, so it **PASSes** NRK-CIPHER-001 and NRK-CIPHER-002.
