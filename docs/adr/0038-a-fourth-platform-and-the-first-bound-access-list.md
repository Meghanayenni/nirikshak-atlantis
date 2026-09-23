# ADR 0038 — A fourth platform, and the first bound access list

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D100 (`pack_versions` is keyed by pack id, not by vendor),
  D101 (NX-OS names its own ACL dialect rather than loosening the IOS one),
  D102 (`duration_minutes` is a new cast, not a looser `duration`)
- **Affects:** `packs/builtin/cisco_nxos/1.0.0.yaml` (new),
  `api/models/enums.py`, `api/parse/casts.py`, `api/parse/structures.py`,
  `api/normalise/service.py`

## Context

`corpus/cisco/dev/dc1-leaf-01.cfg` scored **0.25** against `cisco/ios`, below
the 0.60 detection floor. Correct abstention, and a device nobody could reach:
skipped by the peer baselines, invisible to the analyser, unauditable. Its own
header calls it the corpus's *"good device"* fixture.

## D100 — key provenance by pack id, and do it first

`CsmSource.pack_versions` was built as `{r.vendor: r.pack_version}`.

One vendor with two platforms breaks that, and `cisco/ios 1.0.0` already exists.
A stored finding citing `{"cisco": "1.0.0"}` would be ambiguous between two real
packs, permanently, with nothing able to recover which. The version field exists
so a verdict can name the data that produced it; a key that cannot tell two
packs apart does not do that.

Keyed by `vendor/os_family` now. This was noticed during the ADR 0031 archive
audit and recorded there as belonging to the same repair — it had to land
*before* a second Cisco platform could, not after.

**It also caught four test fixtures** selecting a pack with
`p.vendor == "cisco"`. The moment `cisco/nxos` existed, the Cisco IOS suites
began running against whichever pack sorted first, and the NX-OS pack sorts
first. They select on `(vendor, os_family)` now.

## Detection, which is the whole difficulty

NX-OS and IOS share most of their vocabulary. A pack that merely *scored* on
this file would trip the `min_margin` ambiguity rule and leave the device
unauditable a second way. Every signature is a construct classic IOS does not
write at all:

| Signature | Why IOS never matches it |
| --- | --- |
| `^(no )?feature \S+$` | IOS has no feature gating |
| `^vrf context \S+$` | IOS writes `ip vrf` / `vrf definition` |
| `^line vty$` | IOS always writes a range: `line vty 0 4` |
| `^logging server \S+` | IOS writes `logging host` |

Measured over every non-holdout corpus file:

```
dc1-leaf-01.cfg   detected   cisco/nxos 1.10   runner-up cisco/ios 0.25
```

A margin of 0.85 against a floor of 0.25, and **no other file's detection moved
at all**. The reverse direction is tested explicitly, because it is the one that
would do damage quietly: an NX-OS signature that also matched IOS would not fail
here — it would start pulling IOS devices towards a pack where every pattern
misses and every field reads UNKNOWN.

## D101 — a dialect for CIDR entries, not a looser IOS parser

`10 permit tcp 198.51.100.0/24 any eq 22` is the IOS entry *shape* with a prefix
length where a wildcard mask goes. So `nxos_cidr` shares `_extract_ios_lists`
and `_parse_entry`, injecting only how an address is consumed.

Loosening `_take_address` to accept both was rejected. It would also accept
`permit ip 10.0.0.0 0.0.0.255/24` — a line no device writes, parsed confidently
into an interval nobody meant. Two spellings of one range, read by different
arithmetic, are two dialects.

### The failure this produced, and the test it earned

`nxos_cidr` shipped in `_DIALECTS` and **not** in `_LIST_READERS`. The result:
`extract_acls` returned two empty tuples — identical to a device that filters
nothing. No error, no dropped-list diagnostic, no residue signal. The pack
declared extraction and the list simply was not there.

That is exactly the failure ADR 0029 built `AclExtractionFailure` to prevent,
arriving one layer above where that record is emitted.
`test_every_dialect_has_a_reader` asserts the two tables agree.

## D102 — `duration_minutes`, because ten is not ten

NX-OS writes `exec-timeout 10`; IOS writes `exec-timeout 10 0`. `cast_duration`
reads a single token as *seconds*, which is right for a platform writing
`exec-timeout 600` and wrong by a factor of sixty here.

Its own docstring anticipated this: *"A platform expressing durations some third
way needs a new cast rather than a looser one here."* So the second form gets a
second cast.

**The unit is a parsing convention, not a sourced claim**, and that is worth
saying rather than leaving implicit. Nothing in this repository documents how
any platform writes a timeout — the IOS minutes-and-seconds reading has the same
standing and has shipped unsourced since P4. Both are `SOURCING_BACKLOG` gap 2.
On this device nothing rests on it: 10 seconds and 600 seconds both satisfy
`gt 0 and lte 600`, so the verdict is identical either way.

## What the device now produces

Seven canonical fields, six PASS and one honest abstention:

| Field | Value | Read from |
| --- | --- | --- |
| `telnet_enabled` | `False` | `no feature telnet` |
| `http_server_enabled` | `False` | `no ip http server` |
| `idle_timeout_seconds` | `600` | `exec-timeout 10`, scoped to `line vty` |
| `logging_hosts` | one | `logging server …` |
| `ntp_servers` | two | `ntp server …` |
| `banner_present` | `True` | `banner motd #` |
| `aaa_enabled` | `True` | `aaa authentication login default …` |
| `ssh_version` | **UNKNOWN** | nothing — see below |

`telnet_enabled` is the first shipped pack to assert a literal from a line that
captures no value: NX-OS gates the *service* (`no feature telnet`) where IOS
gates the *transport* on a line. That is the mechanism D69 exposed in the
training form, now used by a builtin pack.

`NRK-SSH-001` abstains with `no_match` on an otherwise well-hardened device.
NX-OS has no `ip ssh version` command, and mapping `feature ssh` to version 2
would be a claim about what the platform supports with no document behind it.
The honest outcome rather than the convenient one.

### The first access list that knows where it is applied

```
MGMT-IN, 3 entries, applied_to=[('mgmt0', 'in')]
  1. permit tcp 198.51.100.0/24 -> any:22
  2. permit tcp 198.51.100.0/24 -> any:443
  3. deny   ip  any -> any, logged
```

Every list before this one — Cisco and JunOS alike — had an empty `applied_to`,
because no development file bound one to an interface. The Cisco pack's
`applied` regex has been declared and unexercised since ADR 0027 and said so.
**It is exercised now**, and the binding is read off the interface rather than
guessed from the list's name.

The analyser reports **nothing** on it, which is the correct result: two
specific permits above a catch-all deny is what a filter is supposed to look
like.

`mgmt0` is still `is_management=None`. The name is a convention and nothing here
documents it, so ADR 0034 applies unchanged and the exposure ranking keeps
abstaining. The interface, its address and its bound list are all read; only the
role is missing.

## Measurements that moved, and were re-pinned rather than loosened

- **Fleet**: 17 devices → **18**, skipped 2 → **1**. Only `core-rtr-01.conf`
  (brace-nested JunOS) is still unreachable.
- **Cohorts**: `cisco/nxos` is its own cohort of **one**, far below the floor of
  five, so it establishes nothing. Pooling it into `cisco/ios` would compare an
  NX-OS leaf against nine IOS routers and call the difference a deviation.
- **Seed index**: 11 entries over 8 fields → **19 over 9**, now spanning two
  *platforms*. Still one vendor, and still far too small to support any claim
  about retrieval — `SOURCING_BACKLOG` gap 8 is unchanged.

**`eval/reports/evaluation.txt` did not move at all.** `dc1-leaf-01.cfg` is a
development file, so the harness scores nothing about NX-OS: there is no
evaluation-split NX-OS configuration and no ground-truth label for one. A fourth
platform is parsed and **unmeasured**, and keeping that distinction visible is
why the harness reports per vendor and never pools (D34).
