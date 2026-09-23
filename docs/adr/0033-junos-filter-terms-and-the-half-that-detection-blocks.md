# ADR 0033 — JunOS filter terms, and the half that detection blocks

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D85 (a dialect owns the extraction *shape*, not only the entry
  grammar), D86 (resolve a prefix list the configuration defines), D87 (the
  brace-nested form is not authored, because nothing could exercise it)
- **Affects:** `api/models/enums.py`, `api/models/pack.py`,
  `api/parse/structures.py`, `packs/builtin/juniper_junos/1.1.0.yaml` (new),
  `packs/builtin/juniper_junos/1.0.0.yaml` (deprecated, re-stamped)

## Context

ADR 0029's tally named JunOS filter terms as the next dialect to write, by
volume of material already sitting in the corpus: 26 ACL lines across three
files against the Arista/NX-OS CIDR form's seven. That ordering was a
measurement, and this is the work it pointed at.

Juniper had **no parsing patterns of any kind**. This is the first thing the
platform reads.

## D85 — a dialect is a shape plus a grammar, not only a grammar

ADR 0027 (D74) said a pack declares *where* things are and the named `dialect`
reads the entries. That was true of IOS and insufficient in general, and the
insufficiency is structural rather than incidental.

An IOS list is a block whose children are one-line entries. A JunOS filter in
flat `set` form is **neither**:

```
set firewall family inet filter PROTECT-RE term allow-mgmt-ssh from protocol tcp
set firewall family inet filter PROTECT-RE term allow-mgmt-ssh from destination-port ssh
set firewall family inet filter PROTECT-RE term allow-mgmt-ssh then accept
```

There is no block for `named_block` to open, no child list to walk, and one
entry spans several independent top-level lines. A seam that varied only the
entry parser could not read it at all.

So `_LIST_READERS` dispatches on the dialect, and `_extract_ios_lists` is the
previous body moved behind that table with its behaviour unchanged. What stays
common is what is common: the all-or-nothing rule, the failure record, and
binding resolution — *where a list is used* is the same question on every
platform, and a reader that answered it would answer it once per dialect.

The reader groups lines by `(filter, term)` in **first-appearance order**,
because that is the order JunOS evaluates terms in and order is the whole of
shadowing analysis. Sorting by name, or relying on whatever order a mapping
happened to produce, would be wrong invisibly.

### What stayed in data, and what did not

`named_block` is `^set firewall family inet filter (\S+) ` — the path prefix up
to and including the filter name. `family inet` is a configuration detail an
operator can legitimately differ on (`inet6`, `ethernet-switching`), so it
belongs in the pack. The `term … from/then …` tail is the filter grammar and
belongs in the reader, exactly as wildcard-mask arithmetic does for IOS.

`applied` became **optional** and is null here. A filter's binding is read off an
interface, and this pack declares no interface extraction, so there is nothing
for a binding regex to be matched against. Declaring one anyway would put a
regex in a pack that nothing runs, which is how DEF-12 happened.
`set interfaces lo0 unit 0 family inet filter input PROTECT-RE` therefore stays
in residue and `PROTECT-RE.applied_to` is empty — an absent binding rather than
a guessed one.

## D86 — resolve a prefix list the configuration defines

`from source-prefix-list TRUSTED-MGMT` resolves through
`set policy-options prefix-list TRUSTED-MGMT 198.51.100.0/24` in the same file.

The IOS reader leaves an `object-group` unresolved, and this looks like a
departure. It is not: no Cisco corpus file *defines* an object group, so there
was never anything to resolve. Here the definition is present, and the
difference matters concretely — `address_covers` returns `None` for an address
with no resolved CIDRs, and the analyser then reports UNDETERMINED instead of
comparing. Leaving the prefix list unresolved would have discarded information
the operator plainly gave, and turned the one real finding in this file into an
abstention.

A prefix list referenced and never defined stays unresolved. That is the honest
outcome and the one the `object-group` case already produces.

## D87 — the brace-nested form is not authored here

The brief for this work expected both dialects, and expected a **shadowed**
result from `corpus/juniper/dev/core-rtr-01.conf`, whose
`term allow-anything { then accept; }` sits above two later terms.

**That file cannot enter the pipeline.** Vendor detection does not identify it:

```
core-rtr-01.conf   below_threshold   best candidate cisco/ios 0.25
```

The juniper signatures all match `^set …`, so a brace-nested JunOS file matches
none of them. ADR 0024 recorded this and deferred it to the NX-OS pack work,
where discriminating signatures are the central difficulty. The blocker is
**upstream of extraction**: a brace-form reader could be written today and
nothing would ever call it.

Writing one anyway would be authoring a declaration no test could show right or
wrong on real data — precisely what D73 declined to do for `snmp_v3_only`. So
the dialect is named `junos_set_filter` for the form it reads rather than
`junos_filter` for the vendor, and
`test_the_brace_nested_form_is_still_unreachable` pins the blocker. **That test
is expected to fail** when somebody adds brace-form signatures, which is exactly
when the second reader becomes worth writing.

## What P7 now yields on JunOS

`corpus/juniper/dev/edge-rtr-02.conf`, filter `PROTECT-RE`, four terms:

| Term | Entry | Observation |
| --- | --- | --- |
| `allow-mgmt-ssh` | permit tcp TRUSTED-MGMT → any:22 | — |
| `allow-mgmt-https` | permit tcp TRUSTED-MGMT → any:443 | — |
| `allow-mgmt-https-dup` | permit tcp TRUSTED-MGMT → any:443 | **redundant**, caused by term 2 |
| `log-and-deny` | deny any any, logged | — |

The expected redundancy appears, and nothing else does. The final
`log-and-deny` matches every packet and is **not** flagged overly permissive,
which is right: a *deny* catch-all at the bottom is what a filter is supposed to
end with, and flagging it would be pattern-matching for alarm.

Residue on `edge-rtr-02.conf` falls **79 → 63**: the fifteen term lines and the
prefix-list definition they resolve through all leave the training queue. The
interface binding does not, and says so.

The corpus-wide tally, updating ADR 0029:

```
4 access lists analysed, 0 dropped   (was 3 analysed, 0 dropped)
```

### What is still in residue, and why

| File | Line | Why |
| --- | --- | --- |
| `edge-rtr-02.conf` | `set interfaces lo0 … filter input PROTECT-RE` | no interface extraction for JunOS |
| `core-rtr-01.conf` | 8 lines | not detected as JunOS at all (D87) |
| `srx-edge-01.conf` | `set security policies from-zone … match source-address any` | a zone policy, not a filter — a third grammar |
| `dc1-spine-01.cfg` | 7 lines | Arista declares no extraction |

The `srx-edge-01.conf` line is worth separating from the rest. It was counted
among the "26 ACL lines" and it is not a firewall filter: JunOS security
policies are a zone-based construct with their own match/then grammar, and a
single orphan line of one is not enough to author a reader from.

## The 1.0.0 re-stamp

`juniper/junos` ships as 1.1.0 with 1.0.0 deprecated and re-stamped. The diff on
1.0.0 is two lines — `status` and `checksum` — and **no parsing content
changed**: not a pattern, not a detect signature, not an identity rule. One
stored audit run cites `juniper 1.0.0` and would parse its configuration
identically today.

This is the D80 situation exactly, and the same distinction applies: byte-level
identity with the file that ran is broken, parse-behaviour reproducibility is
intact, and a checksum cannot tell those two apart. Leaving 1.0.0 active beside
1.1.0 was not an option — `active_packs()` raises on two active versions of one
platform, deliberately (D46).

`eval/reports/evaluation.txt` regenerates with one line changed —
`juniper/junos 1.0.0` becomes `1.1.0`. No measured figure moved, because the
harness scores canonical fields and JunOS still has none: `patterns` is empty in
1.1.0 and Juniper recall stays 0. **This version reads structure, not facts**,
and the pack says so at the top of the file.
