# ADR 0037 — A model read from a line a device writes

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D97 (read the Arista model from the header EOS emits), D98
  (remove the Cisco model pattern — its only evidence is an annotation), D99 (no
  serial pattern, because no configuration export carries one)
- **Affects:** `packs/builtin/arista_eos/1.1.0.yaml` (new),
  `packs/builtin/cisco_ios/1.3.0.yaml` (new), `api/parse/block_parser.py`,
  `docs/data-contracts.md`

## Context

Problem Statement 26155 names serial numbers and hardware details among the
report deliverables. `DeviceIdentity` has carried `model` and `serial` since P3;
the database column, the evidence plumbing and the report field all exist.

What they were resting on turned out to be worth checking.

## D97 — Arista writes its model, so read it

EOS puts this at the top of every `show running-config`:

```
! device: sw-leaf-01 (DCS-7050SX3-48YC8, EOS-4.29.2F)
```

The pack already read `os_version` from it. It now reads `model` from the same
line, and both resolve on all four Arista corpus files:

| File | model | os_version |
| --- | --- | --- |
| `sw-leaf-01.cfg` | `DCS-7050SX3-48YC8` | `4.29.2F` |
| `sw-spine-01.cfg` | `DCS-7280CR3-32P4` | `4.30.1F` |
| `dc1-spine-01.cfg` | `vEOS` | `4.31.2F` |
| `sw-leaf-07.cfg` (eval) | `DCS-7050SX3-48YC8` | `4.29.4M` |

It is a **comment**, and reading it is the behaviour ADR 0011 designed for:
identity extraction runs over the raw line list rather than the tree, because
*"metadata legitimately lives in comments; active security configuration never
does."* This line is the clearest case of that asymmetry being right. The device
emits it, and no canonical security field is read from it.

## D98 — remove the Cisco model pattern

`cisco/ios` read the model from `^! model (\S+)` since P4. The only line
anywhere matching it:

```
corpus/cisco/dev/rtr-core-01.cfg:6:! model ISR4331
```

**Cisco's `show running-config` does not emit the hardware model.** It is in
`show version` and `show inventory`. That line is an annotation a corpus author
wrote so the field would populate — and NIRIKSHAK reported it as observed device
identity, with a citation, through the one path deliberately left open to
comments.

This is not a defect in ADR 0011's asymmetry; it is the asymmetry pointed at the
wrong line. Compare the two:

| | `! device: …` (Arista) | `! model …` (Cisco) |
| --- | --- | --- |
| Written by | the device | a person |
| Appears in | every Arista file, dev and eval | one file |
| Real platform output | yes | no |

Nothing in the repository can tell those apart automatically. "Does this
platform emit this line" is vendor documentation — `SOURCING_BACKLOG` gap 2, in
yet another place. The corpus-policy suite already requires a pattern example to
be a line somebody read in a development file, and `! model ISR4331` satisfies
that, because somebody *did* read it. The test cannot ask whether a device
wrote it.

Removed rather than kept behind a flag. A field resolving on exactly one
synthetic file and no real one is worse than an absent field: it looks
supported. DEVELOPER_GUIDE.md §3 names this directly — *"a field that is present in the
schema but never matches looks supported while producing UNKNOWN forever."*

Cisco `model` is now `None` on all nine Cisco corpus files. `None` and an
UNKNOWN field are kept apart, and the tests assert both: Arista with its header
stripped gives a field the pack *looked at and could not answer*, while Cisco
gives **no field at all**, because the pack no longer attempts one. The second
is a weaker statement than the first and the contract does not flatten them.

The annotation stays in `rtr-core-01.cfg`. It is inert now — nothing reads it —
and editing a registered corpus file to tidy up after a pack would change the
file's hash for no measurement's benefit.

## D99 — no serial pattern, because nothing carries a serial

Measured across every non-holdout corpus file on all three parsed platforms:
**zero** carry a serial number.

That is not a gap in the packs. A serial is inventory data that appears in
`show version` and `show inventory`, not in a configuration export — the same
reason the model is absent from IOS. Declaring a pattern would put a regex in a
pack that no device could satisfy.

So `DeviceIdentity.serial` stays UNKNOWN, and the reason is recorded as a test
rather than as a sentence: `test_no_corpus_configuration_carries_a_serial`
fails the moment a corpus file *does* carry one, which is the point at which the
pattern becomes worth writing.
`test_no_pack_declares_a_serial_pattern` is written to be deleted by whoever
obtains such an export together with the documentation saying the platform emits
it.

**This is one of the PS deliverables not being delivered, and it is being said
plainly.** A report will name a device's hostname, OS version and — on Arista —
its hardware model. It will not name a serial, on any platform, and the
machinery for it is complete and idle.

## The archive reserved a version number, and the test caught it

`arista/eos` ships as **1.1.0**, not 1.0.2.

The first attempt used 1.0.2, and `test_discovery_returns_no_archived_version`
from ADR 0031 failed immediately: `packs/archive/arista_eos/1.0.2.yaml` already
exists — a *trained* pack removed at P15 and recovered two commits ago.

Two different packs sharing one `(platform, version)` would make
`audit_run.pack_versions` permanently ambiguous: a stored finding citing
`arista 1.0.2` could mean either, and no amount of later care would recover
which. **The archive is not only insurance; it reserves the version numbers it
holds**, and that property was found by a test written for a different reason
three commits earlier.

The training-loop fixtures were repointed from 1.0.1 to 1.1.0 for the same
reason: drafting from the deprecated pack produced 1.0.2, teaching the loop to
mint a number the archive owns.

## Consequences

`cisco/ios` ships as 1.3.0 and `arista/eos` as 1.1.0, with 1.2.0 and 1.0.1
deprecated and re-stamped. The re-stamps change `status` and `checksum` only, no
parsing content — the D80 trade again, and `arista/eos 1.0.1` is cited by two
stored audit runs that would parse identically today.

`eval/reports/evaluation.txt` regenerates with the two version strings changed
and **no measured figure moved**. Identity is not among the canonical fields the
harness scores, so adding a model and removing a model changed no precision,
recall or abstention number.

`api/parse/block_parser.py` and `docs/data-contracts.md` both used
`! model ISR4331` as the worked example of why identity reads raw lines. Both
now use the Arista header, and both say that the asymmetry holds only for lines
the platform itself writes. ADR 0011 is left as written — it is a record of what
was decided, and its illustration was accurate when it was made.
