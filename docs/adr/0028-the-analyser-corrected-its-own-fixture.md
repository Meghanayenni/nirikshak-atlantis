# ADR 0028 — The analyser caught an authoring error in its own test data

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P16
- **Decisions:** D77 (fix the fixture, never the analyser)
- **Affects:** `corpus/cisco/dev/edge-rtr-01.cfg`, `corpus/MANIFEST.yaml`

## What happened

The first run of the P7 interval analyser over a real configuration reported
three observations on `EDGE-IN` and **declined to flag entry 4**, which carried
this remark:

```
 remark this deny is unreachable: the catch-all permit below already matches it
 deny   tcp 198.51.100.0 0.0.0.255 any eq 22
```

The remark is wrong. Access lists evaluate top-down, so a permit *below* cannot
shadow a deny *above*. Entry 4 was reached first for any new SSH connection from
that range, and was therefore live. The analyser was right and the fixture's
author was not.

## D77 — fix the fixture, never the analyser

The temptation in this situation is to make the tool agree with the comment,
because the comment reads like a specification. It is not one: it is a claim
about the file, and it was false. Tuning the analyser to agree would have
installed a real defect — reporting live rules as unreachable — in order to
satisfy a sentence somebody typed.

So the entry moved below the catch-all, where the remark's claim becomes true,
and the remark was rewritten to say what the order actually does:

```
 remark catch-all -- makes every rule below it irrelevant
 permit ip any any
 remark unreachable: the catch-all permit ABOVE already matches this traffic.
 remark a rule below cannot shadow a rule above -- ACLs evaluate top-down.
 deny   tcp 198.51.100.0 0.0.0.255 any eq 22
```

`EDGE-IN` now yields four observations rather than three, and Cisco gains the
**genuinely shadowed entry the remark had been promising**:

| Entry | Observation |
| --- | --- |
| 4 · `permit ip any any` | overly permissive |
| 5 · `deny tcp 198.51.100.0/24 any eq 22` | **shadowed** |
| 6 · `permit tcp any any established` | redundant |
| 7 · `deny ip any any log` | shadowed |

## Why this is on the record

A fixture that was correct first time demonstrates that the analyser agrees with
its author. **A fixture the analyser corrected demonstrates something stronger:**
that the analysis is independent of the expectations of the person who wrote the
data, and survives disagreeing with them.

This is also the failure mode the project is most exposed to. Every corpus file
is synthetic and written by one team; an analyser tuned until it matches its
authors' beliefs would score perfectly and mean nothing. That risk is already
recorded against the evaluation numbers (`pattern_author_conflict`), and this is
the first case where the two came apart and the tool won.

## The rest of the audit

Every remark in the corpus making a reachability claim was checked:

| File | Claim | Verdict |
| --- | --- | --- |
| `edge-rtr-01.cfg` | "this deny is unreachable … below" | **wrong — fixed here** |
| `edge-rtr-01.cfg` | "catch-all — makes every rule below it irrelevant" | correct |
| `edge-rtr-01.cfg` | "redundant with the established rule at the top" | correct |
| `edge-rtr-11.cfg` | "catch-all — makes every rule below it irrelevant" | correct — its catch-all is entry 2 |

The two Juniper filter files carry **no** reachability claims. The only comment
of that kind is an absence note in `edge-rtr-02.conf` about `set system services
telnet`, which is a statement about what the file omits and is verifiable by
reading it.

## Consequences

`edge-rtr-01.cfg` is a development-split file, so no label depends on its bytes
and no measurement moved. Its manifest checksum is updated. Every pack example
drawn from it still appears in it — the change reorders lines and adds remarks,
and removes none.
