# ADR 0027 — Reading access lists and interfaces, and what that did and did not start

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P16
- **Decisions:** D74 (structure from data, entries from a named dialect), D75 (an
  access list is emitted whole or not at all), D76 (management status stays
  undocumented rather than inferred)
- **Affects:** `api/parse/structures.py` (new), `api/models/pack.py`,
  `api/models/parsing.py`, `api/normalise/service.py`,
  `packs/builtin/cisco_ios/1.2.0.yaml`

## Context

The gap was larger than "no pack declares a pattern". `build_csm` returned

```python
acls=(),
interfaces=(),
```

**unconditionally, from P5 onward.** `ACL`, `ACLEntry`, `AddrSpec`, `PortSpec`
and `Interface` are complete contracts; the P7 interval analyser is exhaustively
tested against constructed objects; the P12 exposure ranking abstains on every
finding. None of it had ever seen a structure built from a file, because nothing
built one. This was a missing subsystem, not a missing declaration.

## D74 — structure is data, entry grammar is a named dialect

A pack declares **where** things are: where an interface opens, where a list
opens, where a list is bound, as anchored regexes. It does not declare the entry
grammar.

It cannot, honestly. `permit tcp 198.51.100.0 0.0.0.255 any eq 22` becomes an
`ACLEntry` only by turning a wildcard mask into a CIDR, and that is arithmetic on
an integer, not matching. Expressing it as a regex in YAML would either be a
fiction or a small programming language nobody asked for.

So the pack names a `dialect` and the parser for that dialect lives in
`api/parse/structures.py`. Adding a platform that writes an existing grammar
stays a data change, which is what Rule 5 asks for; a genuinely new grammar needs
a parser, which is what "wherever the architecture permits" concedes.

`ios_wildcard` is the only dialect implemented.

## D75 — an access list is emitted whole or not at all

**If any entry in a list cannot be parsed, the entire list is dropped** and its
lines stay in residue, where a human sees them.

This is the decision the rest of the analysis rests on. Order is semantically
significant for shadowing: entry three shadows entry five *because of what sits
between them*. A list quietly missing one entry nobody could read would let the
analyser call a reachable rule unreachable — confidently, with a citation. A
partially parsed ACL is worse than no ACL, because the output looks complete.

Two cases reach it today: an unrecognised port keyword, and a non-contiguous
wildcard mask like `0.0.0.254`, which matches a discontiguous set of addresses
and has no CIDR. Inventing the nearest range would put a wrong interval into
shadowing analysis.

Lines the extractor *does* read leave the residue queue, because asking an
administrator to classify a line the parser already understood spends the one
resource the training loop has.

## D76 — management status is left undocumented

`Interface.is_management` is never set. `Loopback0` carries the description
`MGMT-LOOPBACK`, and reading "MGMT" out of operator free text would be a
heuristic wearing the clothes of a reading. DEF-2 already established that an
undocumented interface is not a non-management one.

This has a direct consequence, below, and it is the honest one.

## What this started, and what it did not

### P7 produces output for the first time

`corpus/cisco/dev/edge-rtr-01.cfg`, `EDGE-IN`, seven entries:

| Entry | Observation |
| --- | --- |
| 5 · `permit ip any any` | **overly permissive** |
| 6 · `permit tcp any any established` | **redundant** — entry 1 is identical |
| 7 · `deny ip any any log` | **shadowed** by the catch-all above it |

`edge-rtr-11.cfg` yields two; `branch-rtr-07.cfg`, a deliberately clean list,
yields **none** — which is the result that shows the analyser is reading rather
than pattern-matching for alarm.

The analyser also declined to flag entry 4, and is right to. The fixture's own
remark says *"this deny is unreachable: the catch-all permit below already
matches it"*, but a rule below cannot shadow a rule above — ACLs evaluate
top-down, and entry 4 is reached first for new SSH connections. **The remark in
the corpus file appears to be wrong, and the analyser disagreed with it
correctly.** Flagged for the corpus author rather than silently accommodated.

### P12 still abstains, and the blocker moved

This is the part not to overstate. Exposure ranking produces nothing, but no
longer for the same reason:

```
before:  no_interface_data          — there were no interfaces at all
now:     indeterminate_interfaces   — "3 interface(s) have undocumented
                                      management status, so the management
                                      plane cannot be located"
```

Interfaces are extracted and their addresses and state are read. What is missing
is which of them is the management plane, and per D76 that is not inferable from
the file. Closing it needs either a pack declaration an operator supplies, or
vendor documentation about which interface names are management — the latter
being `SOURCING_BACKLOG` gap 2 in a new place.

**So one built subsystem started producing output and the other did not.**
Reporting both as unblocked would be the easy summary and the wrong one.

## Consequences

`cisco/ios` ships as **1.2.0**, with 1.1.0 deprecated and re-stamped. Packs are
versioned and immutable, so the declarations are a new version rather than an
edit; the checksum convention is what makes that enforceable, and it is enforced
on load for ACTIVE packs.

Residue on `edge-rtr-01.cfg` falls from 57 lines to 33 — the ACL and interface
lines are recognised now and leave the training queue.

`_pack_examples()` in the corpus-policy suite was extended to cover extraction
examples, so the same provenance rule applies to them: an example is the evidence
a declaration was authored from, and it must be a line someone read in a
development file. The `applied` regex deliberately carries **no** example — no
Cisco development file binds a list to an interface, so it is declared and
unexercised, and the pack says so.
