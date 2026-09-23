# ADR 0029 — A dropped access list announces itself

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P16
- **Decisions:** D78 (name the list and the line that defeated it), D79 (the
  diagnostic is not persisted, and that is stated rather than hidden)
- **Affects:** `api/models/csm.py`, `api/parse/structures.py`,
  `api/routers/audits.py`, `ui/src/components/device/DeviceWorkspace.tsx`

## Context

ADR 0027 (D75) established that an access list is emitted whole or not at all:
order is what shadowing reasons about, so a list with a hole produces confident
wrong conclusions. That decision stands.

It left a reporting problem. A dropped list and a device with genuinely no access
lists produce **the same empty tuple**, and they call for opposite responses:

- *"nobody has taught the parser this syntax"* — a gap in the tool
- *"this device filters nothing"* — a finding about the network

The more alarming of the two is the one that looks like silence.

## D78 — name the list, the line, and the specific reason

`AclExtractionFailure` carries the list name, the line number, the entry text and
an operator-facing sentence. It is emitted *instead of* the list, never beside
it.

The reason names the token that defeated the parser rather than reporting that
parsing failed:

> `EDGE-IN was not analysed: line 3 ('permit ip 10.0.0.0 0.0.0.254 any') uses the
> wildcard mask 0.0.0.254, which is non-contiguous and has no CIDR equivalent`

"could not be parsed" sends an operator to read the whole list. This sends them
to one token — and tells whoever maintains the dialect exactly what to add next,
which is the cheapest routing signal the project has.

It surfaces in the audit response under `acl_analysis.not_analysed`, and in the
device view: an audit that dropped a list reports *"Audit complete · 1 access
list not analysed"* with the reason, rather than a bare success the operator
would have no cause to question.

## D79 — not persisted, and said so

The diagnostic is computed during parsing and reaches the audit response. It is
**not stored**, so re-opening a device later shows the finding tabs without it.

Persisting it means a schema change and a migration, which is its own item. Two
things make deferring it defensible rather than convenient: the audit response —
the moment an operator is actually looking — carries it, and **no access list in
the entire corpus is currently dropped**, so there is nothing yet for a stored
view to show.

That is recorded here rather than left for somebody to discover, because a
deferred capability must raise rather than quietly degrade.

## The tally, which is the useful part

Across every non-holdout corpus file, with the Cisco IOS dialect active:

```
3 access lists analysed, 0 dropped
```

No Cisco list defeats the parser. But *dropped* is not the only way an access
list goes unanalysed, and the third state is far larger — a pack that declares no
extraction at all:

| File | Pack declares extraction | ACL lines sitting in residue |
| --- | --- | --- |
| `juniper/dev/edge-rtr-02.conf` | no | **17** |
| `juniper/dev/core-rtr-01.conf` | no | 8 |
| `arista/dev/dc1-spine-01.cfg` | no | 7 |
| `juniper/dev/srx-edge-01.conf` | no | 1 |
| `juniper/eval/srx-dc-02.conf` | no | 1 |
| `cisco/dev/dc1-leaf-01.cfg` | no pack at all (NX-OS) | — |

So the next dialect to write, by volume of material already sitting in the
corpus, is **Juniper filter terms** — 26 lines across three files — followed by
the Arista/NX-OS CIDR form. That ordering is a measurement rather than a
preference, which is what this tally exists to produce.
