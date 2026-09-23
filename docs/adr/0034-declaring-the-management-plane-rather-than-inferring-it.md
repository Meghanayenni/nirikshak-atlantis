# ADR 0034 — Declaring the management plane rather than inferring it

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D88 (interface roles are platform knowledge, not extraction),
  D89 (a classification carries its citation or is not made), D90 (no match
  means undocumented, never "not management")
- **Affects:** `api/models/pack.py`, `api/models/csm.py`,
  `api/normalise/service.py`, `api/prioritise/exposure.py`

## Context

P12's exposure ranking abstains on every corpus device:

```
indeterminate_interfaces — 3 interface(s) have undocumented management status,
so the management plane cannot be located
```

Interfaces are read. Their addresses, state and applied lists are read. What is
missing is which of them is the management plane, and D76 established that this
is not inferable from the file: `Loopback0` carries the description
`MGMT-LOOPBACK` and `fxp0` carries `OUT-OF-BAND-MGMT`, and reading "MGMT" out of
an operator's free text is a heuristic wearing the clothes of a reading. DEF-2
settled that an undocumented interface is not a non-management one.

This ADR builds the construct that could say so honestly, and then reports that
it ships empty.

## D88 — an interface role is platform knowledge, not extraction

`InterfaceRole` sits beside `PlatformDefault` and `PlatformCapability`, carries
the same `PlatformProvenance`, and is admissible only when `SOURCED`:

```yaml
interface_roles:
  - name_pattern: '^Management\d+$'
    is_management: true
    provenance:
      platform: acme/os
      source_type: vendor_documentation
      source_id: ACME OS Configuration Guide, release 9
      locator: §4.2, table 4-1
      status: sourced
```

That placement is the decision. DEVELOPER_GUIDE.md §3 warns against adding a schema field
before a pattern for it can be verified against a corpus file — and this is not
that kind of field. A parsing pattern is gated on **a line somebody read**; a
platform claim is gated on **a document somebody read**. `defaults` and
`capabilities` already ship empty across all four packs for exactly this reason,
and an interface role is the same kind of statement: it is about what a vendor
designates, not about what this device wrote.

The pattern is an anchored regex, refused otherwise. Unanchored, `Management\d+`
also matches `not-Management0`, which is how a role declaration quietly becomes
the heuristic it exists to replace. Examples must match their own pattern, and
two roles may not share one — otherwise the classification would depend on
declaration order.

A `project_asserted` role can be written down and reviewed; it classifies
nothing. The exposure ranking decides what an operator fixes first, and an
unverified claim must not reach it.

## D89 — a classification carries its citation, or is not made

`Interface` gains `management_ref`, and refuses `is_management` without it.

Rule 2 does not exempt an assertion because it rests on vendor documentation
instead of a configuration line. A classification with no citation would be a
claim about a device with nothing behind it, and it would make the exposure
ranking reachable by anything that sets a boolean. To locate a management plane
you must name the document that says where it is.

This caught nine existing test constructions that set `is_management=True` with
nothing behind it. They now say, in the fixture, that they are fixtures.

## D90 — no match means undocumented, never "not management"

Declaring that `^Management\d+$` is the management plane says **nothing** about
`GigabitEthernet0/0`. `_classify_interfaces` leaves an unmatched name at `None`.

Returning `False` would let one declaration silently classify every interface on
a device, and the ranking would then de-prioritise findings on interfaces nobody
ever looked at — quietly, and with a citation on the one that did match. Saying
an interface is *not* management is its own declaration with its own citation,
because `is_management is False` is a determinable state the ranking acts on and
is exactly as capable of producing a wrong answer as a `True`.

This is the second half of what DEF-2 protects. The first half was the accessor
refusing to fold `None` into "not management"; this is the pack contract
refusing to let silence do it instead.

## The honest outcome: it ships empty, and P12 still abstains

**No pack declares a role.** Nothing in this repository documents which
interface names a vendor designates as management-plane, and no administrator
has confirmed one — the confirmation loop maps a *line* to a *field*, and an
interface role is neither.

So the measurement is unchanged: every interface NIRIKSHAK reads is
`is_management=None`, `exposure_score` and `priority_rank` stay `None`, and the
audit response still reports `indeterminate_interfaces`. **This is
SOURCING_BACKLOG gap 2 appearing in a new place**, exactly as ADR 0027
predicted, and it is an acceptable outcome rather than a failure of this work:
the alternative was to ship the inference DEF-2 forbids.

What did change is that the gap now has a shape. Before this, "P12 abstains"
and "there is no way to tell P12 anything" were the same sentence. Now there is
a construct, a provenance requirement, and a named thing to source — and the
abstention reason says so:

> A pack locates the plane by declaring `interface_roles` from vendor
> documentation; none does yet (SOURCING_BACKLOG gap 2).

### The path is wired, not dead

`test_exposure_stops_abstaining_once_a_role_locates_the_plane` runs the whole
chain on a constructed pack: declare a sourced role, classify `Management0`,
bind an ACL to it, and the assessment moves from `INDETERMINATE_INTERFACES` to
`DETERMINED` with a score above zero.

That test exists because without it, "P12 abstains" and "P12 is broken" look
identical from outside. It is the same shape as D73's
`test_the_mirror_policy_resolves_to_false`: prove the mechanism in both
directions on constructed input, and let no shipped pack claim anything it
cannot cite.

`test_no_shipped_pack_declares_an_interface_role` **is written to be deleted**
by the first sourced role, and fails loudly at that point so whoever adds one
has to read the provenance rules rather than adding a classification quietly.

## Also corrected here

Three operator-facing abstention reasons in `api/prioritise/exposure.py` had
gone stale and were stating things that are no longer true:

- *"No vendor pack declares an interface pattern yet (gap 5)"* — Cisco IOS has
  declared one since ADR 0027.
- *"The corpus contains no access list in any split (gap 1)"* — four are
  analysed as of ADR 0033.

A reason string is what an operator reads instead of a number. One that
describes a state the system left two phases ago is worse than a bare
abstention, because it sends them to a backlog entry that has already closed.
