# ADR 0025 — Presence assertion in the training form, and what happens when two lines disagree

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P15
- **Decisions:** D69 (expose `literal_value`, exclusively), D70 (report the merge
  gap rather than choose a winner)
- **Defects:** DEF-17 (opened — conflicting evidence for one field collapses to
  UNKNOWN)
- **Affects:** `ui/src/components/device/Review.tsx`, `api/train/compile.py`
  (unchanged — see below)

## Context

The backend has accepted `literal_value` on `CompileInput` since P11. The
training form never sent it, so every boolean field — `aaa_enabled`,
`http_server_enabled`, `banner_present`, `snmp_v3_only` — failed to compile with:

> a pattern must either capture a token or declare the literal value its
> presence asserts; this one does neither, so it would produce no fact

The message was exactly right and the administrator had no way to act on it.
**No boolean mapping could be confirmed at all.**

The brief located the form at `ui/src/pages/admin/Training.tsx`. That file no
longer exists: the P13 restructure moved the confirmation loop into the device
workspace, at `ui/src/components/device/Review.tsx`, because the loop needs the
context of the device whose line is being judged.

## D69 — the literal value replaces the token picker; it does not sit beside it

When the selected data type is `bool`, the form asks *"What does this line
assert?"* with `true` / `false`, and the token picker is **removed**.

Offering both would invite a decision naming two sources for one value, and the
compiler would then have to choose between them — precisely the kind of silent
adjudication this project puts in front of a person. The two inputs are mutually
exclusive in the contract, and the form now says so by construction.

## Was there a correctness gap? No — verified, not assumed

The brief flagged a possible gap: *if a pattern can only assert TRUE on match,
`snmp-server community public RO` is unconfirmable and the SNMP check risks a
false PASS.* That would be serious, so it was tested end to end rather than read
off the source:

```
literal 'false', cast bool  ->  state=present  value=False
literal 'true',  cast bool  ->  state=present  value=True
```

A literal value with `cast: bool` asserts FALSE correctly, through the compiler,
the parser and the normaliser. **The compiler needs no extension and none was
made.** The gap was entirely in the interface, which is where the fix went.

`test_a_presence_line_can_assert_FALSE` pins it, stated separately from the TRUE
case because it is the half that matters: without it an abstention would stand in
for a FAIL on a device that genuinely fails.

## D70 — two sources for one field: reported, not resolved

The brief asked whether the canonical model can merge two evidence sources for
`snmp_v3_only` — a v3 user asserting TRUE, a v2c community asserting FALSE.

**It cannot.** Measured with both patterns active:

| Configuration | Result |
| --- | --- |
| v3 user only | `True` |
| v2c community only | `False` |
| **both** | `value=None`, `state=unknown` |

The result is the same whichever line comes first, so this is genuine conflict
detection rather than first- or last-match. The model treats disagreement as an
abstention.

That is **safe and lossy**. Safe, because it never picks a value and so cannot
produce a false PASS. Lossy, because for this field the two sources are not
symmetric: a v1/v2c community is dispositive, and the correct answer is FALSE.

No winner was chosen here. Picking one would be a change to what a canonical
field *means* when its evidence disagrees, and that belongs in a contract
decision of its own, not in a commit about a form.

### The gap is wider than SNMP, and it is already firing

`dist-sw-03.cfg` exercises it with **shipped builtin patterns and no training at
all**:

```
line vty 0 4     transport input ssh          -> telnet_enabled FALSE
line vty 5 15    transport input telnet ssh   -> telnet_enabled TRUE
```

```
dist-sw-03   telnet=None state=unknown   idle=None state=unknown
```

A device is only as secure as its weakest line, so the correct answers are
`telnet_enabled = TRUE` and an idle timeout of `0` (never expires) from
`line vty 0 4`. Both report UNKNOWN. Two failing controls on a genuinely
insecure device produce no FAIL.

Opened as **DEF-17**. The fix is a merge policy — worst-case-wins for
security-relevant fields — and it needs its own ADR because it changes what the
canonical model asserts when evidence disagrees, which is a contract, not a
detail.

### Consequence for DEF-8

The brief expected `dist-sw-03.cfg` to demonstrate DEF-8, because it carries
`exec-timeout 0 0` on a vty line where it means a remote session that never
expires. **It cannot, while DEF-17 stands**: the conflicting vty values make
`idle_timeout_seconds` UNKNOWN, so the rule never sees a value and the defect is
masked rather than shown.

`edge-rtr-09.cfg` does demonstrate it — both the console and `line vty 0 4` carry
`exec-timeout 0 0`, there is no conflict, and the field resolves to
`0, state=present`. That is the fixture DEF-8 must be fixed against.
