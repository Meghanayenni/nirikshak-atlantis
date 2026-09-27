# ADR 0064 — EOS management blocks, and a sourced default held back

- **Status:** Accepted
- **Date:** 2026-09-27
- **Phase:** P18
- **Decisions:** D158 (the EOS pack reads `telnet_enabled`, `idle_timeout_seconds`
  and `banner_present`), D159 (the idle timeout is read from both remote planes
  and not from the console), D160 (the sourced default "EOS disables Telnet" is
  not declared until the harness has a way to score inferred values)
- **Affects:** `packs/builtin/arista_eos/1.2.0.yaml` (new, active),
  `packs/builtin/arista_eos/1.1.0.yaml` (deprecated), tests that used EOS as the
  repository's detection-only pack

## Context

Arista EOS had four corpus devices and no security verdicts: the pack read
identity only. EOS puts remote access in `management ssh`, `management telnet`
and `management console` blocks rather than on `line vty`. The development file
with those blocks is `corpus/arista/dev/dc1-spine-01.cfg`:

```
33 management console        36 management ssh           40 management telnet
34    idle-timeout 15        37    idle-timeout 15       41    idle-timeout 0
                             38    no shutdown           42    no shutdown
62 banner motd / 63-64 body / 65 EOF
```

## D158 — three fields

| Field | Pattern | Scope | Line |
| --- | --- | --- | --- |
| `telnet_enabled` = true | `^no shutdown$` | `^management telnet$`, any depth | 42 |
| `idle_timeout_seconds` | `^idle-timeout (\d+)$`, cast `duration_minutes` | `^management ssh$`; `^management telnet$` | 37, 41 |
| `banner_present` = true | `^banner motd$` | top level | 62 |

`banner motd` gets a literal block closed by the fixed line `EOF`, so its body
no longer reaches the unknown-line queue or the pattern engine.

**The unit is minutes, and it is sourced.** Arista's *Session Management
Commands* chapter (EOS User Manual 4.36.2F), entries `idle-timeout (SSH
Management)` and `idle-timeout (Telnet Management)`, gives the value in minutes
and says 0 disables the timeout. The canonical field stays in seconds, so the
same rule reads every platform; `duration_minutes` already existed for NX-OS.

`shutdown` under `management telnet` has no pattern: no development file
carries it. The brief asked for it; with no line to author from, it would be
the unverified pattern the corpus policy refuses.

## D159 — both remote planes, never the console

The brief suggested reading the timeout from `management ssh` or `management
console`. The console is excluded: a console session needs physical access, and
the Cisco pack excludes `line con 0` for the same reason. Telnet is included,
because a telnet session is a remote management session like an ssh one.

The consequence on dc1-spine-01 is an abstention, not a verdict: ssh says 15
minutes, telnet says 0 — never expires — and `idle_timeout_seconds` has no
merge policy, so it is UNKNOWN with `conflicting_evidence`, citing both lines.
Reading ssh alone would have produced PASS (900 s) on a device whose telnet
sessions never time out. The same shape as two Cisco vty ranges (ADR 0026).

## D160 — a default sourced, and held back

Arista's EOS User Manual 4.36.2F, *Connection Management*
(https://www.arista.com/en/um-eos/eos-connection-management), states in its
opening paragraph that EOS disables Telnet by default. arista.com refused a
direct download, so it was read through a rendering fetcher, and a person should
confirm the reading. It was read in the 4.36.2F edition; the corpus devices run
4.29.2F and 4.30.1F.

Declared as a capability plus a default, it resolved `telnet_enabled` to
`false` (ABSENT_DEFAULT, INFERRED) on sw-leaf-01 and sw-spine-01, and the
absence-aware EVALUATE branch fired on real data for the first time. It also
moved the evaluation harness's **wrong-confident count from 0 to 1 of 21**.

That one was diagnosed before anything else. The case that would have mattered
— an evaluation device enabling telnet through syntax the pack does not read —
was ruled out by reading one field of one label (not the configuration): the
EOS label for `telnet_enabled` is `not_determinable`. The label doctrine
records only what the file alone shows, and the harness counts any assertion
against a non-determinable label as wrong-confident. So every sourced default
would score as wrong-confident by construction.

How an inferred value should be scored is a decision about the critical safety
metric, and it was put to the team. **Decided: withhold the default for now.**
The pack declares neither the capability nor the default — a capability alone
would route an absent block to the *training* queue, which is wrong — and the
ready entry sits commented at the end of the pack. An absent telnet block
abstains, as before. `test_arista_security_fields.py` pins that, and names
itself as the test that changes when the default is declared.

The alternatives, for whoever takes the decision up: declare it and report
wrong-confident 1 with this explanation; or score `absent_default` assertions as
their own population, which redefines the safety metric and needs its own ADR.

## What moved

| Device | telnet | idle timeout | banner |
| --- | --- | --- | --- |
| dc1-spine-01 | true (l.42) — **FAIL** | UNKNOWN, conflicting (l.37, l.41) | true (l.62) — PASS |
| sw-leaf-01, sw-spine-01 | UNKNOWN | UNKNOWN | UNKNOWN |

The EOS cohort (four devices) now produces three baseline rows, each
`cohort_too_small`. Evaluation: EOS still asserts nothing on its one evaluation
file (recall 0 of 3); wrong-confident 0 of 20.

Tests that used EOS as the repository's one detection-only pack now load EOS
1.1.0 as it shipped. The training-loop tests train onto the active pack, so
their version arithmetic moves from 1.1.x to 1.2.x.

**A consequence to fix next.** Pattern examples become similarity-index seeds,
and a seed carries its line but not its block. `no shutdown` is now a seed
labelled `telnet_enabled`. dc1-spine-01 has five `no shutdown` lines in its
review queue — under `management ssh` (38), `management api http-commands` (46,
48) and two interfaces (81, 87) — and, measured with the model installed, each
ranks `telnet_enabled` first at cosine 1.0. It is a ranked suggestion, and an
administrator still decides, but this is exactly how a careless confirmation
happens. The fix is for a seed to carry its pattern's scope; that change belongs
in `api/learn/` and is not made here.
