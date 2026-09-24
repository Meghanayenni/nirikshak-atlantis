# ADR 0053 — A refusal that outlived its reason

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D136 (the Cisco IOS pack reads the affirmative `ip http server`,
  authored from the development line that has carried it since P15)
- **Affects:** `packs/builtin/cisco_ios/1.4.0.yaml` (new, active),
  `packs/builtin/cisco_ios/1.3.0.yaml` (deprecated), `eval/reports/evaluation.txt`

## Context

The framework selector's clearest demonstration — a device with `ip http server`
fails under the DISA STIG and is not assessed under CIS (ADR 0052) — could not
happen. **No Cisco IOS pack version has ever read `ip http server` as true.** The
pack carried only `^no ip http server$`, and said why:

> the affirmative form appears nowhere in the development corpus, so it could be
> written from general Cisco knowledge but not verified. A device that enables
> the HTTP server therefore reports UNKNOWN …

That was correct at P4, when the development split held two files. It stopped
being correct at P15, when `corpus/cisco/dev/edge-rtr-01.cfg` was registered with
`ip http server` on line 47. Nobody revisited the refusal. Three corpus files
enable the server — one development, two evaluation — and every one of them has
reported `http_server_enabled` UNKNOWN for eight phases, while the manifest note
on `sw-dist-11.cfg` went on describing the miss as deliberate.

This is the same shape this session found in thread 3b (ADR 0013's reason for
denying the rulepack a checksum, expired at P11) and last session found in the
SNMP gate. A refusal recorded with its reason is the right practice; it needs
the reason re-read when the facts under it move.

## D136 — read the line the corpus now verifies

Pack 1.4.0 adds one pattern, and nothing else changes:

```yaml
- id: p-http-server-002
  field: http_server_enabled
  scope: { block: null }
  match:   { type: regex, pattern: '^ip http server$' }
  capture: { value: 'true', cast: bool }
  examples: ['ip http server']
  negative_examples: ['no ip http server', 'ip http secure-server', 'ip http server extra']
```

Authored from `edge-rtr-01.cfg:47`, a development file, so the corpus-provenance
suite admits its example. Top level, exact line. `ip http secure-server` is a
different listener and a different field, and a negative example says so. No
corpus file carries both the affirmative and the negated form, so the merge
semantics of ADR 0026 are not exercised by this change.

1.3.0 is marked `deprecated` and restamped; 1.4.0 is `active` with its parent
recorded. The two evaluation files were not opened to write this pattern.

## What moved in the measurement

`make evaluate`, before and after, on the unchanged labels:

| Cisco | before | after |
| --- | --- | --- |
| Field assertions / precision | 18 / 100% | 20 / 100% |
| Field recall | 69.2% | 76.9% |
| FAIL recall | 55.6% (5/9) | 77.8% (7/9) |
| FAIL precision | 100% (5/5) | 100% (7/7) |
| **Wrong-confident** | **0** | **0** |

Two misses became two hits: `edge-rtr-11.cfg` and `sw-dist-11.cfg`, both labelled
`http_server_enabled: true` by a human who read the line. The critical metric did
not move.

**The recall gain is real and it is small.** One pattern, written from one
development line, matched two evaluation lines that are character-for-character
identical to it. One author wrote all three files; gap 8 of
`SOURCING_BACKLOG.md` already warns that this corpus flatters exactly this kind
of figure.

## What this does not change for the selector

Neither in-scope IOS XE 17 corpus file enables the server — both carry
`no ip http server` — and the three files that do are IOS 15.x, which the STIG
does not describe. **So the STIG-versus-CIS contrast still cannot be shown on the
corpus.** ADR 0054 shows it on a constructed configuration and says so. What this
ADR changes is that the contrast is now *possible*: before it, an IOS XE device
enabling the server would have been UNKNOWN under every framework.
