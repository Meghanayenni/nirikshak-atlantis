# ADR 0065 — JunOS in two surfaces, and a default a gap makes unsafe

- **Status:** Accepted
- **Date:** 2026-09-27
- **Phase:** P18
- **Decisions:** D161 (the JunOS pack reads four canonical fields, each from the
  surfaces a development file carries), D162 (`distinct` captures: one object
  written on several `set` lines), D163 (a brace statement is admitted as a
  development line in the form the parser reads it), D164 (`ssh_version` is a
  pattern, not a not-applicable capability), D165 (Juniper's documented default
  for telnet is not declared while the flat form has no pattern)
- **Affects:** `packs/builtin/juniper_junos/1.3.0.yaml` (new, active),
  `packs/builtin/juniper_junos/1.2.0.yaml` (deprecated), `api/models/pack.py`,
  `api/parse/fields.py`, `api/routers/fleet.py` (docstring),
  `tests/fixtures/corpus_lines.py` (new)

## Context

JunOS had five corpus devices and no security verdict: its pack read identity
and firewall filters, no canonical field. Detection was checked first, as the
brief asked: all four development files are detected as `juniper/junos`,
`core-rtr-01.conf` parses in brace mode and `edge-rtr-02`, `srx-branch-04` and
`srx-edge-01` in flat `set` mode.

The existing rules — NRK-TELNET-001, -BANNER-001, -LOGGING-001, -SSH-001 — are
not vendor-scoped (`applies_to` is `*`). No rule was added or changed.

## D161 — four fields, from the surfaces the corpus carries

| Field | Brace (core-rtr-01) | Flat `set` |
| --- | --- | --- |
| `telnet_enabled` = true | `telnet` under `system`/`services` (l.67) | **none** — no development line |
| `banner_present` = true | `message "…"` under `system`/`login` (l.44) | `set system login message …` (edge-rtr-02 l.39) |
| `logging_hosts` | `host X` under `system`/`syslog` (l.78) | `set system syslog host X …` (edge-rtr-02 l.43-45; srx-branch-04 l.4; srx-edge-01 l.6) |
| `ssh_version` | **none** — no development line | `set system services ssh protocol-version vN` (srx-branch-04 l.3; srx-edge-01 l.4) |

Two of the brief's four fields therefore work in **both** dialects (banner,
logging hosts) and two in **one** (telnet: brace; SSH version: flat). The brief
asked for both dialects for every field; the missing halves have no line in any
development file to author from, and the corpus policy refuses a pattern with
no verified example. A file in the unread dialect abstains.

The only `set system services telnet` in the corpus is inside a comment
(edge-rtr-02 line 14). A test pins that it is not read.

## D162 — `distinct`: one host on three lines

edge-rtr-02 writes one syslog host as three `set` lines: facility, authorization
and port. A multi-valued field accumulates one value per matching line, so the
host would have been reported three times, while the brace file reports the
same host once. `CaptureSpec.distinct` lets a pattern declare that repeated
captures name one object; the field keeps each value once, in first-seen order,
and cites every line. It defaults to false, so no existing pack changes: an IOS
file that genuinely lists a server twice still says so.

## D163 — a brace statement is a development line

The corpus policy requires every pack example to appear verbatim in a
development file. A brace pattern matches the parsed statement, which drops the
structural `;` or `{`: the line `telnet;` is the statement `telnet`, and the
pattern's own self-check requires its example to match it. The two rules could
not both hold for the first brace-form pattern in the repository.

The provenance check now admits the statement form **only for files the parser
reads as brace**, decided the way the parser decides it (`ALTERNATE_SURFACES`
and `BRACE_OPENER`). Three tests built "every development line" separately — the
corpus policy, the similarity index's seed check and a learn-boundary test — and
the index check failed first. They now share `tests/fixtures/corpus_lines.py`.

## D164 — `ssh_version` is read, not declared not-applicable

The brief said JunOS SSH is always protocol 2, not configurable, and should be a
`PlatformCapability` rather than a pattern. **Two development files configure
it**: `set system services ssh protocol-version v2` (srx-branch-04 line 3,
srx-edge-01 line 4). A capability claiming the control cannot be expressed would
contradict the corpus, and would need a vendor source besides. It is read like
any directive. A list form such as `[ v1 v2 ]` does not match and abstains.

## D165 — a documented default the pack cannot yet use safely

Juniper's *Enable Remote Access Services* (Junos OS Getting Started Guide,
https://www.juniper.net/documentation/us/en/software/junos/junos-getting-started/topics/task/remote-access.html)
states in its introduction that SSH, Telnet and FTP are all disabled by default
in Junos OS. Fetched as HTML and the sentence read directly. It is exactly the
"absent means off" the brief described.

It is not declared, for a reason that is about this pack, not about the harness
question ADR 0064 left open. The flat surface has no telnet pattern. With the
default declared, a `set`-form file that **enables** telnet would match nothing,
fall through to the default, and PASS NRK-TELNET-001 as inferred — a false PASS
carrying a citation, the worst output this system can produce. A default is safe
only once every surface that can enable the service is read. The pack says so
at its end, and `SOURCING_BACKLOG.md` gap 2 records the default as obtained.

The brief's premise that ADR 0027 and `PROVENANCE.md` document this asymmetry
was checked: neither mentions it. The only statement of it in the repository is
the corpus file's own header comment, which the project forbids as a platform
citation.

## What moved

| Device | telnet | banner | logging hosts | SSH version |
| --- | --- | --- | --- | --- |
| core-rtr-01 (brace) | **FAIL** (l.67) | PASS (l.44) | PASS (l.78) | UNKNOWN |
| edge-rtr-02 (flat) | UNKNOWN | PASS (l.39) | PASS (l.43-45) | UNKNOWN |
| srx-branch-04 (flat) | UNKNOWN | UNKNOWN | PASS (l.4) | PASS (l.3) |
| srx-edge-01 (flat) | UNKNOWN | UNKNOWN | PASS (l.6) | PASS (l.4) |

The JunOS cohort (five devices) now compares four fields, with no device
deviating; fifteen baselines fleet-wide. **Evaluation:** JunOS asserts one field
on its evaluation file, correctly (`ssh_version`) — recall 0% → 25%, wrong 0.
Fleet-wide wrong-confident is 0 of 21. The similarity index gains ten seeds and
a third vendor.

Two tests depended on JunOS reading nothing. The fleet test for
`nothing_compared` — its only coverage — now builds the state from five EOS
fixture copies that set nothing EOS reads; JunOS gets its own test showing it
compared. The harness test for "detection-only vendors" now asserts the measured
per-vendor figures.

Not changed, and worth a follow-up: the JunOS pack declares no
`comment_prefixes`, so `#` comment lines in `set` files still reach the
unknown-line queue. A commented directive cannot match a pattern (every flat
pattern is anchored at `set`), so this is queue noise, not a false fact.
