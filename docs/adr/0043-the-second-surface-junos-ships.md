# ADR 0043 — The second surface JunOS ships

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D112 (implement `SyntaxMode.BRACE`), D113 (the surface is
  chosen from the file, not from the platform), D114 (one dialect, two
  surfaces), D115 (a bracketed port list expands; it does not drop the filter)
- **Affects:** `api/parse/block_parser.py`, `api/parse/service.py`,
  `api/parse/structures.py`, `api/models/enums.py`, `api/models/pack.py`,
  `api/ingest/device_identity.py`,
  `packs/builtin/juniper_junos/1.2.0.yaml` (new)
- **Deletes:** `test_the_brace_nested_form_is_still_unreachable`

## Context

`corpus/juniper/dev/core-rtr-01.conf` is legitimate JunOS, registered since P15,
and no part of the pipeline could reach it. It scored 0.25 as `cisco/ios` — below
the detection floor — so it was skipped by the peer baselines, invisible to the
analyser, and unauditable.

It also carries the only expected **shadowed** fixture on a non-Cisco platform:
`term allow-anything { then accept; }` sits above two later terms.

## What the blocker actually was

The brief suggested the filter-term reader from the flat `set` work might make
this cheap once detection was fixed, and asked for verification rather than
assumption. Verified: **detection was the smallest of four blockers.**

| Layer | State before |
| --- | --- |
| Detection | every JunOS signature matched `^set …` |
| Syntax mode | `SYNTAX_MODE_BY_OS["junos"] = SET_PATH`, keyed by platform |
| Parser | `SyntaxMode.BRACE` raised `UnsupportedSyntaxModeError` |
| Extraction | the flat reader groups top-level lines; brace terms are subtrees |

Fixing detection alone would have identified the file correctly and then parsed
a brace hierarchy as flat `set` paths — 165 lines read as unrecognised, a
"successful" audit with every field UNKNOWN. Two of the four had to land before
detection was even worth changing.

## D112 — implement BRACE, because the deferral's own condition was met

`IMPLEMENTED_MODES` excluded `BRACE`, deferred to *"the phase whose corpus
contains a brace-structured platform"*. That file arrived at P15 and the
deferral outlived its condition by three phases.

The parser is dull on purpose: a line ending `{` opens a block, a line that is
`}` closes one, everything else is a statement. Braces and the terminating
semicolon are stripped from `text` and kept in `raw_line`, so a pattern author
writes `^host-name (\S+)$` and matches what they see — requiring `;?$` on every
pattern would move punctuation into every regex in the pack, and the first one
written without it would fail silently.

`/* … */` comments are unplaced lines, not nodes, on the same rule as `#`: a
commented-out directive must never produce a PRESENT field. `## SECRET-DATA`
markers are trailing annotations and are stripped from `text`.

Two details the contract forced, both improvements:

- **A closing brace is recorded as an unplaced line.** `ConfigTree` requires
  every source line to be a node or unplaced, never dropped, so *"the parser
  read your whole file"* stays checkable. The first draft silently discarded 47
  terminators and the contract refused it.
- **An unmatched `}` does not raise.** Refusing to read the rest of a
  configuration over one stray brace would turn a cosmetic defect into a device
  nobody can audit. It is recorded as unplaced, where it is visible.

## D113 — the surface is a property of the file

`SYNTAX_MODE_BY_OS` keyed the mode to `os_family`, and JunOS ships two surfaces.
The same device can be captured either way on the same afternoon, so no
per-platform answer is correct.

`syntax_mode_for(pack, text)` narrows by content for platforms listed in
`ALTERNATE_SURFACES`. The discriminator is deliberately dull: a `set`-form JunOS
file contains **no opening brace at all** — verified across all four in the
corpus, which have zero between them — so one at column zero is unambiguous. No
counting, no ratio, no threshold to tune.

## D114 — one dialect, two surfaces

`AclDialect.JUNOS_FILTER` replaces `JUNOS_SET_FILTER` in the shipped pack. The
pack names the **language**; the reader picks the surface from the parsed tree's
syntax mode. A pack declaring the surface would be wrong for the same device
exported the other way.

`AclExtraction` gains `brace_block`, so both locators are data: the flat form's
`^set firewall family inet filter (\S+) ` and the brace form's `^filter (\S+)$`.
The reader additionally requires `firewall` in the node's ancestry, which is
what separates a filter *definition* from the `filter { input NAME; }` binding
that sits inside an interface — and the corpus file has both.

`JUNOS_SET_FILTER` is kept in the enum: `juniper/junos 1.1.0` still declares it
and must still load.

### Two bugs this surfaced

**`identity_for` returned only the first pattern for a field.** A pack may
legitimately declare `hostname` twice — once per surface — and the second
declaration was read by nothing, which is the shape DEF-12 is named for.
`extract_identity` now consults every declaration for a field, first match
winning, in the pack's declaration order. Both JunOS surfaces report hostname
and OS version now; before this, the brace file reported neither.

**`matched_node_ids` gated on the old dialect name**, so renaming it would have
left every consumed filter line in the training queue — a line the parser
understood, put in front of an administrator to classify. Caught by the residue
test.

## D115 — a bracketed port list expands, it does not drop the filter

`term allow-management` matches `destination-port [ ssh https ]`. The flat
reader dropped a whole filter on a bracketed list, on the ground that one entry
cannot hold two intervals — and under that rule `PROTECT-RE` would have been
dropped and this file would have produced no analysis at all.

That rule was too strong. A bracketed list is a **disjunction over one field**,
not an unreadable token: the term expands into consecutive entries with the same
action and everything else equal. They are adjacent, so nothing can come between
them, and the ordering the shadowing analysis depends on is preserved exactly.

It costs something, and the direction matters. `covers()` is pairwise, so a
later entry covered only by the *union* of an expanded pair is reported as not
shadowed. That under-reports rather than over-reports, which is the trade
`address_covers` already makes deliberately: a missed shadow costs one finding,
an invented one costs trust in every other finding.

Bracketed **addresses** need no expansion — `AddrSpec.resolved_cidrs` holds
several networks and the interval analysis consumes all of them.

`test_a_bracketed_port_list_drops_the_filter_and_says_why` asserted the old
behaviour and was deleted by the change that earned it.

## What P7 yields on the brace file

`PROTECT-RE`, five terms, six entries:

| # | Term | Entry | Observation |
| --- | --- | --- | --- |
| 1 | `allow-established` | permit tcp any→any | — |
| 2 | `allow-management` | permit tcp 198.51.100.0/24 → :22 | **redundant** (1) |
| 3 | " | permit tcp 198.51.100.0/24 → :443 | **redundant** (1) |
| 4 | `allow-anything` | permit any any→any | **overly permissive** |
| 5 | `block-remote-telnet` | deny tcp any→:23 | **shadowed** (1, 4) |
| 6 | `default-deny` | deny any, logged | **shadowed** (4) |

**The expected shadowed result appears**, and it is the first time the interval
analyser has reported one on a non-Cisco platform. A filter that reads as though
it blocks telnet and cannot is exactly what it exists to catch.

Residue on the file falls from 165 unreadable lines to **75**.

### A corpus observation, not a change

Entries 2 and 3 are redundant because `term allow-established` permits **all**
TCP — it matches `from { protocol tcp; }` with no `tcp-established` condition,
so its name describes an intent the configuration does not implement. The file's
own header calls the device *"UNDER-hardened"*, so this may be deliberate.

Flagged for the corpus author rather than edited, on the ADR 0028 precedent: the
analyser reported what the file says, and changing the fixture to match the name
would be changing data to suit a reading.

## Measurements re-pinned

- **Fleet**: 18 devices → **19**, skipped 1 → **0**. Every registered corpus
  file is now audited by a pack. `skipped_files` stays in the response, because
  zero is a result and the field distinguishes it from a file that produced
  nothing.
- **Cohorts**: `juniper/junos` 4 → **5**.
- **Evaluation**: unchanged but for the pack version string. `core-rtr-01.conf`
  is a development file and the evaluation-split JunOS file is `set`-form, so
  the brace surface is parsed and **unmeasured** — the same standing NX-OS has.
