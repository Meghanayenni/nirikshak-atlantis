# ADR 0044 — A serial is not a parsing gap

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D116 (a field the input cannot carry is recorded against the
  input type, not the platform), D117 (the report names the device)
- **Affects:** `api/models/source_limits.py` (new), `api/report/model.py`,
  `api/report/templates/report.html.j2`, `api/routers/reports.py`
- **Supersedes the framing in:** ADR 0037 (D99) — not its decision

## The reframe

ADR 0037 decided not to author a `serial` pattern, and was right. It filed the
result as a deliverable *not being delivered*, which was the wrong description.

A serial number is inventory data. It appears in `show version` and
`show inventory` output and **not in a configuration export**. NIRIKSHAK ingests
configuration exports. So no pattern over this input could ever match one, and
"nobody has authored a serial pattern yet" was never a true account of why the
field is empty — it implied somebody could close it by writing a regex.

They could not. That is a materially better answer to the PS deliverable than
"not delivered", and it is also the honest one.

## D116 — record it against the input type, not the platform

The brief asked for this in the capability model, per platform. **It does not
belong there, and the reason is the whole point of the reframe.**

`PlatformCapability` says whether *a platform* can express a control, and
`supported: false` resolves to `ABSENT_UNSUPPORTED` — a determinable state a
compliance rule may act on. Both halves are wrong here:

- **NX-OS can express a serial.** So can every platform in this corpus. What
  cannot carry it is the input type. Recording a platform limitation would be
  factually wrong, and would then need vendor documentation to be admissible —
  documentation this repository does not have (`SOURCING_BACKLOG` gap 2) for a
  claim that is not true.
- A claim scoped to the **input** needs no citation at all, because it is a
  statement about what NIRIKSHAK reads rather than about somebody else's
  equipment. It is provable from this project's own contract.

So `api/models/source_limits.py` holds a product-level table: per `SourceType`,
the identity fields that input cannot carry, and why. It sits beside the
contracts rather than inside a vendor pack, because it is not vendor knowledge.

Three constraints keep it from becoming a place to hide ordinary gaps:

- an entry asserts that **no pack will ever read this field from this input**,
  which is stronger than "nobody has written the pattern yet" — a merely
  unparsed field belongs in `SOURCING_BACKLOG`, where somebody can close it;
- a reason shorter than fifteen words fails a test, because a table of
  one-word excuses would satisfy the structure and mean nothing;
- **no limit is recorded for XML or JSON**, because that ingestion is not
  built. Asserting something about a code path that does not exist would look
  like coverage of it.

A test asserts no shipped pack declares an identity pattern for a limited
field, so the consequence is checked against the four packs rather than trusted.

### The clean path, named and not built

Accept `show version` / `show inventory` output as a **second input type**
alongside configuration exports, and let a pack declare identity patterns scoped
to it. `SourceType` already distinguishes artefacts and `Evidence` already
records which one a citation came from, so the contracts are in place and what
is missing is ingestion, detection and pack syntax for a second artefact.

That is recorded where the absence is, so the next reader finds the answer
rather than the gap. It is **not built** and this is not a plan to build it.

## D117 — the report names the device

ADR 0041 found that the report identified its subject only by
`config_file_id`, a content hash: no hostname, no model, no OS version, no
serial. All were extracted, stored in `device` and reaching the canonical model,
and stopped at the report boundary. An operator handed `report.pdf` for
`8995304d…` could not tell which router it was.

The report now carries a **Subject** block with all four, and the header names
the hostname. Identity is looked up at render time, like the snippet library and
the control mappings and for the same reason: a report cannot show identity the
`device` row no longer holds.

Two renderings, deliberately different:

- a field nothing read shows **"not reported"**;
- the serial shows **"not applicable"** with the reason.

Blank, or a shared "unknown", would merge two different statements. *"We looked
and failed"* invites somebody to go and find it. *"This input does not contain
one"* tells them the report is complete and the answer lives somewhere else. The
whole of this ADR is that distinction, so the report makes it too.

`config_file_id` keeps its own explanation — it identifies the file, not the
device, and editing the configuration produces a different identifier (DEF-3).
Naming the hostname beside it does not weaken that; it stops the hash from being
the *only* thing a reader has.

## The sharpest example in the repository of why sourced provenance matters

`cisco/ios` read the hardware model from `^! model (\S+)` from P4 until P17.
The only line in the world matching it was one somebody typed into
`corpus/cisco/dev/rtr-core-01.cfg`. Cisco's `show running-config` does not emit
a model line.

So NIRIKSHAK reported a **fabricated** device model as observed identity, **with
a citation**, in a builtin pack, for ten phases.

The citation is what makes that serious. An absent field invites a question. A
field carrying a file name and a line number invites belief — the evidence
pointer is the thing that converts a value into a fact for whoever reads it, and
here it pointed at an annotation a corpus author invented so the field would
populate. Rule 2 exists to make every claim traceable; a traceable fabrication
is worse than an untraceable one, because tracing it succeeds.

It shipped because the corpus-policy suite asks whether a pattern's example is
**a line somebody read in a development file**, and it was — somebody read it,
because somebody wrote it. No test could ask the question that mattered, which
is whether a *device* would ever emit that line. That question is vendor
documentation, and it is `SOURCING_BACKLOG` gap 2 wearing a third disguise.

The Arista model pattern is the contrast that makes the point: EOS writes
`! device: sw-leaf-01 (DCS-7050SX3-48YC8, EOS-4.29.2F)` at the top of every
`show running-config`, in all four Arista corpus files. Same comment syntax,
same extraction path, opposite standing — and nothing in the repository can tell
them apart automatically.

## Consequences

`SOURCING_BACKLOG` gap entry for the serial is reframed rather than closed: it
is not waiting on a pattern author, and it is not waiting on vendor
documentation. It is waiting on a second input type, which is engineering work
nobody is prevented from doing.
