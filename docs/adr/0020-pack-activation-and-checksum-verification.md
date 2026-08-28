# ADR 0020 — Pack activation, and a checksum that finally checks something

- **Status:** Accepted
- **Date:** 2026-08-28
- **Phase:** P11
- **Decisions:** D45 (two pack roots), D46 (semver ordering, one active pack),
  D47 (checksums are verified), D51 (a two-step lifecycle)
- **Defects:** DEF-11 (fixed), DEF-12 (fixed), **DEF-13 (assigned and fixed)**
- **Related:** ADR 0019 (the confirmation loop), ADR 0011 (pattern scoping)

## Context

Until P11 every vendor pack was written by a person and read by a reviewer before
it was ever loaded. P11 ends that: `api/train/` writes pack files at runtime from
administrator confirmations, and those files are loaded by the same process that
wrote them, with nobody in between.

Three latent defects and one deferred finding all become load-bearing at exactly
that moment. None of them was a bug while packs were few and hand-written; all of
them are bugs the first time a pack is generated.

## DEF-13 — the checksum that was never checked

**Assigned a number here.** The finding itself is older: the P4 review
established that pack checksums are *declared and never verified against file
bytes*, `docs/data-contracts.md` recorded that fixing it *"belongs to P11"*, and
`tests/unit/test_rulepack_loading.py` called it *"a mistake worth not
repeating"* — while the mistake went on shipping for seven phases. It had no
identifier, which is part of why it survived so long.

The declared values matched no computable digest of anything. `VendorPack`
validated that an ACTIVE pack *carried* a checksum and that it *looked* like a
sha256, and never once compared it to the file. A declared-but-false integrity
value is worse than none: it looks like a control and is a decoration.

### The convention

Stated in one place, `api/ingest/pack_checksum.py`:

> sha256 of the file's bytes as stored — LF line endings, which `.gitattributes`
> guarantees on every checkout — with the `checksum:` line removed entirely.

Removing the line rather than blanking it is what makes the digest a **fixed
point**: the value being written does not participate in the value being
computed, so a pack can be stamped in one pass and re-stamped forever without
changing. That property is what makes the convention usable for generated files
at all.

CRLF is normalised before hashing. A pack written on Windows and one written on
Linux are the same pack, and an integrity check that disagreed would report
tampering where there is none — the false alarm ADR 0007 names as the worst
failure mode an integrity mechanism has.

### What was corrected, and what was not

**Four** packs failed verification, not the three the P11 plan predicted. The
plan counted the pre-P10 packs and missed that Cisco ships two versions:

| Pack | Status | Old checksum | New checksum |
| --- | --- | --- | --- |
| `arista_eos/1.0.0` | deprecated | `sha256:48ebe2a2…9bb06e0` | `sha256:a93f50f8…2f21435` |
| `cisco_ios/1.0.0` | deprecated | `sha256:3a3bc039…9d0009` | `sha256:be8bb577…a825e28` |
| `cisco_ios/1.1.0` | **active** | `sha256:b23481b9…129b00ac1` | `sha256:b9f20cc9…81b3d0c39` |
| `juniper_junos/1.0.0` | **active** | `sha256:7bcb6552…7b6cba33` | `sha256:f2d79c76…c1ec3bea` |

`arista_eos/1.0.1` needed no change: it was stamped under this convention at P10
and already verified.

**Only the `checksum:` line was edited in each file.** No vendor content —
`detect`, `identity`, `patterns`, `defaults`, `capabilities`, `literal_blocks`,
`comment_prefixes` — was touched, which the diff shows as exactly one changed
line per file.

The two deprecated packs were corrected as well, though only ACTIVE packs are
gated. A deprecated pack is a **rollback target** (D51): pointing the activation
record back at it makes it the pack in force again, and it has to verify then.
A superseded pack is not a dead file.

### Enforcement

Verification runs on load for every ACTIVE pack, and **fails closed**. Skipping
the offending pack and carrying on would leave a platform silently unparsed,
which reads downstream as a device with no security configuration rather than as
an integrity failure — a mis-parse arriving dressed as a fact.

DRAFT and VALIDATED packs are not gated. A draft is still being edited, and
demanding a stamp on every intermediate save would make the stamp a formality
rather than an attestation.

`PackChecksumError` is deliberately **not** a `PackLoadError`. An unverifiable
pack is an integrity event, and collapsing it into "could not read the file"
would send whoever is on call looking at YAML syntax.

## D46 — versions are numbers, and only one pack is in force (DEF-11)

`discover_packs` sorted on `pack_version` as a **string**, so `1.0.10` sorted
below `1.0.9` and `1.2.0` above `1.10.0`. `find_pack` then returned the first
match, making load order the selection mechanism. Correct until now only by
luck — the shipped versions are `1.0.0`, `1.0.1`, `1.1.0`. P11 mints versions
programmatically and reaches `.10` in an afternoon.

Fixed with a numeric tuple key. And competing ACTIVE packs are now an **error**
rather than a race resolved by ordering: silently selecting the higher-sorting
version would mean the fleet is parsed by a pack nobody chose, and an operator's
evidence would cite a `pack_version` they never activated.

## D45 — two roots, and `packs/trained/` is finally read (DEF-12)

`TRAINED_ROOT` was defined at P3 and referenced by nothing; `discover_packs`
only ever read `packs/builtin/`. A pack compiled into `packs/trained/` would
have been written successfully and never loaded — a deferred capability
degrading silently instead of raising.

Both roots are now loaded, and kept apart on purpose:

```
packs/builtin/   what a person wrote and a reviewer read
packs/trained/   what this deployment learned, generated at runtime
```

Generated packs are gitignored. Committing them would blur the one distinction
the two roots exist to keep.

## D51 — a two-step lifecycle, and nothing reviewed is ever mutated

DRAFT → VALIDATED → ACTIVE, with activation an explicit, admin-only, separate
call. The gap between compiling and trusting is where DEVELOPER_GUIDE.md §4's *"show it to
the administrator, allow editing before activation"* lives, and where P13 will
render the generated regex for review. An endpoint that compiled-and-activated in
one request would delete that review while looking like a convenience.

Validation is a real gate: `validate()` runs `validate_patterns()` — the check
`data-contracts.md` §6 has named as *"the validation the P11 workflow gates
activation on"* since P6 — and `activate()` refuses any pack that is not
VALIDATED.

### Editing is required, and re-validation is not optional

An administrator may replace the generated regex. The edit is then checked: it
must be anchored, it must compile, it must not contain `.*`, `.+` or a nested
quantifier, and **it must still match the line it was confirmed from**.

That last check is the one that would otherwise fail silently. A hand-edited
regex which no longer matches the confirmed line has stopped meaning what the
human agreed to, and nothing downstream would notice — the pack would simply
produce no field, and the confirmation would look successful forever.

The audit payload records `pattern_edited` and the pattern itself. Which regex
was activated must be attestable: it is not a device fact, but it is what will
read every future configuration of that platform.

### The activation record

Activation never edits a reviewed file. A deployment that rewrote
`packs/builtin/*.yaml` at runtime would leave the repository dirty, invalidate
those packs' checksums, and destroy the one clean answer to "what did we ship".

So the trained root carries `activation.yaml`:

```
a pack file's `status:` is what it SHIPPED as
the activation record is what this deployment has since decided
```

The record wins where it has an opinion. That keeps "one ACTIVE pack per
platform" true without duplicating a pack and without editing anything. A record
naming a version that is not on disk **refuses to load** rather than falling back
— falling back would parse the fleet with a pack the operator did not choose,
which is D46's failure arriving by a different route.

Deleting the record falls back to the shipped statuses, which is a predictable
failure mode: a fresh checkout parses exactly as the packs in git say it should.

**Rollback is the same mechanism run backwards.** Because no pack file was ever
modified, pointing the record at an earlier version restores the earlier parse
behaviour byte for byte. `PACK_ROLLED_BACK` has been in the enum since P1 and
now fires.

## Consequences

`clear_pack_cache()` — added at P3 with a comment saying P11 would need it — is
called on activation and rollback, so the next file ingested in the same process
is parsed by the pack activated a moment ago. The Concept Report's *"No
redeployment, no restart"* is now literally true and tested over HTTP.

**Still not verified:** rulepack checksums, because `Rulepack` deliberately has
no checksum field (D17). That contract was written *without* one specifically so
this defect would not be duplicated into a second place before it was fixed in
the first. Now that a working convention exists, giving `Rulepack` a verifiable
checksum is a reasonable future change — and it is a different ADR, made for
`rules/`, which P11 did not touch.
