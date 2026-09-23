# ADR 0030 — Pack provenance after a re-stamp, and what the trained-pack reset destroyed

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P16
- **Decisions:** D80 (a re-stamp that changes no parsing content is acceptable
  and must be stated)
- **Defects:** DEF-18 (opened — deleting a trained pack destroys the provenance
  of every stored finding that cites it)
- **Affects:** nothing executable; this is a verification and a record

## Why this was checked

`cisco/ios` shipped as 1.2.0 with 1.1.0 deprecated and **re-stamped**, which
changed the bytes of a pack that stored findings already cite.
`FindingProvenance` records pack versions precisely so a verdict can name the
data that produced it. A version field that cannot be resolved back to the exact
pack is not reproducibility; it is a version number.

## What resolves

Every `(vendor, version)` pair cited by a stored `audit_run` on this deployment,
resolved against `packs/builtin/` and `packs/trained/`:

| Pack | Version | Result | Stored runs |
| --- | --- | --- | --- |
| `cisco/ios` | 1.1.0 | resolves, checksum verifies | 5 |
| `arista/eos` | 1.0.1 | resolves, checksum verifies | 2 |
| `juniper/junos` | 1.0.0 | resolves, checksum verifies | 1 |
| `cisco/ios` | **1.1.5** | **missing** | **2** |

## D80 — the re-stamp is acceptable, and here is exactly why

The diff between the committed 1.1.0 and the re-stamped one is two lines:

```
- status: active            + status: deprecated
- checksum: sha256:b9f20c…  + checksum: sha256:bb7c70…
```

**No parsing content changed.** Not a pattern, not a detect signature, not an
identity rule, not a literal block, not a comment prefix. The five stored runs
citing `cisco/ios 1.1.0` would parse their configurations identically today, and
the checksum verifies against the current bytes.

So byte-level identity with the file that ran is broken, and parse-behaviour
reproducibility is intact. That distinction is the whole claim, and it is worth
stating rather than reporting "verified" and moving on: a future change to 1.1.0
that touched a pattern would break something this one does not, and the
difference between the two is not visible in a checksum.

The alternative — leaving 1.1.0 marked `active` alongside 1.2.0 — was not
available. `active_packs()` raises `DuplicateActivePackError` when a platform has
two, deliberately (D46), rather than resolving the competition by sort order.

## DEF-18 — the reset destroyed provenance, and that was not noticed at the time

`cisco/ios 1.1.5` is cited by two stored audit runs and **no longer exists**. It
was a trained pack, removed by D67 when the contaminated admin-trained patterns
were reset in ADR 0024.

D67 was right about the contamination and wrong about the disposal. The reasoning
recorded there — that `packs/trained/` is gitignored deployment state existing on
one machine — is true of the *repository* and false of the *database beside it*:
`audit_run.pack_versions` points into that directory, so deleting a trained pack
silently orphans every finding produced by it. Two runs on this deployment can no
longer name the pack that read them.

Restoring is not a one-line fix, which is why this is a defect rather than a
patch. The archived file carries `status: active`, so putting it back under
`packs/trained/` would give `cisco/ios` two active versions and the loader would
fail closed — correctly. Making it resolvable means an **archive the activation
scan never reads**, which is a change to how pack storage is organised and
belongs in its own decision.

The archived versions still exist outside the repository in this session's
scratchpad (`trained-backup/`, eleven files), so nothing is irrecoverable yet.
That is luck rather than design, and it will not survive the machine.

### What this does not affect

No measurement. The P9 evaluation report regenerates from the corpus and the
*currently active* packs, and already re-pinned itself to `cisco/ios 1.2.0` when
it was re-run. No test, no metric and no shipped claim depends on the two
orphaned runs; they are audit history on one deployment.

## Consequence

A finding that cannot name the exact pack that read it is not reproducible, and
two such findings now exist. They are recorded here rather than quietly tolerated,
and DEF-18 stays open until pack storage distinguishes *archived* from *absent*.
