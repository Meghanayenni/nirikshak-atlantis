# ADR 0031 — A durable archive for superseded packs

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P17
- **Decisions:** D81 (commit the recovered packs to a directory the activation
  scan cannot reach), D82 (archive the contamination unedited)
- **Defects:** DEF-18 (mitigated, not closed)
- **Affects:** `packs/archive/` (new), `tests/unit/test_pack_archive.py` (new)

## Context

ADR 0030 recorded that `cisco/ios 1.1.5` is cited by two stored audit runs and no
longer exists, and noted — as a matter of luck — that the deleted files still
existed in a previous session's scratch directory.

That sentence was the actual emergency. A defect report that depends on a
temporary directory for its evidence is one reboot from becoming unverifiable,
and the thing being lost is not a pack: it is the only way two stored findings
can name what read them.

Ten pack files were recovered. Each still verifies against its own declared
checksum, so what is committed here is the bytes that ran, not a reconstruction.

| Platform | Versions recovered | Cited by a stored run |
| --- | --- | --- |
| `cisco/ios` | 1.1.1 – 1.1.6 | **1.1.5 — two runs** |
| `juniper/junos` | 1.0.1 – 1.0.3 | none |
| `arista/eos` | 1.0.2 | none |

Only one of the ten answers an orphaned citation. The other nine are kept because
the recovery was opportunistic and there will not be a second one.

## D81 — commit them, outside every pack root

`packs/archive/` is in the repository and is **not** in `PACK_ROOTS`.

Every archived file carries `status: active`, because that is what it was when it
was written. Restoring one under `packs/trained/` would give its platform two
active versions and `active_packs()` would raise `DuplicateActivePackError` —
correctly, per D46. So the archive is inert by construction rather than by
instruction, and `test_the_archive_is_not_a_pack_root` asserts containment rather
than inequality: `discover_packs` uses `rglob`, so an archive *nested* under a
pack root would be found just as surely as one named as a root.

The deployment's activation record is preserved as
`activation-record-as-found.yaml`. `active_packs(root=...)` reads `activation.yaml`
from whichever root it is given, and a file with that name sitting beside ten
loadable versions is one mistaken argument away from activating a pack nobody
chose.

**This directory is not gitignored, and that is the decision.** D67 reasoned that
deleting the trained packs was safe because `packs/trained/` is gitignored
deployment state. The reasoning was true of the repository and false of the
database beside it. An archive inheriting the same ignore rule would inherit the
same defect, so a test asserts `.gitignore` does not exclude it.

## D82 — archive the contamination, unedited

`cisco_ios` 1.1.4, 1.1.5 and 1.1.6 carry `p-weak-ciphers-admin-002` and `-003`,
compiled from `corpus/cisco/eval/edge-rtr-11.cfg`. Both example lines —
`ip ssh server algorithm encryption aes128-cbc` and
`ip ssh server algorithm mac hmac-sha1` — appear in that evaluation file and in
no development file. This is exactly the contamination D67 reset the packs for,
and it is committed here unchanged.

Editing it out was considered and rejected. An archive that cleans what it
archives is not evidence; the reason these versions were removed is part of what
a reader needs from them.

**It contaminates no measurement**, and the distinction is worth stating rather
than assuming. Contamination means a pattern authored from evaluation data being
*active* while the parser is scored. The evaluation harness reads
`load_active_packs()`, which cannot see this directory, and the corpus lines
quoted here were already committed under `corpus/`. What is new in the repository
is a pack file that quotes them, not the lines.

`test_no_trained_pack_quotes_an_evaluation_or_holdout_line` scans `packs/trained/`
and continues to. Extending it here would fail by design on files that exist to
record that failure.

## What this does not do

**DEF-18 stays open.** Nothing resolves a pack version through this directory.
`audit_run.pack_versions` still points into `packs/trained/`, and the two runs
citing `cisco/ios 1.1.5` still cannot name their pack *through the loader* — a
human can now open the file, which is strictly more than before and strictly less
than the fix.

The repair is an archive tier the loader knows about: a version resolvable for
provenance and not eligible for activation, which means a third pack status or a
separate resolution path, a decision about what `pack_versions` stores, and a
migration for rows that already point at a bare version string. That is its own
ADR. This one buys the time to write it.

A second, smaller thing surfaced while checking: `audit_run.pack_versions` stores
`{"cisco": "1.1.5"}` — keyed by **vendor**, not by `pack_id`. `cisco/ios` and a
future `cisco/nxos` would collide in that column. Recorded here because the
archive work is what made it visible; it belongs to the same repair.
