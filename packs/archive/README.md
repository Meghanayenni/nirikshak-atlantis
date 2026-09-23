# `packs/archive/` — superseded trained packs, kept so a finding can still name them

**Nothing here is loadable, and that is the point.** These files are a durable
copy of vendor packs this deployment compiled at runtime and later removed. They
exist because `audit_run.pack_versions` points at a pack *version*, and a stored
finding that cannot resolve its version has lost the property the field exists to
provide (DEF-18, ADR 0030).

## Why this directory is not a pack root

`api/ingest/packs.py` searches `PACK_ROOTS` — `packs/builtin/` and
`packs/trained/`. This directory is in neither, and
`tests/unit/test_pack_archive.py` asserts it stays that way.

Every file here still carries `status: active` as it was written. Copying one
back under `packs/trained/` would give its platform two active versions and
`active_packs()` would raise `DuplicateActivePackError` — correctly (decision
D46). **Do not restore these by copying.** Making a superseded version resolvable
without being activatable is a change to how pack storage is organised, and it is
still open.

The deployment's activation record is preserved as
`activation-record-as-found.yaml` rather than `activation.yaml`, deliberately: a
file with the loader's activation filename sitting beside loadable pack versions
is one mistaken `--root` away from activating a pack nobody chose.

## What is here

Ten pack files across three platforms, recovered outside the repository and
committed unmodified. Each still verifies against its own declared checksum, so
these are the bytes that ran, not a reconstruction.

| Platform | Versions | Cited by a stored audit run? |
| --- | --- | --- |
| `cisco/ios` | 1.1.1 – 1.1.6 | **1.1.5 — two runs** |
| `juniper/junos` | 1.0.1 – 1.0.3 | no |
| `arista/eos` | 1.0.2 | no |

Only `cisco_ios/1.1.5.yaml` answers an orphaned citation today. The other nine
are kept because the recovery was opportunistic and a second chance at it is not
guaranteed.

## These files contain the contamination that caused their removal

`cisco_ios` 1.1.4, 1.1.5 and 1.1.6 carry `p-weak-ciphers-admin-002` and `-003`,
compiled from `corpus/cisco/eval/edge-rtr-11.cfg` — an evaluation-split file.
That is why the trained packs were reset (decision D67, ADR 0024), and it is
preserved here rather than cleaned, because an archive that edits what it
archives is not evidence of anything.

This does not contaminate any measurement. Contamination is a pattern authored
from evaluation data being **active** when the parser is scored; these are
unreachable by the loader, and the evaluation harness reads
`load_active_packs()`. The corpus lines quoted here were already committed in
`corpus/`.
