# ADR 0024 — Corpus registration, and a training loop that could contaminate its own evaluation

- **Status:** Accepted
- **Date:** 2026-09-23
- **Phase:** P15
- **Decisions:** D65 (register the uploaded corpus), D66 (a non-default SNMP
  community is a credential), D67 (reset trained packs rather than reclassify an
  evaluation file), D68 (complete the RFC 2606 allowlist)
- **Defects:** DEF-16 (opened — the confirmation loop does not check the split)
- **Affects:** `corpus/`, `tests/integration/test_corpus_policy.py`,
  `docs/SOURCING_BACKLOG.md`

## Context

Nine configurations had been uploaded to a running deployment and never
registered in `corpus/MANIFEST.yaml`. They were not missing from the repository
by accident — they had arrived through the *interface*, which stores uploads as
content-addressed blobs under `uploads/`, a path no corpus test inspects.

This was not bookkeeping. Running the corpus-policy suite before touching
anything produced two failures:

```
cisco/ios   p-idle-timeout-seconds-admin-001: 'exec-timeout 5 0' appears only in eval/holdout
juniper/junos p-logging-hosts-admin-001:      '…' appears in no development file
```

Eight admin-trained patterns were live in the active packs. **Not one of their
example lines appeared in any registered development file**, and one line
appeared only in the evaluation split.

## What the failure actually meant

`test_every_pack_example_comes_from_the_development_split` exists to catch a
pattern authored from data reserved for measuring it. It caught one — but the
mechanism was new. Tracing each example to the file it came from:

| Pattern | Authored from | Split the file was later assigned |
| --- | --- | --- |
| `p-weak-ciphers-admin-002`, `-003` | `edge-rtr-11.cfg` | **eval** |
| `p-idle-timeout-seconds-admin-001` | `dist-sw-03.cfg` | dev |
| `p-logging-hosts-admin-001…003` | `edge-rtr-02.conf` | dev |

Two patterns in the shipped Cisco pack had been compiled from a file whose whole
purpose is to be a regression fixture nobody authors from. Nobody did anything
wrong: an administrator uploaded a configuration through the interface, worked
the Needs-review queue, and confirmed what the lines meant. The loop did exactly
what it is built to do.

**That is the defect.** The confirmation loop has no notion of a corpus split. It
cannot have one for an arbitrary operator upload — most deployments have no
corpus at all — but in *this* repository, where the same files serve as
evaluation data, the loop can silently contaminate the measurement it is judged
by. Recorded as DEF-16 rather than fixed here: a guard belongs with the training
workflow and needs its own ADR.

## Decisions

**D65 — register all nine, with their declared provenance.** Seven are
byte-identical to what was uploaded; their recorded `sha256` equals the content
hash the ingestion layer had already computed, which is a free verification that
nothing was altered in transit. All are `source_type: synthetic`,
`is_real_world_data: false`.

`dc1-spine-01.cfg` is **Arista EOS**, not NX-OS. Its name pairs with
`dc1-leaf-01.cfg` as though they were one fabric from one vendor, and it was very
nearly registered on that inference; the file's own header declares
`vEOS, EOS-4.31.2F`. Recorded here because the next person will read the names
before the headers.

**D66 — a non-default SNMP community is a credential.** Two files carried
invented community strings (`NIRIKSHAK-SAMPLE-RO-COMMUNITY`). The sanitisation
test permits only `public` and `private`, and it is right to: a community string
is a shared secret whatever it was chosen for, while the two published defaults
are the *finding* rather than a secret. Both were rewritten to `public`. The
property each fixture exists to exercise — a v2c community present, so
`snmp_v3_only` must resolve FALSE — is unchanged.

The alternative, widening the test to exempt a placeholder prefix, was rejected.
It would weaken a sanitisation gate to admit data, and the gate's value is that
it does not negotiate.

**D67 — reset the trained packs; do not reclassify the evaluation file.** The
conflict was between the split `edge-rtr-11.cfg` is designed for and the patterns
already compiled from it. Moving it to `dev` would have resolved the failure and
destroyed the fixture: it exists to prove the pack learned IOS rather than
memorising `edge-rtr-01`, which only holds if nothing was authored from it.

`packs/trained/` is deployment state, not repository content — it is gitignored
for exactly this reason. The eight patterns existed on one machine. They were
removed, and the mappings are re-confirmed from development files. A backup was
kept outside the repository.

**D68 — complete the RFC 2606 allowlist.** Six files failed
`test_hostnames_use_reserved_domains` on `corp.example.net`. RFC 2606 §3 reserves
`example.com`, `example.net` **and** `example.org`; the allowlist named only the
first. The data satisfied the standard and the test did not. Completing the list
is a correction to the test, not a relaxation for the data — no domain outside
RFC 2606 is admitted.

## Consequences

The corpus gains its **first access lists and first interfaces**, across three
vendors:

- `edge-rtr-01.cfg` — a deliberately shadowed entry, with the file's own remark
  saying so: *"this deny is unreachable: the catch-all permit below already
  matches it"*
- `edge-rtr-11.cfg` — an overly permissive `permit ip any any`
- `branch-rtr-07.cfg` — a clean list, so the analyser can be shown finding nothing
- `dc1-leaf-01.cfg` — a CIDR-style NX-OS list applied to an interface with a
  direction
- `edge-rtr-02.conf` — 31 Juniper filter terms

### What this does and does not unblock

`SOURCING_BACKLOG` gap 1 asked for "development-split configurations containing
real access lists". That material now exists, and gap 1 is closed **as a sourcing
item**.

**The P7 analyser and P12 exposure ranking still produce nothing**, and it would
be wrong to claim otherwise. Verified directly after registration:

```
cisco/ios pack declares acl parsing?: False
CSM acls: 0   CSM interfaces: 0   residue: 57
```

No shipped pack declares an ACL or interface pattern, so neither reaches the
canonical model; the ACL lines sit in residue. Both features are now blocked on
**pattern authoring**, which is engineering work that can proceed from the
development split — not on sourcing, which needed material from outside the
repository. That is a real change in the nature of the blockage, and it is the
whole of the change.

### A second capability came unblocked, unasked

Peer-baseline outlier detection has abstained since P12 because every cohort held
fewer than the five devices a baseline needs. The registration took the Cisco IOS
cohort from four to nine, and **eight baselines are now computed, with zero
deviations.**

The zero is a result, not an abstention, and the response keeps the two apart: a
cohort below the floor carries an explanation and an outcome that is not
`compared`; these were compared and agreed. Two files are counted as *skipped*
rather than dropped — `dc1-leaf-01.cfg` is NX-OS and `core-rtr-01.conf` is
brace-nested JunOS, and neither has an active pack.

`test_every_cohort_is_below_the_floor_and_says_so` asserted the opposite and was
right for as long as it was true. It is replaced in this commit by
`test_baselines_are_established_now_that_a_cohort_clears_the_floor`, which pins
the new numbers the same way — a test written to be deleted, deleted by the change
that earned it.

### Detection does not discriminate brace-nested JunOS

`core-rtr-01.conf` is a legitimate JunOS configuration in brace-nested form, and
vendor detection does not identify it: the juniper signatures match the flat
`set` form only. It is recorded here rather than fixed, because the same class of
problem belongs with the NX-OS pack work, where discriminating signatures are the
central difficulty.

### Measurements moved, and were re-pinned rather than loosened

Labelling `edge-rtr-11.cfg` grew the scored population from four files to five.
The harness assertions are pinned at real values on purpose, so several changed:
Cisco field observations 26 → 39, correct 18, evidence scored 11 → 18, expected
FAIL verdicts 6 → 9. **`wrong_confident` stayed 0 and precision stayed 1.0** on a
population half as large again, which is the only part of that list worth
anything.

An evaluation file must carry a ground-truth label — `is_scoreable` is
`split == "eval"`, so an unlabelled one would silently shrink the measured
population while appearing to enlarge it. The label was authored by reading the
configuration, records `review_status: unreviewed`, and carries the same
pattern-author conflict flag the other Cisco labels do.

`corpus/PROVENANCE.md` was added because nine file headers cite it and it did not
exist. It records what each file declares about itself and states plainly that it
is not a bibliography: no document edition or locator was supplied, so nothing in
it is a verified citation.
