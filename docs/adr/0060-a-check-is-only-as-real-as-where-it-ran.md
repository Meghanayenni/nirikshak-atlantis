# ADR 0060 — A check is only as real as where it ran

- **Status:** Accepted
- **Date:** 2026-09-25
- **Phase:** P18
- **Decisions:** D149 (a manifest hash is taken from committed bytes, never
  from a working copy), D150 (verification that matters runs somewhere other
  than the machine that wrote the code, and nothing in it may hide a failure)
- **Affects:** `corpus/MANIFEST.yaml`

## What happened

The pre-submission audit ran the backend suite in a fresh clone at
`D:\nirikshak-clean` and reported **0 failures**. It had **8**. The command was
`pytest -q -rs`: `-rs` prints the summary of *skipped* tests, and the project's
`addopts = "-q"` suppresses the final count line, so the only failure evidence
was an `F` among the progress dots — and the check that read the log looked for
`FAILED` summary lines, which `-rs` does not print. Every run on the
development machine was genuinely clean. Every run in the clean clone was
reported through the same blind filter.

It was found in the next session by running the suite in the clean clone again
and reading the exit code, which said 1 while the filter said 0. **The
verification was only as good as the environment it ran in, and as the command
that read it.** This repository's entire argument is that its checks are real —
that a claim is backed by something that can fail. A check whose failures are
filtered out of the report is not one.

## What the eight were

| Failure | Cause | Resolution |
| --- | --- | --- |
| `test_every_checksum_matches` — `cisco/dev/edge-rtr-01.cfg` | The manifest recorded the sha256 of a **CRLF** copy on the development disk (`f1033267…`, 3,774 bytes, 110 CRs). The committed blob is LF (`c71b5f90…`, 3,664 bytes); `.gitattributes` checks out LF, so every fresh clone disagreed with the manifest. The development machine passed only because its working copy held CRLF bytes git's normalisation hid from `git status`. | **D149, this ADR.** The manifest records the committed bytes; the working copy was re-checked-out. |
| Six PDF-refusal tests | They run when PDF is unavailable, and assume "WeasyPrint installed, GTK absent". The README's Setup, until the audit, never installed WeasyPrint at all, so they met "WeasyPrint absent". | Setup now installs `[report]` (step 3b). |
| Two AI-refusal tests | They run when the model is unavailable, and assert the *weights-missing* refusal. On this machine the package was absent but the weights sat in a machine-wide Hugging Face cache, which produces a shorter message. | **Left unchanged** — see below. |

## D149 — hash what was committed

Every one of the 21 manifest entries was then checked against `git cat-file
blob HEAD:<path>`, not against this disk: **one** was wrong, and no working copy
of the other twenty differs from its blob. Every other record in the repository
that pins a corpus file's hash — the five label files' `file_sha256`, and the
interface fixture's device id for `rtr-core-01.cfg` — matches committed bytes.
The hashes that are not of corpus files do not share the failure mode: pack and
rulepack checksums normalise CRLF by convention, the STIG index pins a file
marked `-text`, and the CIS index pins a file never in the tree.

## The AI-refusal tests, and why they stay as they are

They already skip when `[ai]` is present; they are the refusal half of a pair.
Making them skip when it is absent would disable them in the only state they
exist to test. So the question was whether a reviewer who skips the optional
step 3c would see them fail. Measured, in the clean clone with the package
removed:

- home directory pointed at an empty folder — **a fresh machine**: all three
  refusal tests **pass**;
- this machine's real home, weights cached in `~/.cache/huggingface`: two fail.

The failure belongs to this machine's leftover state, the same lesson as the
checksum. A reviewer with the package absent but the weights cached from another
project would still meet it; a guard keyed on the weights rather than the
package would close that, and is recorded rather than made.

## D150 — where verification runs, and how it is read

Verification that decides readiness runs in a clone that has never been the
development tree, and its result is read from the exit code and the failure
list, never from a filter over a summary. The two facts this session added to
the record — a hash that only matched one disk, and a test that only failed on
one — were both invisible from the machine that produced them.
