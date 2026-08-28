# ADR 0018 — The embedding model is an environment prerequisite

- **Status:** Accepted
- **Date:** 2026-08-28
- **Phase:** P10
- **Decision:** D40
- **Affects:** `api/learn/embedding.py`, `README.md`, developer setup
- **Precedent:** ADR 0006, which answered the same shape of problem for GTK

## Context

DEVELOPER_GUIDE.md §11 fixes the embedding model as `all-MiniLM-L6-v2` through
sentence-transformers. The package is a `pip` install; **the weights are not**.
They are fetched from the network on first use, and NIRIKSHAK is built to run
air-gapped (Rule 6) with `settings.airgap` hard-disabling outbound calls.

That is structurally identical to the problem ADR 0006 recorded at P0: a
specified component with an acquisition step `pip` cannot perform, discovered
early enough to answer deliberately rather than the night before a demo.

## Probe

Read-only, at P10. No package installed, nothing downloaded.

```
sentence_transformers : ABSENT
torch                 : ABSENT
faiss                 : ABSENT
numpy                 : ABSENT
~/.cache/huggingface  : exists (no all-MiniLM-L6-v2)
airgap default        : False
```

## Decision

Treat the model as a **documented environment prerequisite**, exactly as the GTK
runtime is for PDF rendering. Four consequences, and the last is the one that
matters most.

**No weights in the repository.** They are not committed, not vendored, not
checked into LFS. `test_no_model_weights_are_committed` scans the tree for
`.bin`, `.safetensors`, `.onnx`, `.pt`, `.pth`, `.ckpt` and `.h5` and fails if
one appears. A model in a git history is a large binary nobody reviews, and its
provenance becomes whoever ran the download.

**A live probe, not an assumption.** `availability()` checks for the package and
for local weights on every call, uncached — the stack can be installed while the
service is running, and a cached negative would keep reporting the absence of
something now present.

**Fail closed under airgap.** With `airgap` enabled the loader passes
`local_files_only=True`, so an absent model is a clean refusal rather than a
hanging fetch. The error says so: *"NIRIKSHAK is running with airgap enabled, so
it will not fetch them. Failing closed is the intended behaviour (Rule 6)."*

**No fallback, and no substitution.** `embed()` returns vectors from the named
model or raises `ModelUnavailableError`. There is no hash embedding, no
bag-of-words stand-in, and no alternative model. This is stricter than it may
look: a stand-in would produce rankings that *look* like model output and are
not, and an administrator confirming a mapping is trusting the ranking that put
it in front of them. A silently degraded suggestion is worse than no suggestion,
because the confirmation it produces enters a vendor pack permanently.

Substituting a different model would also change every score in the index and
would need its own ADR — it is not a decision the adapter may take.

## What this costs, and what it does not

**Nothing before P11 is blocked.** Clustering, indexing, ranking arithmetic and
the whole calibration module work with the `[ai]` extra uninstalled, and the test
suite runs on a machine that never installs one. The import of
`sentence_transformers` is lazy and lives inside a function, asserted by
`test_the_ml_import_is_lazy_so_the_suite_runs_without_the_extra`.

**Only embedding is blocked**, and it raises an error naming the package, the
model, the airgap state and this document.

## Setup

```bash
make install-ai          # the [ai] extra: sentence-transformers, torch, faiss, numpy
```

Then, once, on a machine with network access:

```python
from sentence_transformers import SentenceTransformer

SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
```

The weights land in the local cache and stay there. An air-gapped deployment
copies that cache directory rather than fetching, and `SENTENCE_TRANSFORMERS_HOME`
or `HF_HOME` points at it.

**Judge-environment note**, inherited from ADR 0006: whatever is chosen must be
reproducible from the README on a clean machine, because a reviewer may well try.
A download step is documentable. A vendored blob of weights is not reviewable,
and an improvised fallback is neither.

## Consequences

`/health` does not yet report model availability. It reports PDF availability and
the snippet library because both have operator-facing consequences today; the
model has none until P11 puts a training queue in front of a person. Adding it
belongs to the phase that gives it meaning.

The `[ai]` extra stays uninstalled in this repository. That is not an oversight
being tolerated — it is the state P10 was designed to work in, and every test
proves it.
