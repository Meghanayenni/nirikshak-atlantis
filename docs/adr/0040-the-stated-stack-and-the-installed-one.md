# ADR 0040 — The stated stack and the installed one

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P17
- **Decisions:** D105 (remove a dependency nothing imports, and record it),
  D106 (the SBOM describes the lock file, not the machine), D107 (`pip-audit`
  gates `verify`, not `test`)
- **Affects:** `DEVELOPER_GUIDE.md` §11, `pyproject.toml`, `requirements.lock`,
  `Makefile`, `docs/openapi.json` (new), `docs/sbom.cdx.json` (new),
  `eval/report.py`, `README.md`

## Context

A reviewer comparing `DEVELOPER_GUIDE.md` §11 to `pyproject.toml` and to the imports
would have found a mismatch in both directions: technologies named in the stack
that nothing uses, and dependencies installed that nothing imports.

## D105 — remove what nothing imports, and say so

Four runtime dependencies were declared and **imported nowhere**:

| Dependency | Why it was there | Why it is not |
| --- | --- | --- |
| `textfsm` | the original parsing plan | ADR 0004 replaced it with this project's own block parser at P0 — TextFSM targets `show`-command output and the corpus holds running-configs |
| `ntc-templates` | TextFSM template library | same, and it pulls TextFSM in |
| `jsonpath-ng` | the `jsonpath` match primitive | declared in `MatchType` and refused by the pack engine; no corpus file is that shape |
| `cryptography` | presumed needed for password hashing | it never was. `api/security/passwords.py` uses `hashlib.scrypt`, and `test_no_invented_cryptography` asserts that choice *"adds no new dependency"* — which this declaration quietly contradicted |

`pip show` confirms none was required by anything but `nirikshak` itself, so
removing them takes `future` (a TextFSM dependency) with them and touches
nothing else. Five entries left `requirements.lock`.

`MatchType.TEXTFSM` and `MatchType.JSONPATH` **stay in the contract**. They are
declared and deliberately unimplemented: the pack engine refuses each by name
and explains why. That is what a deferred capability looks like here — it
raises, it does not degrade — and it costs nothing, whereas an installed package
nobody imports is supply-chain surface bought for a comment.

**Ollama** was the other direction. It was never a dependency and is imported
nowhere; §11 listed it as the local LLM. No local LLM is used or needed — the
similarity layer is sentence-transformers plus FAISS, it proposes and never
decides, and Rule 1 leaves a generative model nothing to do. Listing it
described an intention as a component.

§11 now says what is installed, and names the three removals with their reasons,
because *"do not introduce a new major technology without explaining why"* has an
obvious mirror image that was not written down.

## D106 — the SBOM describes the lock file, not the machine

`cyclonedx-py environment .venv` produced **119 components**, including
`pip-audit` and `cyclonedx-bom` themselves. A bill of materials for one
developer's laptop is not a bill of materials for a product.

`cyclonedx-py requirements requirements.lock` produces **42**, which is the
closure this project declares. `docs/sbom.cdx.json` is that, CycloneDX 1.6, with
`--output-reproducible` so it diffs cleanly rather than churning a timestamp on
every regeneration.

It also served as the check on D105: the first environment SBOM still listed all
four removed packages, because they were removed from the manifests and not
uninstalled from the venv. The lock-file SBOM lists none of them.

`docs/openapi.json` is exported alongside it — 28 paths, free from FastAPI, and
it makes the architecture document's claims about the HTTP surface checkable
against something generated rather than written.

## D107 — `pip-audit` gates `verify`, not `test`

The brief asked for pip-audit "in the test target". It is in `make verify`
instead, and the reason is what pip-audit found on its first run:

```
starlette 0.46.2   7 advisories
lxml      5.4.0    1 advisory
pytest    8.4.2    1 advisory
```

**Nine known advisories in locked third-party dependencies.** None is a defect
in this repository, and none is fixable without a version bump this change is
not the place for — `starlette 0.47+` needs a FastAPI major bump, which is its
own piece of work with its own testing.

Wiring that into `make test` would make every unrelated change look broken and
teach everybody to ignore a red build, which is how a security gate becomes
decoration. So `make test` runs tests, `make audit` exits non-zero on an
advisory, and `make verify` runs lint, tests and the supply chain together — the
target CI should use.

**The nine advisories are an open item**, recorded here and in `README.md`
rather than silenced. A finding nobody is allowed to see is worth the same as no
finding at all.

The tooling is its own `[supply]` extra rather than part of `[dev]`: it belongs
to CI and `make verify`, not to the first install every contributor does, and
the 8 GB target is easier to keep honest with two fewer packages on the common
path.

## Three stale claims, corrected in the same pass

Found while checking the stack against reality, and all of the same kind — a
sentence that was true when written and had not been revisited:

- `eval/report.py` printed *"ACL analysis accuracy — not measured: the corpus
  contains no access list"* and *"remediation coverage — not measured: the
  vetted snippet library is empty."* Five access lists are analysed and twenty
  snippets ship. Both lines now say **why** the thing is unmeasured — no
  independently written lists, no ground truth about them, no measured
  remediable rate — which is still "not measured" and is no longer false about
  the inputs.
- `README.md` said the snippet library is empty and referred to "the six gaps"
  in a document listing eight.
- Two docstrings in `api/analyse/` described a corpus with no access lists.

The evaluation report is generated, so that line had been printed into every
regeneration since the extractor landed. **A refusal has to be accurate about
what it is refusing**, or it stops being an honest abstention and becomes
another stale claim that happens to point the safe way.
