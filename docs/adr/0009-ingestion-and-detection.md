# ADR 0009 — Configuration ingestion and vendor detection

- **Status:** Accepted
- **Date:** 2026-08-27
- **Phase:** P3
- **Decisions:** D3 (identity patterns), D4 (split databases), D5 (FILE_REJECTED)

## Context

P3 is the first phase that touches real configuration files. It answers three
questions — what file is this, what platform is it, what are its lines — and
deliberately nothing else. No parsing of security fields, no canonical model, no
verdicts, no network.

## Three measured findings that shaped the design

These were run against CPython 3.11 before the design was fixed, not assumed.

### F1 — `str.splitlines()` disagrees with an operator's editor

Python splits on nine characters beyond CR, LF and CRLF: U+000B, U+000C,
U+000D, U+001C, U+001D, U+001E, U+0085, U+2028, U+2029. A banner containing a
vertical tab — plausible in a copy-pasted MOTD — reports five lines where an
editor shows three.

```
"hostname r1\n banner motd ^C\x0bWARNING\x0c ... ^C\n ip ssh version 2"
  str.splitlines()        -> 5 lines
  re.split(r"\r\n|\r|\n") -> 3 lines
```

Every citation NIRIKSHAK produces names a line number. Numbers that disagree
with the operator's editor make every citation in every report quietly wrong,
and nothing surfaces the error until somebody checks by hand.

**Decision:** `api/ingest/lines.split_lines` is the only line splitter.
`tests/architecture/test_ingest_boundaries.py` detects `.splitlines()` calls by
AST across `api/` and fails on any not listed in `SPLITLINES_EXEMPT` with a
reason. Two exemptions exist today: splitting a pydantic exception message for
display, and splitting SQL migration text. Neither produces an evidence line
number, and a companion test fails if an exemption goes stale.

### F2 — a NUL byte does not mean binary

| Case | NUL | decodes UTF-8 | printable |
| --- | --- | --- | --- |
| utf-8 config | no | yes | 100% |
| **utf-16 config** | **yes** | no | 46% |
| PNG header | yes | no | 69% |
| **ELF header** | yes | **yes** | 8% |
| gzip | yes | no | 0% |

Neither signal works alone: a UTF-16 configuration is full of NULs, and an ELF
header decodes as UTF-8 without complaint. The discriminator that separates
every case is the **printable ratio of the decoded text**.

**Decision:** BOM sniff first (so UTF-16/32 are decoded rather than refused for
their NULs), then decode, then a printable-ratio check with a 0.90 threshold.
A stray leading U+FEFF is stripped after decoding — it would otherwise become
part of line 1's text and change that line's hash and every citation of it.

### F3 — the trailing newline

`"a\nb\n"` is two lines, not three. `"a\nb\n\n"` is three. `""` is zero.
Getting this wrong shifts the count by one on almost every real file.

## Vendor detection — two thresholds

Deterministic and data-driven, reading the `detect` signatures already defined
by the `VendorPack` contract. No model, no heuristic, no vendor names in code.

```
score  = Σ weights of matching signatures
margin = best.score − runner_up.score

DETECTED  when score >= 0.60 and margin >= 0.25
UNKNOWN   otherwise, with a reason
```

**Why two thresholds.** A single "highest score wins" rule fails in two ways
that deserve different answers. `min_score` catches thin evidence — a file that
barely resembles anything known. `min_margin` catches ambiguity — a file that
resembles Cisco IOS and Arista EOS equally, which happens because the syntaxes
genuinely overlap. Both yield UNKNOWN, but the recorded reason differs, and the
second tells us the signature set needs a *discriminating* pattern rather than
more patterns. Collapsing them would mean confidently picking the winner of a
coin flip.

The `DetectionResult` contract enforces the abstention: a non-DETECTED outcome
that names a vendor cannot be constructed, and a DETECTED outcome without its
score cannot either.

**Detection carries evidence** — which signatures matched, at which lines, with
the raw text. Both "why did you think this was Cisco?" and "why did you refuse
to say?" are answerable from the record.

## Detection-only packs

P3 ships packs with `detect` and `identity` populated and `patterns: []`. That
is an honest state rather than a placeholder: the platform is recognised, device
identity is read, and every canonical security field stays UNKNOWN because
nothing yet claims to parse one. It also makes the unsupported-vendor test case
natural instead of contrived.

## Device identity — decision D3

An additive `identity:` section on `VendorPack`, reusing `MatchSpec` and
`CaptureSpec` rather than inventing a parallel schema. Each field is a
`Field[str]`, so it carries evidence and abstains independently: a configuration
with a hostname but no serial produces one PRESENT field and one UNKNOWN, never
an invented serial. No pack means no identity — an UNKNOWN platform yields
UNKNOWN identity, because there is nothing to say where to look.

## Line cache — one structure, three jobs

```
config_line   (file_id, line_number) -> line_sha256      position -> content
line_cache     line_sha256 -> text                       content -> text, once
```

**Deduplication:** a line on device 1 is stored once and referenced by device
400. **Evidence:** any citation resolves exactly without opening the blob.
**Cache:** P4 attaches parse results to `line_sha256`, so a repeated line is
parsed once across the fleet. `occurrence_count` is incidentally the raw
material for P12's peer-baseline analysis.

## Storage — decision D4

Two databases. `nirikshak.db` holds configuration content; `nirikshak-audit.db`
holds the chain. This makes "the audit database contains no configuration
content" provable by opening the file rather than resting on payload discipline,
gives R12's role separation a boundary to attach to, and lets R11 encrypt the
operational store without touching the chain's verifiability.

Raw bytes live in a content-addressed blob store, **verbatim**. Secrets are
scrubbed before *inference* (P10), not before storage: redacting here would
destroy the evidence a finding depends on, since a report saying "your SNMP
community is weak" while showing `<redacted>` is not evidence. The blob store
and operational database are therefore the protection boundary, which is exactly
what R11 encrypts and R12 gates.

## Rejections — decision D5

A refusal is a first-class outcome. One unreadable file in fifty must not cost
the operator the other forty-nine, so the batch continues and the API returns a
per-file result. Refusals are audited as `FILE_REJECTED`, never as
`FILE_INGESTED` — recording a refusal as an ingestion would misdescribe what
happened.

## Consequences

`api/ingest/` may not import `api/comply/`, `api/normalise/`, `api/learn/` or
`api/remediate/`, and may not import any network module — `httpx`, `requests`,
`urllib`, `socket` and six others are asserted absent. "Do not silently send
configurations to external services" is not a rule anyone has to remember,
because there is nothing in the package to send them with.
