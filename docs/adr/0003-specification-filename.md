# ADR 0003 — Specification filename standardised

- **Status:** Accepted
- **Date:** 2026-08-26
- **Decision reference:** R3
- **Affects:** `docs/`

## Context

`DEVELOPER_GUIDE.md` names the product specification as
`docs/NIRIKSHAK_Concept_Report.pdf` in three places — lines 15, 484 and 503,
including §14 ("Before coding: read docs/NIRIKSHAK_Concept_Report.pdf") and §15
("The project specification is: docs/NIRIKSHAK_Concept_Report.pdf").

The file on disk was `docs/concept.pdf`.

Any contributor — or agent — following `DEVELOPER_GUIDE.md` literally would fail to find
the stated source of truth.

## Decision

Standardise on `docs/NIRIKSHAK_Concept_Report.pdf`. The file was renamed.

## Consequences

**No edit to `DEVELOPER_GUIDE.md` was required.** It already named the target path in all
three places, so renaming the file made the existing text correct rather than
demanding a change to a document that defines the project's constraints. That
was the deciding factor between renaming the file and editing the reference:
the constraint document stays byte-identical.

The PDF's **contents are unmodified** — this was a rename, not an edit. Verified
by checksum before and after:

```
sha256  330bbc3181fcf99c54e45176803de121c8386f3a07a1cca1f364cb6b630b5d76
```

The file was untracked at the time, so this was a filesystem rename; `git mv`
did not apply.

Documentation written from this point forward references the new name.
