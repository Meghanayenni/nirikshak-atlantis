# ADR 0059 — Prose that cannot quietly expire

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D147 (six stale paragraphs corrected from derived figures, the
  superseded ones replaced by dated notes), D148 (load-bearing prose claims —
  absences first — are registered against predicates over the code; a general
  scanner is declined)
- **Affects:** `docs/architecture.md`, `docs/SOURCING_BACKLOG.md`, `docs/data-contracts.md`, `ui/src/types/api.ts`, `ui/src/test/helpers.tsx`, `ui/src/test/honesty.test.tsx`,
  `tests/architecture/test_prose_claims.py` (new)

## Context

Six paragraphs had drifted, and every one understated what exists:

| Where | Said | Derived at this commit |
| --- | --- | --- |
| `architecture.md` opening | "as it stands at P14" | four phases later; a phase label has no runtime source |
| `architecture.md` pipeline diagram | snippet lookup "(library is empty)" | 20 vetted snippets, 3 platforms |
| `architecture.md` §7 | brace-nested JunOS "is **not** read"; detection never reaches `core-rtr-01.conf` | detected as `juniper/junos`, read by pack 1.2.0, `PROTECT-RE` analysed |
| `architecture.md` §7 | NX-OS and brace-JunOS files "have no active pack" | all 19 non-holdout files have one |
| `SOURCING_BACKLOG.md` gap 1 | the analyser "still produces nothing" | 6 access lists across 3 dialects, 0 dropped; 5 shadowed, 4 redundant, 3 overly permissive |
| `SOURCING_BACKLOG.md` gap 5 | "two Cisco development devices"; "three cohorts of 4, 3 and 3", no baseline anywhere | 7 Cisco dev devices (6 IOS, 1 NX-OS); cohorts IOS 9, JunOS 5, EOS 4, NX-OS 1; 8 IOS baselines compared, 0 deviations |

Correcting them turned up three more of the same kind, fixed here too:
`data-contracts.md` headed a section "`frameworks` ships empty" and said "no rule
uses it" (all seven do); a comment in `ui/src/types/api.ts` and a fixture comment
said the snippet library "ships empty"; and a UI test's name rested on that
premise while its assertion — no command when no snippet exists — is still
right, so only the name changed. `SOURCING_BACKLOG`'s "Arista remains
detection-only" was checked and is accurate: the EOS pack reads identity but no
pattern, which is what `is_detection_only` means.

Every figure in the right-hand column was computed by running the pipeline
over the manifest's non-holdout files, not copied from the brief — whose own
numbers the previous session found stale within one commit.

## D147 — correct, and say what was corrected

The diagram now reads "(vetted library)" — no count to drift. The opening says
"as it is built". The superseded §7 paragraph and the gap-1 paragraph are
replaced by short dated notes, following the convention `SOURCING_BACKLOG.md`
already uses: a working document removes a false paragraph rather than leaving
it, and says in one line that it did.

Deriving the cohort figures surfaced one thing no document said: **the JunOS
cohort has five devices — above the floor — and produces no baseline row at
all**, because its pack reads no canonical field. The same holds for EOS at
four. That is now stated in both documents rather than left for a reader to
infer from an empty result.

## D148 — a registry, not a scanner

Can the prose be guarded? **Generally, no — not honestly.** The six drifted
sentences used six unrelated phrasings: a phase label, a word inside an ASCII
diagram, "is **not** read", "neither has an active pack", "still produces
nothing", a list of three numbers. A lexical net for absence-shaped prose would
have missed most of them and flagged many true sentences; a guard with that
false-negative rate would be decoration.

What is practical is the shape `test_skip_guards` already uses.
`tests/architecture/test_prose_claims.py` registers eleven load-bearing claims —
document, exact phrase, predicate over live code and data:

- **absences**: no pack declares `interface_roles` (two documents); no platform
  default or capability claim ships (two); JunOS and EOS read no canonical field;
- **figures written here**: every file has an active pack; the four cohort
  sizes; eight IOS baselines compared with no outlier; six ACLs, none dropped,
  5/4/3 observations; seven Cisco development devices; twenty snippets on three
  platforms.

While a phrase is in its document the predicate must hold, so the day a pack
declares a management interface the sentence saying none does fails the build
and names itself. A phrase that disappears must take its entry with it. A
separate check refuses a document dating itself by phase. Verified to fail by
changing "six access lists" to "seven" in the backlog.

**What it does not do:** find the next unregistered claim. A sentence written
tomorrow is unguarded until somebody registers it. That limit is recorded rather
than papered over with a scanner that would appear to close it.
