# ADR 0041 — A working deliverable described as blocked

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D108 (append a resolution to ADR 0006 rather than rewriting
  it), D109 (assert the positive path at both levels)
- **Affects:** `docs/adr/0006-weasyprint-gtk-probe.md`,
  `tests/unit/test_pdf_adapter.py`, `README.md`, `docs/architecture.md`

## What was wrong

Problem Statement 26155 names a per-device PDF report as a deliverable.
`README.md`, `docs/architecture.md`, the working brief and ADR 0006 all stated
that the GTK runtime was absent and the endpoint answered 503.

It is installed, through MSYS2, and the endpoint returns a PDF.

**Nothing was broken.** ADR 0006 deliberately kept the probe in code *"rather
than in prose so it re-runs on every request instead of describing a machine
from August"*, and that decision held perfectly: the probe re-ran, reported
availability correctly, and four tests carrying
`skipif(availability().available)` began skipping and kept skipping.

What failed is narrower and worth naming precisely. **A live probe protects the
behaviour. It does not protect the claims made about the behaviour.** The
documents asserted an environment fact as though it were permanent, and no test
asserted the positive path — so a working endpoint and three documents calling
it blocked could sit side by side indefinitely, with a green suite.

## D108 — append a resolution, do not rewrite the ADR

ADR 0006's reasoning was correct for the machine it probed. Editing it to say
the opposite would destroy the record of a decision that was right, and would
make the repository's own history unreliable in exactly the way its audit chain
exists to prevent elsewhere.

So the resolution is appended, in the same form the P8 resolution was appended,
and it says which parts changed (the machine, the probe's platform spelling) and
which did not (every decision: WeasyPrint only, no fallback, no HTML under a
`.pdf` name).

## D109 — assert the positive path at both levels

`render_pdf` returning `%PDF-` bytes, **and** the endpoint returning
`application/pdf` from a persisted run. Both `skipif(not available)`, which
remains correct — skipping where the runtime is genuinely absent is the right
behaviour, and the refusal tests still cover that machine.

Two levels rather than one because they fail separately: the endpoint could stop
calling the adapter, and the adapter could stop producing a PDF, and either
alone would leave the other green.

Three assertions were added at the adapter:

- the output starts with `%PDF-` **and ends with `%%EOF`**, because a truncated
  PDF opens as a damaged file rather than as an error;
- a long document renders **more than one page**, because a renderer that
  silently truncates is worse than one that fails — the document looks complete
  and is missing findings;
- the probe and the renderer **agree**, which is the check the `Dockerfile`
  build performs, applied to the host as well.

## Does this close the PS deliverable?

**As a document, yes.** `corpus/cisco/dev/sw-access-02.cfg` renders to seven A4
pages, 48,666 bytes: seven findings, two failures each citing the exact
configuration line it rests on, remediation where a vetted snippet resolves,
provenance naming the engine, rulepack, vendor pack and snippet library
versions, and five disclosures generated from what the report actually contains.
One device, one file, self-contained, printable.

**In one respect, no — and it is worth stating plainly.** The report does not
name the device. `Report` carries `config_file_id`, `vendor` and `os_family`
and nothing else about identity: no hostname, no model, no OS version, no
serial. An operator handed `report.pdf` for `8995304d…` cannot tell which router
it is without resolving a content hash by hand.

Those fields are all extracted, reach the canonical model and are stored in the
`device` table. They stop at the report boundary. PS 26155 names *"serial
numbers and hardware details"* as report deliverables and the report carries
none of them, which makes this a gap in the document rather than in the parser.

It is not fixed here, because it belongs with the identity work in ADR 0044 —
which decides what `serial` actually means for a running-config — rather than
with a correction about PDF. Recorded so it is a scheduled item and not a
discovery.

## The generalisable finding

Not "PDF works". The finding is that **a test which skips is a test which does
not test**, and that every skip guard in this suite deserves the same question:
*when the condition is met, does anything assert the happy path?*

That audit is ADR 0042, which covers all fourteen guards in the suite.
