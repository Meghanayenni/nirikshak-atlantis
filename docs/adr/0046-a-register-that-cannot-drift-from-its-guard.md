# ADR 0046 — A register that cannot drift from its guard

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D119 (keep the hand-maintained set, and fail when it disagrees
  with the register), D120 (derive every bound from the table)
- **Affects:** `tests/architecture/test_architecture_document.py`

## What went wrong

`OPEN_DEFECTS` read `{"DEF-3", "DEF-8"}` while DEF-16, DEF-17 and DEF-18
existed. Two open defects were unguarded and one fixed defect was still listed
as open — for three phases, with a green suite.

Two companion bounds had rotted the same way: `range(1, 16)` in the
completeness check and `range(1, 19)` in its converse, each a literal somebody
had to raise by hand and did not.

The constant's own docstring explained why it was hand-maintained, and the
reasoning was sound: *"the point of the test is to fail when reality and the
document diverge, and both sides being derived from the same text would make it
pass vacuously."* That argument is correct and it is not a defence against
drift. **A hand-maintained list beside a hand-maintained document will diverge;
the question is only whether anything notices.**

## D119 — keep the constant, and reconcile it

The fix is not a more careful list. `OPEN_DEFECTS` stays, for exactly the reason
its docstring gives, and `test_the_register_and_the_guard_agree` compares it to
the register parsed out of §9 and fails in **either** direction:

- a defect the document marks OPEN and the constant omits — *"opening one
  silently escapes the guard"*;
- a defect the constant lists and the document does not mark open — *"either it
  was fixed and the constant was not updated, or the row was softened without
  the fix"*.

Both sides remain deliberate. Divergence is now a build failure rather than a
thing somebody might spot, which is the only arrangement where a hand-kept list
cannot quietly rot.

The table is parsed into `DefectRow`, and `is_open` tests for `OPEN` anywhere in
the status cell. DEF-18's row reads `**OPEN** — evidence secured (ADR 0031)`,
and a status that qualifies itself must not read as closed: softening a row into
prose is precisely how an open defect would disappear.

## D120 — derive every bound from the table

`test_the_register_is_contiguous_from_one` asserts every number up to the
register's **own highest row** has an entry. A numbering gap fails; a number
somebody forgot to raise cannot exist, because there is no literal to raise.

`test_no_defect_is_listed_twice` is new — two rows for one defect is how a
register starts contradicting itself, and nothing had checked it.

`test_the_headline_count_matches_the_rows` checks the sentence above the table,
which is the part people actually read: *"Eighteen numbered defects. Three are
open."* Both halves are now checkable against the rows beneath them. A table
edited without its summary is the same drift one line higher.

## The guard can fail, and is shown failing

Five tests drive the parser over a doctored register containing a missing
number, a duplicated number, a bold open row and a plain fixed one — because
`test_the_register_and_the_guard_agree` would pass just as happily if
`_register_rows` silently skipped the emphasised rows, which is the failure it
exists to catch, one level up. This repository already makes that argument about
its import detector and its contamination detector.

Verified against the real document as well: softening DEF-16's row to
`Fixed (pretend)` fails three of these tests. Before this change it failed none.

## What this does not fix

The register is still prose in a document, and this checks its internal
consistency rather than its truth. Nothing here can tell that DEF-3 is genuinely
open — only that the document and the guard say the same thing about it, that
the numbering is complete, and that the summary matches the rows.

That is the limit of what a test over a document can do, and it is worth being
explicit about: the mechanism prevents *drift*, not *error*.
