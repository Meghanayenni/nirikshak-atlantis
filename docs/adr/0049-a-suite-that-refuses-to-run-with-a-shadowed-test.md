# ADR 0049 — A suite that refuses to run with a shadowed test

- **Status:** Accepted
- **Date:** 2026-09-24
- **Phase:** P18
- **Decisions:** D126 (detect at collection time, from the source, and abort),
  D127 (inventory harmless cross-module repeats rather than forbidding them)
- **Affects:** `tests/conftest.py` (new),
  `tests/architecture/test_no_shadowed_tests.py` (new)

## The defect this closes

`test_junos_filter_extraction.py` defined
`test_a_term_cites_every_line_that_built_it` twice — once for the flat `set`
surface, once for the brace one. Python replaced the first with the second at
import, and the flat-form assertion stopped running. The suite reported one test
where two were written, and reported it green.

Ruff caught it, by luck of configuration rather than design. **pytest collected
it happily**, because by the time pytest sees a module the shadowed function no
longer exists.

**This is the worst class of defect available here.** Every other failure this
repository guards against is a wrong answer, and a wrong answer is visible. This
one is a question nobody asks any more, with nothing left to show it was ever
asked. At 2,400 tests, one going quiet costs nothing detectable.

## D126 — read the source, at collection time, and abort

Three properties, each forced by the shape of the problem.

**From the source, not the collected items.** A collection hook inspecting
`items` cannot see this: Python discarded the first definition at import, so
only one function object exists to collect. The check parses each collected
module's AST, which is the only place both definitions still exist.

**At collection time**, in `tests/conftest.py`, so it runs before any test does
and reports once at the top rather than as one failure among thousands.

**It aborts the session** rather than failing a single test —
`pytest.UsageError`, exit code 4, so CI fails. A suite that cannot say how many
of its assertions ran should not report a result at all. That is a stronger
response than this repository usually takes, and it is proportionate: every
other guard here protects a claim about the *system*, and this one protects the
claim that the guards ran.

### Scopes are checked separately

Module level and each class body are their own namespace. Two `test_same` in two
different classes shadow nothing, and flagging them would be the guard crying
wolf — a guard people learn to ignore protects nothing. Shadowing *inside* one
class body is caught, because the replacement there is just as silent.

The detector is made to fail on purpose against constructed sources: a shadowed
pair, a same-name-different-scope trio that must stay clean, a duplicate inside
a class, and an unparseable module. Without those,
`test_no_module_defines_a_test_name_twice` would pass just as happily if
`duplicate_test_names` always returned an empty list — which is the failure mode
it exists to catch, one level up. The argument is the same one this repository
already makes about its import detector and its contamination detector.

Verified end to end: a module with a duplicated test name aborts the run with
the offending name and exits 4.

## D127 — inventory cross-module repeats; do not forbid them

The one-off survey the brief asked for. **No module currently shadows
anything.** Four names appear in two modules each, and all four are harmless —
Python namespaces them separately and both run:

| Name | Modules |
| --- | --- |
| `test_discovery_is_ordered` | `test_rulepack_loading.py`, `test_snippet_library.py` |
| `test_no_calibrator_is_active` | `test_calibration.py`, `test_learn_boundaries.py` |
| `test_oversized_file_is_rejected` | `test_ingest_validate.py`, `test_ingestion.py` |
| `test_unknown_requires_a_reason` | `test_field_confidence.py`, `test_finding_snippet_training_audit.py` |

Each pair asks the same question at two levels — the unit contract and the
boundary that enforces it, or the model and the HTTP surface — which is
deliberate and worth keeping.

They are **pinned** rather than permitted silently, so the set is looked at
rather than assumed empty. The expectation is expected to change whenever a test
is added or renamed; updating it is a one-line edit and a glance at whether the
new pair is really two different questions rather than one asked twice.

## A small irony, kept

The first draft of the guard's own module defined a helper called
`test_modules()`. pytest collected it as a test and warned that it returned a
list instead of `None` — a helper masquerading as an assertion, which is a mild
version of exactly what this module is about. Renamed to `_modules()`, and the
reason is in its docstring.
