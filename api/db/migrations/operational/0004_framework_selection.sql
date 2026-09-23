-- NIRIKSHAK operational 0004 — which benchmarks an audit was scoped to
--
-- P17, ADR 0036. Problem Statement 26155 asks for evaluation against
-- user-selected benchmarks, and a selection changes WHICH RULES RAN. Without
-- this column a stored run records seven findings or three and gives a reader
-- no way to tell a narrowed scope from a device that produced fewer results.
--
-- Nullable, and NULL means "no framework filter" — NIRIKSHAK's own checks,
-- which is what every run before this migration was. Backfilling a value would
-- assert a selection nobody made.
--
-- A JSON array of framework identifiers, not a single value: the selection is a
-- set, and one column that could hold "nist" but not "nist and stig" would have
-- to grow a second time.
--
-- WHAT THIS IS NOT. It records the scope of the run, never a verdict and never
-- a control's text. The audit chain's payload is unchanged: counts,
-- identifiers and versions.

ALTER TABLE audit_run ADD COLUMN framework_selection TEXT;
