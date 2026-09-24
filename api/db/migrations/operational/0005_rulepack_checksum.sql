-- NIRIKSHAK operational 0005 — the content of the rules that decided a run
--
-- P18, ADR 0056. `rulepack_version` is a label a person chooses, and from P6 to
-- P18 the label `1.0.0` named three different sets of rules. A report decides
-- whether to show today's control mappings beside a stored verdict by asking
-- whether the run was evaluated under the rules active now; comparing labels
-- could not answer that. This column records the rulepack's checksum, which
-- can.
--
-- Nullable, and NULL on every run before this migration: nobody recorded what
-- those rules were, and backfilling today's digest would assert they were
-- today's rules. A NULL never matches, so such a run renders without control
-- identifiers — visibly less, rather than quietly wrong.

ALTER TABLE audit_run ADD COLUMN rulepack_checksum TEXT;
