# ADR 0008 — The audit log is tamper-evident, not tamper-proof

- **Status:** Accepted
- **Date:** 2026-08-26
- **Decision reference:** R17 (accepted as a future extension)
- **Affects:** every description of the audit chain, in code, docs, UI and reports

## Context

A hash chain is commonly described as making a log "tamper-proof". That claim is
wrong for an unkeyed chain, and an audit tool that overstates its own guarantees
is worse than one that states them plainly — an auditor who later discovers the
gap has reason to distrust everything else the tool says.

## Decision

**Describe the P2 audit log as tamper-EVIDENT. Never as tamper-proof.**

The word "tamper-proof" must not appear in code, documentation, interface or
generated reports. A test asserts its absence from verification output.

## What the chain detects

| Threat | Detected by |
| --- | --- |
| Accidental corruption | `entry_hash` recomputation |
| A record's payload edited | `payload_hash` mismatch |
| A record's actor, action, subject or timestamp edited | `entry_hash` mismatch |
| A record deleted from the middle | `seq` gap and broken link |
| The most recent record deleted | `audit_chain_head` mismatch |
| Records reordered | `prev_hash` encodes order |
| A `prev_hash` rewritten | linkage walk |
| `UPDATE` or `DELETE` through the application | SQLite triggers |
| Append-only triggers dropped | trigger existence check |
| A record claiming a different hash algorithm | verifier's configured algorithm |

## What it does not detect

**An attacker with unrestricted database write access who recomputes the
complete unkeyed chain.** SHA-256 takes no secret. Anyone able to write to the
database and run the same public hash function can alter a record and rebuild
every subsequent link so the whole chain verifies.

**Deletion of the log together with the head row.** An empty database is
indistinguishable from a fresh installation. Nothing *inside* a database can
prove that something was once there.

**A plausible but false record appended through the application.** That is a
valid append; distinguishing it requires authenticating the actor, which is
decision R12, not this one.

## Two tests assert the non-detection

`tests/integration/test_audit_tamper.py` contains:

- `test_08_all_records_and_head_deleted_is_NOT_detected`
- `test_14_full_chain_rewrite_is_NOT_detected`

These are **not gaps in coverage**. They are the threat model written as
executable documentation. Writing a test that asserts a weakness feels wrong
until you consider the alternative: a suite that is silent about the limits and
a report that overstates them.

If a future change introduces a keyed digest or external anchoring, fixture 14
inverts from "passes" to "detected" — and that inversion is the evidence the
change did what it claimed.

## R17 — the future extension, not implemented in P2

Closing the recomputation gap requires a secret the attacker does not have, or
an anchor outside the database:

1. **HMAC-SHA256** with a key held outside the database.
2. **Signed checkpoints** over the head hash at intervals.
3. **External anchoring** — writing the head hash to append-only storage.

All three are key management, which is also what **R11** (encryption at rest)
turns on, so they belong in one conversation rather than two.

**P2 implements none of them, by decision.** What P2 does provide is the
`hash_algo` column, present from the first migration, so a keyed successor can
be adopted by migration rather than by rewriting history.

## Consequences

Language is part of the deliverable. Wherever the audit chain is described:

- **Say:** tamper-evident; detects modification, deletion, reordering and
  corruption; verification is independent of the interface.
- **Do not say:** tamper-proof, immutable, blockchain-backed, cryptographically
  guaranteed against all modification.

The verification report carries an explicit
`tamper_evident_not_tamper_proof: true` field, and the CLI prints the caveat on
a successful run — the moment an operator is most likely to over-read the
result.
