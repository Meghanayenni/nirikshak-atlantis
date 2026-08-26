# ADR 0007 — Audit hash chain on SQLite

- **Status:** Accepted
- **Date:** 2026-08-26
- **Phase:** P2
- **Affects:** `api/db/`, `api/audit/`, `api/routers/audit.py`, `scripts/`

## Context

`DEVELOPER_GUIDE.md` §9 requires an audit trail over AI suggestions, administrator
corrections, vendor pack changes and audit results, with hash chaining for
integrity. P1 defined the `AuditRecord` contract and its per-record invariant;
P2 is the storage, linking and verification built on it.

## Decision

A three-table SQLite schema with an append-only, hash-linked log. Standard
library `sqlite3` only — no ORM, no migration framework, no distributed ledger.

### Schema

| Table | Purpose |
| --- | --- |
| `audit_log` | The chain. 13 columns, every one hashed or structurally verified. |
| `audit_chain_head` | Singleton. Detects deletion of the chain's tail, which the links alone cannot. |
| `schema_migrations` | Applied versions with the checksum of each file as applied. |

Three schema choices are worth recording:

**No unhashed metadata column.** A `written_at` column was considered and
rejected. Any column outside the hash is a place to record something untrue
without detection, so there is none.

**The `model` CHECK constraint.**
`CHECK (actor_type <> 'model' OR action = 'ai_suggested')` repeats Rule 1 in
SQL. The Pydantic contract already enforces it; repeating it here means a direct
`INSERT` through `sqlite3`, bypassing the application entirely, still cannot
record a model issuing a verdict.

**Append-only triggers.** `UPDATE` and `DELETE` on `audit_log` raise at the
database. An attacker must `DROP TRIGGER` first, and verification reports a
missing trigger — so the attempt leaves a mark even when it succeeds.

### Hashing

```
payload_hash = SHA256(canonical_json(payload))
entry_hash   = SHA256(canonical_json({seq, timestamp, actor, action,
                                      subject, payload_hash, prev_hash}))
```

Canonical JSON is `sort_keys=True`, `separators=(",", ":")`,
`ensure_ascii=False`, `allow_nan=False`, encoded UTF-8. Because
`ensure_ascii=False` emits characters rather than escapes, the encode step is
what fixes the byte sequence.

The database stores `payload_json` as the exact canonical string that was
hashed. Verification rehashes **that stored string**, not a re-serialised
object, so no future change in Python's JSON behaviour can perturb a historical
hash.

`hash_algo` is stored but **not** hashed, and the verifier takes its expected
algorithm from configuration rather than from the row — otherwise a downgrade
would be self-authorising. The column exists so decision R17 can adopt a keyed
digest by migration instead of by rewriting history.

### Append

One transaction per record, opened with `BEGIN IMMEDIATE`:

```
BEGIN IMMEDIATE → read head → compute hashes → INSERT → upsert head → COMMIT
```

`IMMEDIATE` rather than SQLite's default deferred transaction is not incidental.
With a deferred transaction two writers can both read the same head, both
compute the same next `seq`, and one discovers the collision only at `INSERT` —
after doing all its work.

The insert and the head update share the transaction, so an interrupted append
leaves either both or neither. The chain is inherently serial — each record's
`prev_hash` depends on its predecessor — so an in-process writer lock is the
correct shape, not a scalability compromise.

Pragmas: `journal_mode=WAL` so readers never block the writer,
`synchronous=FULL` because a log that loses its most recent records to a power
failure is not an audit log, `busy_timeout=5000`, `foreign_keys=ON`.

### Migrations

Numbered `.sql` files, forward-only, one transaction each, checksum recorded and
re-verified at startup. An edited already-applied migration **refuses startup**:
silent schema drift beneath an integrity mechanism is worse than downtime.

`Connection.executescript` could not be used — verified, not assumed: it issues
an implicit `COMMIT` before running, which would silently end the enclosing
transaction and cost migrations their atomicity. Splitting on `;` is equally
wrong because trigger bodies contain semicolons, so statements are accumulated
until `sqlite3.complete_statement` reports one complete.

### Reconciliation after an interrupted write

Head-versus-log mismatches are treated **asymmetrically on purpose**:

| Condition | Action |
| --- | --- |
| Head lags the log | Rebuild the head forward — the evidence still exists |
| Head is ahead of the log | **Refuse.** Records are missing, and rebuilding backwards would erase the only signal they existed |

### Verification and failure handling

`verify_chain` is a pure function over a connection with no FastAPI import: an
integrity check that can only be run through the interface it polices is not
much of a check. `scripts/verify_audit_chain.py` is the authority; the API
endpoint calls the identical function.

On failure: never auto-repair, never delete. Appends continue, because refusing
to write would lose further evidence and hand an attacker a denial of service.
Reports state the integrity result and the first failing seq. CLI exit codes are
0 clean, 1 failed, 2 unreadable.

### Payload minimisation

The chain records **that** something happened and to what, referencing artefacts
by identifier and hash rather than embedding them. `file_ingested` stores a file
id, name, SHA-256, size and line count — never contents. `ai_suggested` stores
the cluster, model id and the three candidate fields — never the configuration
line, which is referenced through `training_example_id`.

This satisfies `DEVELOPER_GUIDE.md` §9's requirement to treat configuration files as
sensitive, and keeps the chain small enough to verify in full, routinely.

## Consequences

AI suggestions stay distinguishable from decisions by two independent signals —
the `action` and the `actor_type` — both enforced in the contract and in SQL.

The audit layer may not import `api/comply/`, `api/learn/` or `api/parse/`,
asserted by `tests/architecture/test_import_rules.py`. It records events; it
does not judge them.

The limits of this mechanism are documented separately in **ADR 0008**, and two
tamper fixtures assert them.
