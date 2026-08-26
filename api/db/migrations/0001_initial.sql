-- NIRIKSHAK 0001 — audit hash chain
--
-- Three tables, two triggers. Every column in audit_log is either hashed or
-- verified structurally: there is deliberately no unhashed metadata column,
-- because a column outside the hash is a place to record something untrue
-- without detection.

CREATE TABLE schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    checksum    TEXT    NOT NULL,   -- sha256 of the .sql file as applied
    applied_at  TEXT    NOT NULL
);

CREATE TABLE audit_log (
    seq           INTEGER PRIMARY KEY,  -- explicit, monotonic, gapless
    timestamp     TEXT    NOT NULL,     -- canonical UTC form, byte-exact as hashed
    actor_type    TEXT    NOT NULL,
    actor_id      TEXT    NOT NULL,
    actor_role    TEXT,
    action        TEXT    NOT NULL,
    subject_kind  TEXT    NOT NULL,
    subject_id    TEXT    NOT NULL,
    payload_json  TEXT    NOT NULL,     -- canonical JSON string, byte-exact as hashed
    payload_hash  TEXT    NOT NULL,
    prev_hash     TEXT    NOT NULL,
    entry_hash    TEXT    NOT NULL UNIQUE,
    hash_algo     TEXT    NOT NULL DEFAULT 'sha256',

    CHECK (seq >= 0),
    CHECK (actor_type IN ('human', 'system', 'model')),

    -- CLAUDE.md Rule 1, enforced below Python. The Pydantic contract already
    -- rejects this; repeating it here means a direct sqlite3 INSERT that
    -- bypasses the application cannot record a model issuing a verdict either.
    CHECK (actor_type <> 'model' OR action = 'ai_suggested'),

    CHECK (length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(prev_hash)    = 64 AND prev_hash    NOT GLOB '*[^0-9a-f]*'),
    CHECK (length(entry_hash)   = 64 AND entry_hash   NOT GLOB '*[^0-9a-f]*')
);

-- Append-only, enforced by the database rather than by convention. An attacker
-- must DROP these first, and a missing trigger is itself reported by
-- verification — so the attempt leaves a mark even when it succeeds.
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

-- Singleton. Detects deletion of the chain's tail, which the links alone
-- cannot: removing the last record leaves a perfectly valid shorter chain.
CREATE TABLE audit_chain_head (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    last_seq     INTEGER NOT NULL,
    last_hash    TEXT    NOT NULL,
    record_count INTEGER NOT NULL,
    updated_at   TEXT    NOT NULL
);

-- Query indexes. None participates in any hash.
CREATE INDEX idx_audit_action    ON audit_log(action);
CREATE INDEX idx_audit_actor     ON audit_log(actor_id);
CREATE INDEX idx_audit_subject   ON audit_log(subject_kind, subject_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
