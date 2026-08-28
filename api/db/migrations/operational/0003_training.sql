-- NIRIKSHAK operational 0003 — the training queue and the decisions made on it
--
-- P11, decision D49. Two tables, both in the OPERATIONAL database, neither
-- touching the audit chain.
--
-- THE BOUNDARY, restated where someone changing this file will read it:
--
--   operational database   configuration content, findings, users, ownership
--   audit database         identifiers, counts and hashes — nothing else
--
-- These tables hold configuration-derived text, so the operational database is
-- where they belong. The audit chain records THAT a mapping was confirmed, by
-- whom, for which field, and which pack version resulted. It does not record the
-- line. Decision D4 keeps the two in separate files precisely so "the audit
-- database contains no configuration content" is provable by opening it, and
-- P11 does not weaken that.
--
-- EVERY LINE STORED HERE IS SCRUBBED. `api/normalise/residue.py` redacts residue
-- as it leaves the parser (decision D12), and nothing in `api/train/` has a route
-- to `ConfigNode.raw_line`. The text in these tables is what may be shown to an
-- administrator and what may reach an embedding model; the unredacted line stays
-- in the blob store where evidence resolves it.

-- ---------------------------------------------------------------------------
-- The training queue (D49)
-- ---------------------------------------------------------------------------

-- Residue was previously computed during normalisation and discarded. That was
-- adequate while nobody looked at it; it is not adequate for a queue a person
-- works through over days, because clustering is fleet-wide by design — one
-- shape across thirty devices is one decision worth thirty — and recomputing it
-- would mean re-parsing every configuration each time the queue is opened.
--
-- The primary key is (file_id, line_number): the position of a line in a file
-- NIRIKSHAK has already ingested. That is durable across sessions and across
-- pack activations, which is what lets a decision made on Tuesday still refer to
-- the same line on Friday.
CREATE TABLE unknown_line (
    file_id       TEXT    NOT NULL REFERENCES config_file(file_id),
    line_number   INTEGER NOT NULL,

    text_scrubbed TEXT    NOT NULL,   -- post-redaction; never the raw line
    signature     TEXT    NOT NULL,   -- token shape, from api/learn/signature.py
    cluster_id    TEXT    NOT NULL,   -- derived from the signature, stable across runs
    block_path    TEXT    NOT NULL DEFAULT '[]',  -- JSON array of enclosing headers

    vendor        TEXT,
    os_family     TEXT,
    recorded_at   TEXT    NOT NULL,

    PRIMARY KEY (file_id, line_number),

    CHECK (line_number >= 1),
    CHECK (length(text_scrubbed) > 0)
);

CREATE INDEX idx_unknown_line_cluster ON unknown_line(cluster_id);
CREATE INDEX idx_unknown_line_file    ON unknown_line(file_id);

-- ---------------------------------------------------------------------------
-- The decisions (P1 contract `TrainingExample`)
-- ---------------------------------------------------------------------------

-- Where trust actually originates. A confidence score, however high, never
-- creates a trusted mapping; this row does.
--
-- The CHECK constraints below repeat invariants the Pydantic contract already
-- enforces. That repetition is deliberate and follows the audit chain's
-- precedent: a direct sqlite3 INSERT that bypasses the application must not be
-- able to record a decision the contract would have refused.
CREATE TABLE training_example (
    example_id        TEXT PRIMARY KEY,

    vendor            TEXT NOT NULL,
    os_family         TEXT NOT NULL,

    raw_line_scrubbed TEXT NOT NULL,          -- post-redaction, as the name says
    normalised_line   TEXT NOT NULL DEFAULT '',
    cluster_id        TEXT,

    field             TEXT,                   -- NULL when rejected
    value_semantics   TEXT,
    suggestions_json  TEXT NOT NULL DEFAULT '[]',
    outcome           TEXT NOT NULL,

    confirmed_by      TEXT NOT NULL,          -- the human who decided
    confirmed_at      TEXT,
    source            TEXT NOT NULL DEFAULT 'admin',
    audit_seq         INTEGER,

    CHECK (length(confirmed_by) > 0),
    CHECK (length(raw_line_scrubbed) > 0),

    -- Rule 3 at the storage layer: a line rejected as not security relevant
    -- cannot simultaneously name a canonical field.
    CHECK (outcome <> 'rejected_not_security_relevant' OR field IS NULL),

    -- The converse: every other outcome is a confirmation, and a confirmation
    -- without a field decided nothing.
    CHECK (outcome =  'rejected_not_security_relevant' OR field IS NOT NULL),

    -- Trust originates in a person. `source` exists so a future non-admin origin
    -- has somewhere to go, but nothing may claim to be a model decision: Rule 1
    -- means a model proposes and never confirms.
    CHECK (source IN ('admin', 'seed')),

    CHECK (outcome IN (
        'accepted_rank_1', 'accepted_rank_2', 'accepted_rank_3',
        'corrected', 'rejected_not_security_relevant'
    )),

    CHECK (audit_seq IS NULL OR audit_seq >= 0)
);

CREATE INDEX idx_training_example_cluster ON training_example(cluster_id);
CREATE INDEX idx_training_example_field   ON training_example(field);
CREATE INDEX idx_training_example_vendor  ON training_example(vendor, os_family);
