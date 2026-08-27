-- NIRIKSHAK operational 0002 — findings persistence and access control
--
-- Two additions, both in the OPERATIONAL database and neither touching the
-- audit chain (decisions D23, D25).
--
-- THE BOUNDARY, stated where someone changing this file will read it:
--
--   operational database   configuration content, findings, users, ownership
--   audit database         identifiers, counts and hashes — nothing else
--
-- The audit chain records THAT an audit ran, over which device, with which
-- rulepack, and how many findings of each verdict. It does not record what any
-- finding said, and this migration does not change that. Decision D4 keeps the
-- two in separate files precisely so "the audit database contains no
-- configuration content" is provable by opening it.
--
-- Nothing here alters, relaxes or re-keys the P2 chain. The chain's tables live
-- in the other database and are not referenced.

-- ---------------------------------------------------------------------------
-- Identity (D25)
-- ---------------------------------------------------------------------------

-- Passwords are stored ONLY as a scrypt hash carrying its own parameters.
-- There is deliberately no column a plaintext password could be written to.
CREATE TABLE app_user (
    user_id       TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,          -- scrypt$n$r$p$salt$key — never plaintext
    role          TEXT NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,

    CHECK (role IN ('user', 'admin')),
    CHECK (disabled IN (0, 1)),
    -- The stored value must carry the algorithm tag. A bare hex digest would be
    -- an unsalted fast hash, which is the mistake this CHECK exists to make
    -- impossible rather than merely discouraged.
    CHECK (password_hash LIKE 'scrypt$%'),
    CHECK (length(username) >= 3)
);

-- Who uploaded what. Ownership sits on the ingestion rather than on config_file,
-- because config_file is content-addressed: the same configuration uploaded by
-- two people is one file and two ingestions.
ALTER TABLE ingestion ADD COLUMN owner_id TEXT REFERENCES app_user(user_id);

CREATE INDEX idx_ingestion_owner ON ingestion(owner_id);

-- ---------------------------------------------------------------------------
-- Audit runs and findings (D23)
-- ---------------------------------------------------------------------------

-- One row per evaluation run. `audit_id` is the same identifier the AUDIT_RUN
-- entry in the audit chain carries as its subject, so the two can be joined
-- without correlating on timestamps.
CREATE TABLE audit_run (
    audit_id         TEXT PRIMARY KEY,
    device_id        TEXT NOT NULL,
    owner_id         TEXT REFERENCES app_user(user_id),

    engine_version   TEXT NOT NULL,
    rulepack_id      TEXT NOT NULL,
    rulepack_version TEXT NOT NULL,
    pack_versions    TEXT NOT NULL DEFAULT '{}',   -- JSON: vendor -> pack version

    rules_evaluated  INTEGER NOT NULL,
    count_pass       INTEGER NOT NULL DEFAULT 0,
    count_fail       INTEGER NOT NULL DEFAULT 0,
    count_unknown    INTEGER NOT NULL DEFAULT 0,
    count_na         INTEGER NOT NULL DEFAULT 0,

    evaluated_at     TEXT NOT NULL,

    CHECK (rules_evaluated >= 0)
);

CREATE INDEX idx_audit_run_device ON audit_run(device_id);
CREATE INDEX idx_audit_run_owner  ON audit_run(owner_id);

-- One row per finding. Minimum necessary metadata (D23): identifiers, verdict,
-- severity, the rendered expectation, and POINTERS to evidence.
--
-- `observed_value` is the one field carrying data derived from a configuration,
-- and it is required: a finding that cannot say what it saw is not reviewable.
-- It lives here, in the operational database, and never reaches the audit chain.
CREATE TABLE finding (
    finding_id      TEXT PRIMARY KEY,
    audit_id        TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    rule_id         TEXT NOT NULL,

    status          TEXT NOT NULL,
    base_severity   TEXT NOT NULL,

    observed_value  TEXT,                  -- JSON-encoded scalar or list
    observed_state  TEXT NOT NULL,
    confidence      REAL NOT NULL,
    confidence_method TEXT NOT NULL,

    expected        TEXT NOT NULL,
    absence_reason  TEXT,                  -- citation when the verdict rests on a default
    unknown_reason  TEXT,

    FOREIGN KEY (audit_id) REFERENCES audit_run(audit_id) ON DELETE CASCADE,
    CHECK (status IN ('pass', 'fail', 'unknown', 'not_applicable')),
    CHECK (base_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    -- Rule 3, in the schema: an abstention must say why it abstained, and a
    -- decided verdict must not pretend it did.
    CHECK ((status = 'unknown') = (unknown_reason IS NOT NULL)),
    CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE INDEX idx_finding_audit    ON finding(audit_id);
CREATE INDEX idx_finding_status   ON finding(audit_id, status);
CREATE INDEX idx_finding_device   ON finding(device_id);

-- Evidence as POINTERS, not copies (D23). (file_id, line_number) resolves
-- through config_line and line_cache to the exact stored text, so a report
-- quotes the operator's own file rather than a transcription that could drift
-- from it. Storing the raw line again would create a second copy that could
-- disagree with the first.
CREATE TABLE finding_evidence (
    finding_id   TEXT    NOT NULL,
    ordinal      INTEGER NOT NULL,          -- preserves citation order
    file_id      TEXT    NOT NULL,
    line_start   INTEGER NOT NULL,
    line_end     INTEGER NOT NULL,

    PRIMARY KEY (finding_id, ordinal),
    FOREIGN KEY (finding_id) REFERENCES finding(finding_id) ON DELETE CASCADE,
    CHECK (line_start >= 1),
    CHECK (line_end >= line_start)
);

CREATE INDEX idx_finding_evidence_file ON finding_evidence(file_id, line_start);
