-- NIRIKSHAK operational 0001 — configuration ingestion
--
-- This database holds configuration content. The audit chain lives in a
-- separate file (decision D4) so "the audit database contains no configuration
-- content" is provable by opening it rather than by trusting payload discipline.

CREATE TABLE schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    checksum    TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL
);

-- One row per distinct file content. Content-addressed: file_id IS the SHA-256
-- of the raw bytes, so re-uploading the same file is recognised as the same
-- file rather than as a new one.
CREATE TABLE config_file (
    file_id          TEXT PRIMARY KEY,      -- sha256 of raw bytes
    size_bytes       INTEGER NOT NULL,
    line_count       INTEGER NOT NULL,
    encoding         TEXT    NOT NULL,      -- determines what every raw_line says
    file_format      TEXT    NOT NULL,      -- cli | xml | json
    blob_path        TEXT    NOT NULL,

    detected_vendor    TEXT,                -- NULL means UNKNOWN, never a guess
    detected_os_family TEXT,
    detection_score    REAL,
    detection_margin   REAL,
    detection_reason   TEXT    NOT NULL,    -- detected | ambiguous | below_threshold | …
    detection_evidence TEXT,                -- JSON: which signatures matched, where

    first_seen_at    TEXT    NOT NULL,

    CHECK (size_bytes >= 0),
    CHECK (line_count >= 0),
    CHECK (file_format IN ('cli', 'xml', 'json')),
    CHECK (length(file_id) = 64 AND file_id NOT GLOB '*[^0-9a-f]*'),
    -- A vendor may only be recorded together with the evidence that produced it.
    CHECK (detected_vendor IS NULL OR detection_score IS NOT NULL)
);

-- Position -> content. This is what makes evidence exact: (file_id, line_number)
-- resolves to the precise text that was on that line.
CREATE TABLE config_line (
    file_id      TEXT    NOT NULL,
    line_number  INTEGER NOT NULL,          -- 1-based, as an editor would show
    line_sha256  TEXT    NOT NULL,

    PRIMARY KEY (file_id, line_number),
    FOREIGN KEY (file_id) REFERENCES config_file(file_id) ON DELETE CASCADE,
    CHECK (line_number >= 1)
);

-- Content -> text, stored once for the whole fleet. The Concept Report's
-- efficiency claim: identical lines across a large estate resolve once.
-- P4 attaches parse results to this table rather than re-parsing per device.
CREATE TABLE line_cache (
    line_sha256      TEXT PRIMARY KEY,
    text             TEXT    NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    first_seen_at    TEXT    NOT NULL,

    CHECK (length(line_sha256) = 64 AND line_sha256 NOT GLOB '*[^0-9a-f]*'),
    CHECK (occurrence_count >= 1)
);

-- Device identity extracted from a file. Every field is independently nullable:
-- a configuration with a hostname but no serial yields one known and one
-- UNKNOWN, never an invented serial.
CREATE TABLE device (
    device_id          TEXT PRIMARY KEY,
    file_id            TEXT NOT NULL,
    hostname           TEXT,
    vendor             TEXT,
    os_family          TEXT,
    os_version         TEXT,
    model              TEXT,
    serial             TEXT,
    peer_group         TEXT,
    identity_evidence  TEXT NOT NULL DEFAULT '{}',   -- JSON: field -> line refs

    FOREIGN KEY (file_id) REFERENCES config_file(file_id) ON DELETE CASCADE
);

-- One row per upload attempt, including refusals. A file uploaded twice
-- produces two ingestion rows and one config_file row.
CREATE TABLE ingestion (
    ingestion_id      TEXT PRIMARY KEY,
    batch_id          TEXT    NOT NULL,
    original_filename TEXT    NOT NULL,
    file_id           TEXT,                -- NULL when the file was rejected
    status            TEXT    NOT NULL,    -- ingested | duplicate | rejected
    reason            TEXT,                -- rejection reason, machine-readable
    size_bytes        INTEGER,
    received_at       TEXT    NOT NULL,

    CHECK (status IN ('ingested', 'duplicate', 'rejected')),
    -- A rejection must say why; a success must not carry a rejection reason.
    CHECK ((status = 'rejected') = (reason IS NOT NULL)),
    CHECK ((status = 'rejected') = (file_id IS NULL))
);

CREATE INDEX idx_config_file_vendor   ON config_file(detected_vendor, detected_os_family);
CREATE INDEX idx_config_line_hash     ON config_line(line_sha256);
CREATE INDEX idx_device_file          ON device(file_id);
CREATE INDEX idx_device_hostname      ON device(hostname);
CREATE INDEX idx_ingestion_batch      ON ingestion(batch_id);
CREATE INDEX idx_ingestion_status     ON ingestion(status);
