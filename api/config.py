"""Typed application configuration.

Values come from the environment or a local .env file. The settings that carry
safety meaning are `confidence_threshold` (Rule 3 — below this, a field becomes
UNKNOWN rather than a guess) and `airgap` (Rule 6 — hard-disables every outbound
call, failing closed rather than degrading silently).
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime configuration for NIRIKSHAK."""

    model_config = SettingsConfigDict(
        env_prefix="NIRIKSHAK_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Rule 3 — abstention threshold for the CALIBRATED SIMILARITY population
    # only (decision D6). Provisional until the calibrator is fitted against
    # labelled ground truth at P9. See R7 and R8.
    confidence_threshold: float = 0.85

    # D6 — platform defaults are their own population with their own floor.
    # A documented default is either sourced and trusted or it is not used;
    # borrowing the similarity threshold here would compare incomparable numbers.
    #
    # Two numbers, and they mean different things (decision D13):
    #
    #   platform_default_confidence      the confidence an ACCEPTED, admissibly
    #                                    sourced default is assigned
    #   platform_default_min_confidence  the ADMISSIBILITY FLOOR below which the
    #                                    field abstains
    #
    # They are deliberately not equal. Setting the assigned value at the floor
    # would put every default exactly on the boundary, which makes the floor
    # untestable in the failing direction and reads as a coincidence rather than
    # a decision. Neither number is a calibrated probability — the platform
    # default population is not similarity-derived and is never pooled with it
    # when fitting the calibrator at P9 (R7).
    #
    # A pack author cannot choose either: PlatformDefault has no confidence
    # field and forbids extras, so this is the only place the number exists.
    platform_default_confidence: float = 0.95
    platform_default_min_confidence: float = 0.90

    # Rule 6 — when true, no outbound network call is permitted, including
    # model downloads.
    airgap: bool = False

    # --- persistence (decision D4) ----------------------------------------
    # Two databases, deliberately. The operational store holds configuration
    # content; the audit chain holds identifiers and hashes. Keeping them in
    # separate files makes "no configuration content in the audit database" a
    # property anyone can check by opening the file.
    db_path: Path = REPO_ROOT / "nirikshak.db"
    audit_db_path: Path = REPO_ROOT / "nirikshak-audit.db"

    # Content-addressed store for raw uploaded configurations. Kept verbatim:
    # evidence fidelity depends on the bytes being unaltered. This directory is
    # what decision R11 would encrypt at rest.
    blob_root: Path = REPO_ROOT / "uploads"

    # --- ingestion limits --------------------------------------------------
    max_file_bytes: int = 10 * 1024 * 1024
    max_batch_files: int = 500
    max_batch_bytes: int = 200 * 1024 * 1024

    max_archive_entries: int = 1000
    max_archive_uncompressed_bytes: int = 200 * 1024 * 1024
    max_compression_ratio: int = 100

    # Fraction of the decoded text that must be printable for a file to be
    # treated as configuration rather than as binary. Measured: real configs sit
    # at 93–100%, binaries at 69% and below.
    min_printable_ratio: float = 0.90

    # --- vendor detection (deterministic, two thresholds) -----------------
    # MIN_SCORE catches thin evidence; MIN_MARGIN catches genuine ambiguity
    # between syntactically close platforms. Failing either yields UNKNOWN with
    # a distinct reason, because the two say different things about our
    # signature set.
    detection_min_score: float = 0.60
    detection_min_margin: float = 0.25


settings = Settings()
