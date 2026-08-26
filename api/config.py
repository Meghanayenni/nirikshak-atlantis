"""Typed application configuration.

Values come from the environment or a local .env file. The two settings that
carry safety meaning are `confidence_threshold` (Rule 3 — below this, a field
becomes UNKNOWN rather than a guess) and `airgap` (Rule 6 — hard-disables every
outbound call, failing closed rather than degrading silently).
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

    # Rule 3 — abstention threshold. Provisional until the calibrator is fitted
    # against labelled ground truth at P9. See R7 and R8.
    confidence_threshold: float = 0.85

    # Rule 6 — when true, no outbound network call is permitted, including
    # model downloads.
    airgap: bool = False

    db_path: Path = REPO_ROOT / "nirikshak.db"


settings = Settings()
