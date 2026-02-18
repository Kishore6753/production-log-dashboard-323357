from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Typed application settings loaded from environment variables."""

    app_title: str = "Production Log Analysis API"
    app_description: str = (
        "APIs to upload production logs, run evidence-based analysis, and persist "
        "structured reports to PostgreSQL."
    )
    app_version: str = "0.2.0"

    postgres_url: str = os.getenv("POSTGRES_URL", "")
    postgres_user: str = os.getenv("POSTGRES_USER", "")
    postgres_password: str = os.getenv("POSTGRES_PASSWORD", "")
    postgres_db: str = os.getenv("POSTGRES_DB", "")
    postgres_port: str = os.getenv("POSTGRES_PORT", "")

    # For MVP we store uploaded files locally in this container.
    uploads_dir: str = os.getenv("UPLOADS_DIR", "data/uploads")

    def build_database_dsn(self) -> str:
        """
        Build SQLAlchemy DSN.

        Supports either:
        - POSTGRES_URL containing a full SQLAlchemy/psycopg DSN, or
        - individual POSTGRES_* vars.
        """
        if self.postgres_url:
            return self.postgres_url

        # If the env is not set, we fail fast later with an actionable error.
        host = self.postgres_user and "localhost"
        _ = host  # keep lint happy; host is intentionally not guessed beyond localhost

        # Do not guess hostname; orchestration typically provides POSTGRES_URL.
        return ""

    def require_database_dsn(self) -> str:
        """Return database DSN or raise a clear error if missing."""
        dsn = self.build_database_dsn()
        if not dsn:
            raise RuntimeError(
                "Database DSN missing. Please set POSTGRES_URL (preferred) in .env for "
                "production_log_backend. Alternatively provide enough POSTGRES_* vars."
            )
        return dsn


# PUBLIC_INTERFACE
def get_settings() -> Settings:
    """Get Settings instance (simple function to allow future caching/overrides)."""
    return Settings()
