from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from src.core.config import get_settings

_engine: Engine | None = None
_SessionLocal: sessionmaker | None = None


def _create_engine() -> Engine:
    """Create the SQLAlchemy engine using environment configuration."""
    settings = get_settings()
    dsn = settings.require_database_dsn()

    # NOTE: we do not enable echo logs by default (avoid leaking sensitive info).
    return create_engine(dsn, pool_pre_ping=True)


def _get_engine() -> Engine:
    """
    Lazily create and memoize the SQLAlchemy engine.

    This avoids crashing the app at import-time when POSTGRES_URL isn't configured yet,
    while still failing with a clear error when a DB-backed endpoint is invoked.
    """
    global _engine
    if _engine is None:
        _engine = _create_engine()
    return _engine


def _get_session_local() -> sessionmaker:
    """Lazily create and memoize the SQLAlchemy sessionmaker."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=_get_engine(),
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )
    return _SessionLocal


# PUBLIC_INTERFACE
def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and ensures it is closed."""
    SessionLocal = _get_session_local()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
