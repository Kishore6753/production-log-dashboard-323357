from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from src.core.config import get_settings


def _create_engine() -> Engine:
    """Create the SQLAlchemy engine using environment configuration."""
    settings = get_settings()
    dsn = settings.require_database_dsn()

    # NOTE: we do not enable echo logs by default (avoid leaking sensitive info).
    return create_engine(dsn, pool_pre_ping=True)


engine: Engine = _create_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


# PUBLIC_INTERFACE
def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and ensures it is closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
