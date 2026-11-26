"""Engine, session factory and declarative base for the shared intel store.

The intel store lives in its own schema (default ``intel``).  Per spec §11 it
is read-only to tenant workers; only the ETL role writes to it.  Tenant
schemas are introduced in a later phase and do not share this metadata.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import cache
from typing import Any

from sqlalchemy import MetaData, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from aegis.config import get_settings

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base bound to the shared intel schema."""

    metadata = MetaData(
        schema=get_settings().intel_schema,
        naming_convention=NAMING_CONVENTION,
    )


@cache
def get_engine(dsn: str | None = None, **kwargs: Any) -> Engine:
    settings = get_settings()
    options: dict[str, Any] = {
        "echo": settings.db_echo,
        "pool_size": settings.db_pool_size,
        "pool_pre_ping": True,
        "future": True,
    }
    options.update(kwargs)
    return create_engine(dsn or settings.database_dsn, **options)


def sessionmaker_for(engine: Engine | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=engine or get_engine(), expire_on_commit=False)


@contextmanager
def session_scope(engine: Engine | None = None) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on failure."""
    factory = sessionmaker_for(engine)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
