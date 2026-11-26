"""Engine, session factories and the three declarative bases.

Spec §11 requires hard tenant isolation, so the database is split three ways
and each half has its own metadata:

``intel`` (:class:`Base`)
    The shared per-CVE store.  Collected once, read by every tenant, written
    only by the ETL role.

``control`` (:class:`ControlBase`)
    The tenant registry.  Global by necessity - you cannot enumerate tenants
    from inside a tenant.

``tenant`` (:class:`TenantBase`)
    Per-tenant data: inventory and matches.  Declared against the placeholder
    schema name ``tenant`` and resolved to a real schema
    (``tenant_acme``, ...) per session via SQLAlchemy's
    ``schema_translate_map``.  One set of models, N physically separate
    schemas, and a query that forgets to scope simply cannot see another
    tenant's rows.
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


#: Placeholder schema name used by the per-tenant models.  It is never a
#: real schema: every session resolves it through ``schema_translate_map``.
TENANT_SCHEMA_TOKEN = "tenant"


class Base(DeclarativeBase):
    """Declarative base bound to the shared intel schema."""

    metadata = MetaData(
        schema=get_settings().intel_schema,
        naming_convention=NAMING_CONVENTION,
    )


class ControlBase(DeclarativeBase):
    """Declarative base for the global tenant registry."""

    metadata = MetaData(
        schema=get_settings().control_schema,
        naming_convention=NAMING_CONVENTION,
    )


class TenantBase(DeclarativeBase):
    """Declarative base for per-tenant data.

    Bound to the placeholder :data:`TENANT_SCHEMA_TOKEN`; see
    :func:`aegis.db.tenancy.tenant_session_scope`.
    """

    metadata = MetaData(
        schema=TENANT_SCHEMA_TOKEN,
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
