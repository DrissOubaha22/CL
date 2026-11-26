"""Shared test fixtures.

Unit tests need no database.  Integration tests need a live PostgreSQL and
are skipped unless ``AEGIS_TEST_DSN`` points at one; the intel store relies on
PostgreSQL-specific features (JSONB, partial indexes, schemas) so faking it
with SQLite would test something the product does not run on.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from aegis.config import get_settings
from aegis.core.enums import AutomationPolicy, FeedSource
from aegis.db.base import TENANT_SCHEMA_TOKEN, Base, ControlBase, TenantBase
from aegis.db.models.control import Tenant, schema_name_for
from aegis.intel.schemas import FeedContribution, SourceRef

TEST_DSN = os.environ.get("AEGIS_TEST_DSN")

requires_db = pytest.mark.skipif(not TEST_DSN, reason="set AEGIS_TEST_DSN to run integration tests")


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    """Engine with the global schemas (intel + control) built from the models."""
    if not TEST_DSN:
        pytest.skip("AEGIS_TEST_DSN is not set")

    engine = create_engine(TEST_DSN, future=True)
    settings = get_settings()
    with engine.begin() as connection:
        for schema in (settings.intel_schema, settings.control_schema):
            connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))

    for metadata in (Base.metadata, ControlBase.metadata):
        metadata.drop_all(engine)
        metadata.create_all(engine)

    yield engine

    _drop_test_tenant_schemas(engine)
    for metadata in (Base.metadata, ControlBase.metadata):
        metadata.drop_all(engine)
    engine.dispose()


def _drop_test_tenant_schemas(engine: Engine) -> None:
    prefix = get_settings().tenant_schema_prefix
    with engine.begin() as connection:
        rows = connection.execute(
            text(
                "SELECT schema_name FROM information_schema.schemata "
                "WHERE schema_name LIKE :pattern"
            ),
            {"pattern": f"{prefix}%"},
        ).scalars()
        for schema in list(rows):
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """A session whose writes are rolled back after each test."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    # Truncate rather than nest transactions: the code under test commits.
    schema = get_settings().intel_schema
    tables = ", ".join(
        f'"{schema}"."{table.name}"' for table in reversed(Base.metadata.sorted_tables)
    )
    session.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    session.commit()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def make_contribution(
    cve_id: str = "CVE-2026-104286",
    source: FeedSource = FeedSource.CISA_KEV,
    *,
    retrieved_at: datetime | None = None,
    **fields: object,
) -> FeedContribution:
    """Build a valid contribution with sensible provenance."""
    payload: dict[str, object] = {
        "cve_id": cve_id,
        "source": source,
        "retrieved_at": retrieved_at or datetime(2026, 11, 26, 12, 0, tzinfo=UTC),
        "sources": [SourceRef(url=f"https://example.test/{source}")],
    }
    payload.update(fields)
    return FeedContribution(**payload)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# tenant fixtures (phase 2)
# --------------------------------------------------------------------------


def _make_tenant(session: Session, engine: Engine, slug: str, name: str) -> Tenant:
    """Register a tenant and build its schema from the models.

    Tests build the tenant schema with ``create_all`` rather than the
    migrations; ``tests/integration/test_migrations.py`` is what proves the
    migrations reproduce these models.
    """
    tenant = Tenant(
        slug=slug,
        name=name,
        schema_name=schema_name_for(slug),
        automation_policy=AutomationPolicy.REVIEW_ALL,
        active=True,
    )
    session.add(tenant)
    session.flush()

    with engine.begin() as connection:
        connection.execute(text(f'DROP SCHEMA IF EXISTS "{tenant.schema_name}" CASCADE'))
        connection.execute(text(f'CREATE SCHEMA "{tenant.schema_name}"'))

    scoped = engine.execution_options(
        schema_translate_map={TENANT_SCHEMA_TOKEN: tenant.schema_name}
    )
    TenantBase.metadata.create_all(scoped, checkfirst=True)
    return tenant


@pytest.fixture
def control_session(engine: Engine) -> Iterator[Session]:
    """A session on the control schema, emptied before each test."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    session.execute(text(f'TRUNCATE "{get_settings().control_schema}"."tenant" CASCADE'))
    session.commit()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def tenant(control_session: Session, engine: Engine) -> Tenant:
    """A single provisioned tenant, ``acme``."""
    created = _make_tenant(control_session, engine, "acme", "Acme Corp")
    control_session.commit()
    return created


@pytest.fixture
def two_tenants(control_session: Session, engine: Engine) -> tuple[Tenant, Tenant]:
    """Two provisioned tenants, for isolation tests."""
    acme = _make_tenant(control_session, engine, "acme", "Acme Corp")
    globex = _make_tenant(control_session, engine, "globex", "Globex SA")
    control_session.commit()
    return acme, globex


@pytest.fixture
def tenant_session(tenant: Tenant, engine: Engine) -> Iterator[Session]:
    """A session scoped to the ``acme`` tenant schema."""
    scoped = engine.execution_options(
        schema_translate_map={TENANT_SCHEMA_TOKEN: tenant.schema_name}
    )
    factory = sessionmaker(bind=scoped, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


def session_for(tenant: Tenant, engine: Engine) -> Session:
    """An unmanaged session for a given tenant; the caller closes it."""
    scoped = engine.execution_options(
        schema_translate_map={TENANT_SCHEMA_TOKEN: tenant.schema_name}
    )
    return sessionmaker(bind=scoped, expire_on_commit=False)()
