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

from aegis.auth.rbac import Principal, Role
from aegis.config import get_settings
from aegis.core.enums import AutomationPolicy, FeedSource
from aegis.db.base import TENANT_SCHEMA_TOKEN, Base, ControlBase, TenantBase

# Imported from the package root on purpose: that executes
# aegis/db/models/__init__.py, which registers every table on the two
# metadatas before the engine fixture calls create_all.
from aegis.db.models import Tenant
from aegis.db.models.control import schema_name_for
from aegis.intel.schemas import FeedContribution, SourceRef

TEST_DSN = os.environ.get("AEGIS_TEST_DSN")

#: Mirrors the migration that installs it; see the engine fixture.
_APPEND_ONLY_FUNCTION = """
CREATE OR REPLACE FUNCTION control.audit_event_is_append_only()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'control.audit_event is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;
"""

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

    # The audit log is append-only in production, enforced by a trigger a
    # migration installs (spec §11).  Tests build the schema with
    # create_all, so the trigger is installed here too - otherwise the
    # append-only tests would pass against a table that is not.
    # tests/integration/test_migrations.py is what proves the migration and
    # these models agree.
    with engine.begin() as connection:
        connection.execute(text(_APPEND_ONLY_FUNCTION))
        for operation in ("UPDATE", "DELETE"):
            connection.execute(
                text(
                    f"CREATE OR REPLACE TRIGGER audit_event_no_{operation.lower()} "
                    f"BEFORE {operation} ON {settings.control_schema}.audit_event "
                    "FOR EACH ROW EXECUTE FUNCTION "
                    f"{settings.control_schema}.audit_event_is_append_only()"
                )
            )

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
    # The audit log is append-only, so it is emptied with TRUNCATE (which
    # the row triggers do not see) rather than DELETE. Without this,
    # events accumulate across tests and an assertion about "the last
    # denial" picks up a previous test's.
    control = get_settings().control_schema
    session.execute(text(f'TRUNCATE "{control}"."tenant", "{control}"."audit_event" CASCADE'))
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


# --------------------------------------------------------------------------
# principals (phase 5)
# --------------------------------------------------------------------------


def principal(
    subject: str = "analyst@example.test",
    *,
    tenant_roles: dict[str, set[Role]] | None = None,
    platform_roles: set[Role] | None = None,
) -> Principal:
    """A principal for tests, defaulting to an analyst at ``acme``."""
    roles = tenant_roles if tenant_roles is not None else {"acme": {Role.ANALYST}}
    return Principal(
        subject=subject,
        tenant_roles={slug: frozenset(items) for slug, items in roles.items()},
        platform_roles=frozenset(platform_roles or set()),
        issuer="oidc",
    )
