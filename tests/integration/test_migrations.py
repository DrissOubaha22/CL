"""The committed migrations must reproduce exactly the current models.

There are two histories - ``migrations`` for the global schemas and
``migrations_tenant`` for each tenant schema - and both are checked the same
way: build a throwaway database, bring it up, and diff the result against the
declarative metadata.  Catches the common failure of a model change landing
without its migration.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import MetaData, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from aegis.config import get_settings
from aegis.db.base import Base, ControlBase, TenantBase
from aegis.db.models.control import Tenant
from aegis.db.tenant_migrations import tenant_alembic_config
from tests.conftest import TEST_DSN, requires_db

pytestmark = [pytest.mark.integration, requires_db]

CHECK_DB = "aegis_migration_check"


@pytest.fixture
def migrated_dsn() -> Iterator[str]:
    """A fresh database with the migrations applied, dropped afterwards."""
    url = make_url(TEST_DSN)
    admin_url = url.set(database="postgres")
    target_url = url.set(database=CHECK_DB)

    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{CHECK_DB}"'))
            connection.execute(text(f'CREATE DATABASE "{CHECK_DB}"'))

        config = Config("alembic.ini")
        config.set_main_option("sqlalchemy.url", target_url.render_as_string(False))
        command.upgrade(config, "head")

        yield target_url.render_as_string(False)
    finally:
        with admin.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :db AND pid <> pg_backend_pid()"
                ),
                {"db": CHECK_DB},
            )
            connection.execute(text(f'DROP DATABASE IF EXISTS "{CHECK_DB}"'))
        admin.dispose()


TENANT_SCHEMA = "tenant_migration_check"


def _diff(engine, metadata, schema: str):
    """Differences between a live schema and the declarative metadata."""
    with engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={
                "include_schemas": True,
                "compare_type": True,
                "version_table_schema": schema,
                "include_object": (
                    lambda obj, name, type_, reflected, compare_to: (
                        obj.schema in (schema, None) if type_ == "table" else True
                    )
                ),
            },
        )
        return compare_metadata(context, metadata)


def test_global_migrations_reproduce_the_models(migrated_dsn: str) -> None:
    """``intel`` and ``control`` match ``migrations/``."""
    settings = get_settings()
    engine = create_engine(migrated_dsn)
    try:
        diff = [
            item
            for metadata, schema in (
                (Base.metadata, settings.intel_schema),
                (ControlBase.metadata, settings.control_schema),
            )
            for item in _diff(engine, metadata, schema)
        ]
    finally:
        engine.dispose()

    assert diff == [], (
        "the global migrations do not match the models; run "
        "`alembic revision --autogenerate` and commit the result. "
        f"Difference: {diff}"
    )


def _tenant_metadata_at(schema: str) -> MetaData:
    """The per-tenant models rebound from the placeholder to a real schema.

    Alembic's comparison reads ``table.schema`` literally and does not apply
    ``schema_translate_map``, so the metadata has to be rewritten before it
    can be diffed against a provisioned tenant schema.
    """
    rebound = MetaData(schema=schema)
    for table in TenantBase.metadata.sorted_tables:
        table.to_metadata(rebound, schema=schema)
    return rebound


def test_tenant_migrations_reproduce_the_models(migrated_dsn: str) -> None:
    """A tenant schema built by ``migrations_tenant/`` matches the models."""
    config = tenant_alembic_config(TENANT_SCHEMA, dsn=migrated_dsn)
    command.upgrade(config, "head")

    engine = create_engine(migrated_dsn)
    try:
        diff = _diff(engine, _tenant_metadata_at(TENANT_SCHEMA), TENANT_SCHEMA)
    finally:
        engine.dispose()

    assert diff == [], (
        "the tenant migrations do not match the models; autogenerate a new "
        "revision against migrations_tenant and commit it. "
        f"Difference: {diff}"
    )


def test_provisioning_a_tenant_reaches_the_head_revision(
    migrated_dsn: str,
) -> None:
    """``create_tenant`` must use the migrations, not ``create_all``.

    Two code paths producing "the same" schema drift apart the first time a
    migration does something ``create_all`` cannot express.
    """
    from aegis.db.tenancy import create_tenant, drop_tenant_schema
    from aegis.db.tenant_migrations import head_revision, tenant_revision

    engine = create_engine(migrated_dsn)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        tenant = create_tenant(session, slug="provcheck", name="Provisioning Check", engine=engine)
        session.commit()
        assert tenant_revision(tenant, engine=engine) == head_revision()
    finally:
        tenant_to_drop = session.get(Tenant, 1)
        if tenant_to_drop is not None:
            drop_tenant_schema(tenant_to_drop, engine=engine)
        session.close()
        engine.dispose()
