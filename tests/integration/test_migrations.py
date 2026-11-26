"""The committed migrations must reproduce exactly the current models.

Builds a throwaway database, brings it up with ``alembic upgrade head``, and
diffs the result against the declarative metadata.  Catches the common
failure of a model change landing without its migration.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from aegis.config import get_settings
from aegis.db.base import Base
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


def test_migrations_reproduce_the_models(migrated_dsn: str) -> None:
    schema = get_settings().intel_schema
    engine = create_engine(migrated_dsn)
    try:
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
            diff = compare_metadata(context, Base.metadata)
    finally:
        engine.dispose()

    assert diff == [], (
        "the migrations do not match the models; run "
        "`alembic revision --autogenerate` and commit the result. "
        f"Difference: {diff}"
    )
