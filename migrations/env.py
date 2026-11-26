"""Alembic environment for the shared intel schema."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from aegis.config import get_settings
from aegis.db.base import Base
from aegis.db.models import *  # noqa: F401,F403 - register metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
# A caller (the migration-drift test, for instance) may target another
# database by setting the url first; only fall back to the configured DSN.
if not config.get_main_option("sqlalchemy.url", default=""):
    config.set_main_option("sqlalchemy.url", settings.database_dsn)

target_metadata = Base.metadata
INTEL_SCHEMA = settings.intel_schema


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Only manage objects in the intel schema; tenant schemas are separate."""
    if type_ == "table":
        return obj.schema in (INTEL_SCHEMA, None)
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        include_schemas=True,
        include_object=include_object,
        version_table_schema=INTEL_SCHEMA,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{INTEL_SCHEMA}"'))
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_object=include_object,
            version_table_schema=INTEL_SCHEMA,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
