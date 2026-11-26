"""Alembic environment for the global schemas.

Covers ``intel`` (shared per-CVE store) and ``control`` (tenant registry).
Per-tenant schemas are migrated separately by ``migrations_tenant`` so a
tenant can be migrated independently; see ``aegis tenant upgrade``.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from aegis.config import get_settings
from aegis.db.base import Base, ControlBase
from aegis.db.types import StrEnumType
from aegis.db.models import *  # noqa: F401,F403 - register metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
# A caller (the migration-drift test, for instance) may target another
# database by setting the url first; only fall back to the configured DSN.
if not config.get_main_option("sqlalchemy.url", default=""):
    config.set_main_option("sqlalchemy.url", settings.database_dsn)

target_metadata = [Base.metadata, ControlBase.metadata]
GLOBAL_SCHEMAS = (settings.intel_schema, settings.control_schema)
#: Alembic's own version table lives with the intel schema.
VERSION_SCHEMA = settings.intel_schema


def render_item(type_, obj, autogen_context) -> str | bool:
    """Render our custom column types in generated migrations.

    ``StrEnumType`` is a ``VARCHAR`` in the database; the enum round-trip is
    application-level only.  Rendering it as ``sa.String`` keeps migrations
    free of application imports and makes the two indistinguishable to the
    schema comparison, which is correct - they produce identical DDL.
    """
    if type_ == "type" and isinstance(obj, StrEnumType):
        return f"sa.String(length={obj.length})"
    return False


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Manage only the global schemas; per-tenant schemas are migrated apart."""
    if type_ == "table":
        return obj.schema in GLOBAL_SCHEMAS
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        include_schemas=True,
        include_object=include_object,
        render_item=render_item,
        version_table_schema=VERSION_SCHEMA,
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
        for schema in GLOBAL_SCHEMAS:
            connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
        connection.commit()
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            include_schemas=True,
            include_object=include_object,
            render_item=render_item,
            version_table_schema=VERSION_SCHEMA,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
