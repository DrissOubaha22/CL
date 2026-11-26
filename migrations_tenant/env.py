"""Alembic environment for a single tenant schema.

Run once per tenant, with the target schema passed in
``config.attributes["tenant_schema"]`` - see
:func:`aegis.db.tenant_migrations.upgrade_tenant`.  The models are declared
against the placeholder schema, so the whole migration is executed through a
``schema_translate_map``: one revision history, applied independently to each
tenant's schema, with the version table living in that same schema.

**Autogenerating a revision**: pass ``tenant_schema="tenant"`` - the
placeholder name itself.  Alembic's comparison reads ``table.schema``
literally and does not apply the translate map, so a revision generated
against ``tenant_acme`` would see every table as new.  Against a schema
actually named ``tenant`` the metadata and the reflection agree.
:func:`aegis.db.tenant_migrations.autogenerate_schema` does this.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool, text

from aegis.config import get_settings
from aegis.db.base import TENANT_SCHEMA_TOKEN, TenantBase
from aegis.db.models import tenant as _tenant_models  # noqa: F401 - register metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

if not config.get_main_option("sqlalchemy.url", default=""):
    config.set_main_option("sqlalchemy.url", get_settings().database_dsn)

target_metadata = TenantBase.metadata

#: Which tenant schema this invocation targets.  Autogenerate against the
#: placeholder is meaningless, so a concrete schema is required.
TENANT_SCHEMA = config.attributes.get("tenant_schema")
if not TENANT_SCHEMA:
    raise RuntimeError(
        "migrations_tenant requires config.attributes['tenant_schema']; "
        "use `aegis tenant upgrade` rather than invoking alembic directly"
    )


def render_item(type_, obj, autogen_context) -> str | bool:
    """Render ``StrEnumType`` as the ``VARCHAR`` it is in the database."""
    from aegis.db.types import StrEnumType

    if type_ == "type" and isinstance(obj, StrEnumType):
        return f"sa.String(length={obj.length})"
    return False


def include_object(obj, name, type_, reflected, compare_to) -> bool:
    """Only per-tenant tables; the global schemas migrate separately."""
    if type_ == "table":
        return obj.schema in (TENANT_SCHEMA_TOKEN, TENANT_SCHEMA, None)
    return True


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{TENANT_SCHEMA}"'))
        connection.commit()

        scoped = connection.execution_options(
            schema_translate_map={TENANT_SCHEMA_TOKEN: TENANT_SCHEMA}
        )
        context.configure(
            connection=scoped,
            target_metadata=target_metadata,
            include_schemas=True,
            include_object=include_object,
            render_item=render_item,
            compare_type=True,
            # Each tenant tracks its own revision, inside its own schema.
            version_table_schema=TENANT_SCHEMA,
        )
        with context.begin_transaction():
            context.run_migrations()


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        include_schemas=True,
        include_object=include_object,
        render_item=render_item,
        version_table_schema=TENANT_SCHEMA,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
