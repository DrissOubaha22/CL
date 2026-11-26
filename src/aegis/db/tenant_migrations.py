"""Applying the per-tenant migration history to each tenant schema.

One revision history (``migrations_tenant``), applied independently to every
tenant schema, with the Alembic version table stored *inside* that schema.
A tenant can therefore lag or be migrated alone, which is the point of
schema-per-tenant: no global lock, no all-or-nothing deploy.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import structlog
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, text

from aegis.db.base import get_engine
from aegis.db.models.control import Tenant

log = structlog.get_logger(__name__)

__all__ = [
    "TenantMigrationState",
    "head_revision",
    "tenant_alembic_config",
    "tenant_revision",
    "upgrade_all_tenants",
    "upgrade_tenant",
]

#: Repository root, located from this file so the CLI works from any cwd.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
TENANT_ALEMBIC_INI = _PROJECT_ROOT / "alembic_tenant.ini"


@dataclass(slots=True)
class TenantMigrationState:
    """Where one tenant's schema stands against the head revision."""

    slug: str
    schema_name: str
    current: str | None
    head: str | None

    @property
    def up_to_date(self) -> bool:
        return self.current == self.head


def tenant_alembic_config(schema: str, dsn: str | None = None) -> Config:
    """An Alembic config pointed at one tenant schema."""
    if not TENANT_ALEMBIC_INI.exists():  # pragma: no cover - packaging guard
        raise FileNotFoundError(f"tenant migration config not found at {TENANT_ALEMBIC_INI}")
    config = Config(str(TENANT_ALEMBIC_INI))
    config.set_main_option("script_location", str(_PROJECT_ROOT / "migrations_tenant"))
    if dsn:
        config.set_main_option("sqlalchemy.url", dsn)
    config.attributes["tenant_schema"] = schema
    return config


def head_revision() -> str | None:
    """The newest revision in the per-tenant history."""
    config = tenant_alembic_config(schema="__head_lookup__")
    script = ScriptDirectory.from_config(config)
    return script.get_current_head()


def tenant_revision(tenant: Tenant, *, engine: Engine | None = None) -> str | None:
    """The revision a tenant's schema is currently at, or ``None``."""
    bind = engine or get_engine()
    with bind.connect() as connection:
        exists = connection.execute(
            text("SELECT 1 FROM information_schema.schemata WHERE schema_name = :s"),
            {"s": tenant.schema_name},
        ).first()
        if exists is None:
            return None
        context = MigrationContext.configure(
            connection, opts={"version_table_schema": tenant.schema_name}
        )
        return context.get_current_revision()


def upgrade_tenant(
    tenant: Tenant,
    *,
    revision: str = "head",
    engine: Engine | None = None,
) -> TenantMigrationState:
    """Bring one tenant's schema up to ``revision``.

    Idempotent: a schema already at the target revision is left untouched.
    """
    bind = engine or get_engine()
    dsn = bind.url.render_as_string(hide_password=False)

    config = tenant_alembic_config(tenant.schema_name, dsn=dsn)
    command.upgrade(config, revision)

    state = TenantMigrationState(
        slug=tenant.slug,
        schema_name=tenant.schema_name,
        current=tenant_revision(tenant, engine=bind),
        head=head_revision(),
    )
    log.info(
        "tenant.migrated",
        slug=tenant.slug,
        schema=tenant.schema_name,
        revision=state.current,
    )
    return state


def upgrade_all_tenants(
    tenants: list[Tenant],
    *,
    revision: str = "head",
    engine: Engine | None = None,
) -> list[TenantMigrationState]:
    """Fan the migration out across tenants.

    One tenant failing does not stop the others - with isolated schemas a
    partial rollout is a recoverable state, not a corrupt one - but the
    exception is re-raised once every tenant has been attempted.
    """
    states: list[TenantMigrationState] = []
    failures: list[tuple[str, Exception]] = []

    for tenant in tenants:
        try:
            states.append(upgrade_tenant(tenant, revision=revision, engine=engine))
        except Exception as exc:
            log.error("tenant.migration_failed", slug=tenant.slug, error=str(exc))
            failures.append((tenant.slug, exc))

    if failures:
        names = ", ".join(slug for slug, _ in failures)
        raise RuntimeError(f"tenant migrations failed for: {names}") from failures[0][1]
    return states
