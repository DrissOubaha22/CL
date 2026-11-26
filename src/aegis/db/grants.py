"""Database roles and grants (spec §11).

Spec §11: "Shared intel store is read-only to tenant workers."  Schema
isolation (phase 2) stops one tenant reading another's rows; this stops a
tenant worker *writing* the shared intel every tenant depends on.  The
first is enforced by not putting the tables in reach; the second has to be
enforced by the database, because the tables are deliberately in reach.

Two roles:

``aegis_etl``
    Writes ``intel`` and ``control``.  The feed pipelines and provisioning
    run as this.

``aegis_tenant``
    Reads ``intel``, writes tenant schemas.  Matching, verification,
    scoring, bulletins and the API run as this.

Applying these is a deployment step, not a migration: a migration runs as
the owner and granting rights to roles that may not exist yet would make
every deployment carry the same role names.  ``aegis db grants`` emits or
applies them.
"""

from __future__ import annotations

import structlog
from sqlalchemy import Engine, text

from aegis.config import Settings, get_settings

log = structlog.get_logger(__name__)

__all__ = ["ETL_ROLE", "TENANT_ROLE", "apply_grants", "grant_statements"]

ETL_ROLE = "aegis_etl"
TENANT_ROLE = "aegis_tenant"


def grant_statements(
    *,
    settings: Settings | None = None,
    etl_role: str = ETL_ROLE,
    tenant_role: str = TENANT_ROLE,
) -> list[str]:
    """The SQL that makes the shared intel store read-only to tenants.

    Returned rather than executed so a deployment can review it, put it in
    a change ticket, or run it as a superuser elsewhere.
    """
    config = settings or get_settings()
    intel = config.intel_schema
    control = config.control_schema

    return [
        # --- the shared intel store: ETL writes, tenants only read --------
        f'GRANT USAGE ON SCHEMA "{intel}" TO "{etl_role}", "{tenant_role}"',
        f'GRANT SELECT ON ALL TABLES IN SCHEMA "{intel}" TO "{tenant_role}"',
        f'GRANT ALL ON ALL TABLES IN SCHEMA "{intel}" TO "{etl_role}"',
        f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA "{intel}" TO "{etl_role}"',
        # Tables added by a later migration inherit the same split.
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{intel}" GRANT SELECT ON TABLES TO "{tenant_role}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{intel}" GRANT ALL ON TABLES TO "{etl_role}"',
        # --- the control plane --------------------------------------------
        f'GRANT USAGE ON SCHEMA "{control}" TO "{etl_role}", "{tenant_role}"',
        # Tenant workers read the registry to find their own schema, and
        # append to the audit log. They never change a tenant's record.
        f'GRANT SELECT ON "{control}"."tenant" TO "{tenant_role}"',
        f'GRANT SELECT ON "{control}"."delivery_destination" TO "{tenant_role}"',
        f'GRANT SELECT, INSERT ON "{control}"."audit_event" TO "{tenant_role}"',
        f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA "{control}" TO "{etl_role}", "{tenant_role}"',
        f'GRANT ALL ON ALL TABLES IN SCHEMA "{control}" TO "{etl_role}"',
        # --- a note for whoever reads this in psql -------------------------
        f'COMMENT ON SCHEMA "{intel}" IS '
        f"'Shared per-CVE intel. Read-only to {tenant_role} (spec 11).'",
    ]


def tenant_schema_grants(
    schema: str, *, tenant_role: str = TENANT_ROLE, etl_role: str = ETL_ROLE
) -> list[str]:
    """Grants for one tenant's schema, run at provisioning."""
    return [
        f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO "{etl_role}"',
        f'GRANT USAGE ON SCHEMA "{schema}" TO "{tenant_role}"',
        f'GRANT ALL ON ALL TABLES IN SCHEMA "{schema}" TO "{tenant_role}"',
        f'GRANT USAGE ON ALL SEQUENCES IN SCHEMA "{schema}" TO "{tenant_role}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" GRANT ALL ON TABLES TO "{tenant_role}"',
        f'ALTER DEFAULT PRIVILEGES IN SCHEMA "{schema}" '
        f'GRANT USAGE ON SEQUENCES TO "{tenant_role}"',
    ]


def apply_grants(
    *,
    engine: Engine,
    settings: Settings | None = None,
    create_roles: bool = False,
) -> list[str]:
    """Apply the grants, optionally creating the roles first.

    Args:
        engine: A connection with rights to grant - normally the owner.
        settings: Override configuration.
        create_roles: Create the two roles if absent.  Off by default: in
            most deployments the roles are managed outside the application,
            with passwords this process should never see.

    Returns:
        The statements that were executed.
    """
    config = settings or get_settings()
    statements: list[str] = []

    if create_roles:
        for role in (ETL_ROLE, TENANT_ROLE):
            statements.append(
                "DO $$ BEGIN "
                f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') "
                f'THEN CREATE ROLE "{role}" NOLOGIN; END IF; END $$'
            )

    statements.extend(grant_statements(settings=config))

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))

    log.info("db.grants_applied", statements=len(statements))
    return statements
