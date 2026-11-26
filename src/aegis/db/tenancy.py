"""Schema-per-tenant plumbing (spec §1, §11).

Per-tenant models are declared once against the placeholder schema
:data:`~aegis.db.base.TENANT_SCHEMA_TOKEN`.  A session obtained from
:func:`tenant_session_scope` carries a ``schema_translate_map`` that rewrites
that placeholder to the tenant's real schema, so the same model classes read
and write a different physical schema per tenant.

What this buys over a ``tenant_id`` column: isolation stops depending on
every query remembering to filter.  A query issued on Acme's session cannot
return Globex rows, because Globex's tables are not in the search path at
all.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime

import structlog
from sqlalchemy import Connection, Engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from aegis.config import get_settings
from aegis.core.enums import AutomationPolicy
from aegis.db.base import TENANT_SCHEMA_TOKEN, ControlBase, get_engine
from aegis.db.models.control import Tenant, schema_name_for, validate_slug

log = structlog.get_logger(__name__)

__all__ = [
    "TenantNotFound",
    "active_tenants",
    "create_tenant",
    "drop_tenant_schema",
    "get_tenant",
    "tenant_session_scope",
]


class TenantNotFound(LookupError):
    """No tenant with that slug, or the tenant is not active."""


def _engine_of(session: Session) -> Engine:
    """The Engine behind a session, whether it is bound to one or a Connection."""
    bind = session.get_bind()
    return bind.engine if isinstance(bind, Connection) else bind


def _quote(identifier: str) -> str:
    """Quote an identifier that has already been validated as a slug."""
    if '"' in identifier:  # defensive; validate_slug forbids it
        raise ValueError(f"illegal identifier: {identifier!r}")
    return f'"{identifier}"'


@contextmanager
def tenant_session_scope(tenant: Tenant | str, engine: Engine | None = None) -> Iterator[Session]:
    """A transactional session bound to one tenant's schema.

    Args:
        tenant: A :class:`Tenant` row, or a slug to resolve.  Passing the row
            avoids a lookup; passing a slug is convenient from the CLI.
        engine: Override the configured engine (tests).

    Yields:
        A session whose per-tenant tables resolve to that tenant's schema.
        The shared ``intel`` and ``control`` schemas are unaffected, so a
        cross-schema join against intel still works.
    """
    bind = engine or get_engine()

    if isinstance(tenant, str):
        with session_for_control(bind) as control:
            tenant = get_tenant(control, tenant)

    schema = tenant.schema_name
    scoped = bind.execution_options(schema_translate_map={TENANT_SCHEMA_TOKEN: schema})
    factory = sessionmaker(bind=scoped, expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def session_for_control(engine: Engine | None = None) -> Iterator[Session]:
    """A session for the control plane (tenant registry)."""
    factory = sessionmaker(bind=engine or get_engine(), expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_tenant(session: Session, slug: str, *, require_active: bool = True) -> Tenant:
    """Look up a tenant by slug.

    Raises:
        TenantNotFound: if no such tenant exists, or it is deactivated and
            ``require_active`` is set.
    """
    normalised = validate_slug(slug)
    tenant = session.scalars(select(Tenant).where(Tenant.slug == normalised)).one_or_none()
    if tenant is None:
        raise TenantNotFound(f"no tenant with slug {normalised!r}")
    if require_active and not tenant.active:
        raise TenantNotFound(f"tenant {normalised!r} is not active")
    return tenant


def active_tenants(session: Session) -> list[Tenant]:
    """Every tenant a scheduled job should process."""
    return list(
        session.scalars(select(Tenant).where(Tenant.active.is_(True)).order_by(Tenant.slug)).all()
    )


def create_tenant(
    session: Session,
    *,
    slug: str,
    name: str,
    automation_policy: AutomationPolicy = AutomationPolicy.REVIEW_ALL,
    region: str | None = None,
    engine: Engine | None = None,
) -> Tenant:
    """Register a tenant and provision its schema.

    Creating the schema is DDL and therefore not transactional with the
    registry row on every PostgreSQL configuration; the registry row is
    written first and ``provisioned_at`` is set only once the schema exists,
    so a half-finished provisioning is visible rather than silent.

    Raises:
        InvalidTenantSlug: if the slug cannot form a schema name.
        ValueError: if the slug is already registered.
    """
    normalised = validate_slug(slug)
    existing = session.scalars(select(Tenant).where(Tenant.slug == normalised)).one_or_none()
    if existing is not None:
        raise ValueError(f"tenant {normalised!r} already exists")

    tenant = Tenant(
        slug=normalised,
        name=name.strip(),
        schema_name=schema_name_for(normalised),
        automation_policy=automation_policy,
        region=region,
        active=True,
    )
    session.add(tenant)
    session.flush()

    provision_tenant_schema(tenant, engine=engine or _engine_of(session))
    tenant.provisioned_at = datetime.now(UTC)
    session.flush()

    log.info("tenant.created", slug=tenant.slug, schema=tenant.schema_name)
    return tenant


def provision_tenant_schema(tenant: Tenant, *, engine: Engine | None = None) -> None:
    """Create the tenant's schema and bring it to the head revision.

    Provisioning runs the same migration history as an upgrade, rather than
    ``create_all``: a tenant created today and a tenant created last year
    then migrated must end up with byte-identical schemas, and two code paths
    producing "the same" schema drift apart the first time a migration does
    something ``create_all`` cannot express.

    Idempotent: re-running on an existing tenant is a no-op.
    """
    # Imported here: tenant_migrations reads the model metadata this module
    # also exposes, and the indirection keeps the import graph acyclic.
    from aegis.db.tenant_migrations import upgrade_tenant

    upgrade_tenant(tenant, engine=engine or get_engine())
    log.info("tenant.schema_provisioned", slug=tenant.slug, schema=tenant.schema_name)


def drop_tenant_schema(tenant: Tenant, *, engine: Engine | None = None) -> None:
    """Destroy a tenant's schema and everything in it.

    Irreversible, and used by tests and by offboarding.  The registry row is
    left to the caller so the deletion stays explicit.
    """
    bind = engine or get_engine()
    schema = tenant.schema_name
    with bind.begin() as connection:
        connection.execute(text(f"DROP SCHEMA IF EXISTS {_quote(schema)} CASCADE"))
    log.warning("tenant.schema_dropped", slug=tenant.slug, schema=schema)


def provision_control_plane(engine: Engine | None = None) -> None:
    """Create the control schema and registry table, if absent."""
    bind = engine or get_engine()
    schema = get_settings().control_schema
    with bind.begin() as connection:
        connection.execute(text(f"CREATE SCHEMA IF NOT EXISTS {_quote(schema)}"))
    ControlBase.metadata.create_all(bind, checkfirst=True)
