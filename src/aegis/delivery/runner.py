"""Delivering bulletins per tenant (spec §12, §10 step 9).

The destinations live in the control schema and the bulletins live in the
tenant's own, so this is the one place that reads both.  Tenant workers
never touch the control schema themselves: the destinations are read here
and handed down as plain rows.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import structlog
from sqlalchemy import select
from sqlalchemy.engine import Engine

from aegis.auth.rbac import principal_for_service
from aegis.auth.secrets import SecretStore, build_secret_store
from aegis.config import Settings, get_settings
from aegis.core.enums import AuditAction, AuditOutcome
from aegis.db.models import DeliveryDestination, Tenant
from aegis.db.tenancy import active_tenants, session_for_control, tenant_session_scope
from aegis.delivery.sender import DeliveryResult, send_bulletins

log = structlog.get_logger(__name__)

__all__ = ["TenantDelivery", "deliver_all_tenants", "deliver_for_tenant"]


@dataclass(slots=True)
class TenantDelivery:
    """One delivery pass for one tenant."""

    slug: str
    result: DeliveryResult
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.result.ok


def _destinations_for(tenant: Tenant, engine: Engine | None) -> list[DeliveryDestination]:
    with session_for_control(engine) as control:
        return list(
            control.scalars(
                select(DeliveryDestination).where(
                    DeliveryDestination.tenant_id == tenant.tenant_id,
                    DeliveryDestination.active.is_(True),
                )
            ).all()
        )


def deliver_for_tenant(
    tenant: Tenant | str,
    *,
    secrets: SecretStore | None = None,
    settings: Settings | None = None,
    engine: Engine | None = None,
    bulletin_ids: Iterable[int] | None = None,
) -> TenantDelivery:
    """Send one tenant's issued bulletins to its destinations."""
    config = settings or get_settings()
    store = secrets or build_secret_store(settings=config)

    if isinstance(tenant, str):
        from aegis.db.tenancy import get_tenant

        with session_for_control(engine) as control:
            tenant = get_tenant(control, tenant)

    destinations = _destinations_for(tenant, engine)
    if not destinations:
        log.info("delivery.no_destinations", slug=tenant.slug)
        return TenantDelivery(slug=tenant.slug, result=DeliveryResult())

    with tenant_session_scope(tenant, engine) as session:
        result = send_bulletins(
            session,
            destinations,
            secrets=store,
            settings=config,
            bulletin_ids=bulletin_ids,
        )

    _audit(tenant.slug, result, engine=engine)
    return TenantDelivery(slug=tenant.slug, result=result)


def deliver_all_tenants(
    *,
    slugs: Iterable[str] | None = None,
    secrets: SecretStore | None = None,
    settings: Settings | None = None,
    engine: Engine | None = None,
) -> Sequence[TenantDelivery]:
    """Deliver for every active tenant, one failure not stopping the rest."""
    config = settings or get_settings()
    store = secrets or build_secret_store(settings=config)

    wanted = set(slugs) if slugs is not None else None
    with session_for_control(engine) as control:
        tenants = [
            tenant for tenant in active_tenants(control) if wanted is None or tenant.slug in wanted
        ]

    results: list[TenantDelivery] = []
    for tenant in tenants:
        try:
            results.append(
                deliver_for_tenant(tenant, secrets=store, settings=config, engine=engine)
            )
        except Exception as exc:
            log.error("delivery.tenant_failed", slug=tenant.slug, error=str(exc))
            results.append(
                TenantDelivery(slug=tenant.slug, result=DeliveryResult(), error=str(exc))
            )
    return results


def _audit(slug: str, result: DeliveryResult, *, engine: Engine | None) -> None:
    """Record the delivery on the audit trail (spec §11)."""
    if result.sent == 0 and result.failed == 0 and not result.misconfigured:
        return

    from aegis.auth.audit import audit_trail

    with audit_trail(engine=engine) as trail:
        trail.record(
            principal=principal_for_service("delivery", tenants=[slug]),
            action=AuditAction.BULLETIN_DELIVERED,
            outcome=(AuditOutcome.ALLOWED if result.ok else AuditOutcome.FAILED),
            tenant_slug=slug,
            resource_type="bulletin",
            reason=(
                f"missing secret for: {', '.join(result.misconfigured)}"
                if result.misconfigured
                else None
            ),
            detail={
                "sent": result.sent,
                "failed": result.failed,
                "skipped": result.skipped,
            },
        )
