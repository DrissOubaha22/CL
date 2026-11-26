"""Running bulletin generation across tenants (spec §10, steps 7-8).

Per tenant, because bulletins are per tenant. The tenant's own automation
policy is read from the registry and passed down, so §8.2's "under tenant
policy" is honoured by the thing that actually issues.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import structlog
from sqlalchemy.engine import Engine

from aegis.ai.client import LlmClient, LlmUnavailable, build_client
from aegis.bulletins.engine import BulletinResult, generate_bulletins
from aegis.config import Settings, get_settings
from aegis.db.models import Tenant
from aegis.db.tenancy import active_tenants, session_for_control, tenant_session_scope

log = structlog.get_logger(__name__)

__all__ = ["TenantBulletins", "generate_all_tenants", "generate_for_tenant"]


@dataclass(slots=True)
class TenantBulletins:
    """One bulletin pass for one tenant."""

    slug: str
    result: BulletinResult

    @property
    def ok(self) -> bool:
        return self.result.error is None


def _resolve_llm(llm: LlmClient | None, settings: Settings) -> tuple[LlmClient | None, str | None]:
    """The model client to draft with, and its name for the audit trail.

    A deployment with the LLM off, or unreachable, drafts deterministically
    rather than issuing nothing.
    """
    if llm is not None:
        return llm, settings.llm_model
    try:
        return build_client(settings=settings), settings.llm_model
    except LlmUnavailable as exc:
        log.info("bulletin.llm_unavailable", reason=str(exc))
        return None, None


def generate_for_tenant(
    tenant: Tenant | str,
    *,
    llm: LlmClient | None = None,
    settings: Settings | None = None,
    engine: Engine | None = None,
    regenerate: bool = False,
) -> TenantBulletins:
    """Draft and route this tenant's bulletins."""
    config = settings or get_settings()

    if isinstance(tenant, str):
        with session_for_control(engine) as control:
            from aegis.db.tenancy import get_tenant

            tenant = get_tenant(control, tenant)

    client, model_name = _resolve_llm(llm, config)

    with tenant_session_scope(tenant, engine) as session:
        result = generate_bulletins(
            session,
            llm=client,
            model_name=model_name,
            automation_policy=tenant.automation_policy,
            regenerate=regenerate,
        )
    return TenantBulletins(slug=tenant.slug, result=result)


def generate_all_tenants(
    *,
    slugs: Iterable[str] | None = None,
    llm: LlmClient | None = None,
    settings: Settings | None = None,
    engine: Engine | None = None,
    regenerate: bool = False,
) -> Sequence[TenantBulletins]:
    """Generate bulletins for every active tenant.

    The model client is built once and shared: it holds a connection pool,
    and a failure to build it should degrade every tenant to deterministic
    drafting identically rather than tenant by tenant.
    """
    config = settings or get_settings()
    client, _ = _resolve_llm(llm, config)

    wanted = set(slugs) if slugs is not None else None
    with session_for_control(engine) as control:
        tenants = [
            tenant for tenant in active_tenants(control) if wanted is None or tenant.slug in wanted
        ]

    results: list[TenantBulletins] = []
    for tenant in tenants:
        try:
            results.append(
                generate_for_tenant(
                    tenant,
                    llm=client,
                    settings=config,
                    engine=engine,
                    regenerate=regenerate,
                )
            )
        except Exception as exc:
            log.error("bulletin.tenant_failed", slug=tenant.slug, error=str(exc))
            results.append(TenantBulletins(slug=tenant.slug, result=BulletinResult(error=str(exc))))
    return results
