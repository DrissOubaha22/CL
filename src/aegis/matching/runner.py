"""Running the matcher across tenants (spec §10, steps 3 and 6).

Matching is per tenant because inventory is per tenant, but it is driven by
the shared intel store: new intel means re-matching every tenant against the
CVEs that changed, not re-matching everything.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

import structlog
from sqlalchemy.engine import Engine

from aegis.core.enums import RunStatus
from aegis.db.models import Tenant
from aegis.db.tenancy import active_tenants, session_for_control, tenant_session_scope
from aegis.matching.engine import MatchOutcome, reset_context_cache, run_matching

log = structlog.get_logger(__name__)

__all__ = ["TenantMatchResult", "match_all_tenants", "match_tenant"]


@dataclass(slots=True)
class TenantMatchResult:
    """A matching pass for one tenant."""

    slug: str
    outcome: MatchOutcome

    @property
    def ok(self) -> bool:
        return self.outcome.ok


def match_tenant(
    tenant: Tenant | str,
    *,
    cve_ids: list[str] | None = None,
    engine: Engine | None = None,
) -> TenantMatchResult:
    """Match one tenant's inventory against the intel store."""
    slug = tenant if isinstance(tenant, str) else tenant.slug
    with tenant_session_scope(tenant, engine) as session:
        outcome = run_matching(session, cve_ids=cve_ids)
    return TenantMatchResult(slug=slug, outcome=outcome)


def match_all_tenants(
    *,
    cve_ids: list[str] | None = None,
    slugs: Iterable[str] | None = None,
    engine: Engine | None = None,
) -> Sequence[TenantMatchResult]:
    """Match every active tenant.

    One tenant failing does not stop the others: with isolated schemas a
    failure is contained to that tenant, and stopping would leave the rest
    unmatched for no benefit.
    """
    # The advisory-context cache is keyed on CVE and valid for the whole
    # sweep; the intel store is read-only while matching runs.
    reset_context_cache()

    wanted = set(slugs) if slugs is not None else None
    with session_for_control(engine) as control:
        tenants = [
            tenant for tenant in active_tenants(control) if wanted is None or tenant.slug in wanted
        ]

    results: list[TenantMatchResult] = []
    for tenant in tenants:
        try:
            results.append(match_tenant(tenant, cve_ids=cve_ids, engine=engine))
        except Exception as exc:
            log.error("match.tenant_failed", slug=tenant.slug, error=str(exc))
            results.append(
                TenantMatchResult(
                    slug=tenant.slug,
                    outcome=MatchOutcome(status=RunStatus.FAILED, error=str(exc)),
                )
            )
    return results
