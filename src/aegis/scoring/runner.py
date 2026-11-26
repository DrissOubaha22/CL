"""Running verification and scoring across tenants (spec §10, steps 4-5).

Step 4 verifies, step 5 scores, and they run together because a tier that
ignores a verification that just happened is a tier that will be wrong for a
cycle.  Both are per tenant, both read the shared intel store read-only.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from sqlalchemy.engine import Engine

from aegis.config import Settings
from aegis.core.enums import RunStatus
from aegis.db.models import Tenant
from aegis.db.tenancy import active_tenants, session_for_control, tenant_session_scope
from aegis.scoring.engine import ScoringResult, score_matches
from aegis.verification.engine import VerificationResult, verify_matches
from aegis.verification.probes import Prober

log = structlog.get_logger(__name__)

__all__ = ["TenantAssessment", "assess_all_tenants", "assess_tenant"]


@dataclass(slots=True)
class TenantAssessment:
    """One verify-and-score pass for one tenant."""

    slug: str
    verification: VerificationResult
    scoring: ScoringResult

    @property
    def ok(self) -> bool:
        return self.scoring.ok

    @property
    def status(self) -> RunStatus:
        return self.scoring.status


def assess_tenant(
    tenant: Tenant | str,
    *,
    verify: bool = True,
    force: bool = False,
    prober: Prober | None = None,
    settings: Settings | None = None,
    engine: Engine | None = None,
    now: datetime | None = None,
) -> TenantAssessment:
    """Verify, then score, one tenant's open matches.

    Args:
        tenant: A tenant row or slug.
        verify: Run exposure verification first.  Off re-scores from the
            verifications already on record, which is what a configuration
            change needs.
        force: Re-verify matches already checked inside the freshness window.
        prober: Override the prober (tests pass a stub).
        settings: Override configuration.
        engine: Override the engine (tests).
        now: Timestamp for the pass.
    """
    slug = tenant if isinstance(tenant, str) else tenant.slug
    when = now or datetime.now(UTC)

    with tenant_session_scope(tenant, engine) as session:
        verification = (
            verify_matches(
                session,
                prober=prober,
                settings=settings,
                now=when,
                force=force,
            )
            if verify
            else VerificationResult()
        )
        scoring = score_matches(session, now=when)

        return TenantAssessment(slug=slug, verification=verification, scoring=scoring)


def assess_all_tenants(
    *,
    slugs: Iterable[str] | None = None,
    verify: bool = True,
    force: bool = False,
    prober: Prober | None = None,
    settings: Settings | None = None,
    engine: Engine | None = None,
) -> Sequence[TenantAssessment]:
    """Verify and score every active tenant.

    One tenant failing does not stop the others; with isolated schemas the
    failure is contained to that tenant.
    """
    wanted = set(slugs) if slugs is not None else None
    with session_for_control(engine) as control:
        tenants = [
            tenant for tenant in active_tenants(control) if wanted is None or tenant.slug in wanted
        ]

    results: list[TenantAssessment] = []
    for tenant in tenants:
        try:
            results.append(
                assess_tenant(
                    tenant,
                    verify=verify,
                    force=force,
                    prober=prober,
                    settings=settings,
                    engine=engine,
                )
            )
        except Exception as exc:
            log.error("assess.tenant_failed", slug=tenant.slug, error=str(exc))
            results.append(
                TenantAssessment(
                    slug=tenant.slug,
                    verification=VerificationResult(),
                    scoring=ScoringResult(status=RunStatus.FAILED, error=str(exc)),
                )
            )
    return results
