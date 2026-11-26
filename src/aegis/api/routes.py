"""Tenant-scoped REST endpoints (spec §12).

Every route below takes its tenant from the path and its authorisation from
a :func:`~aegis.api.deps.tenant_access` dependency, so the three things §11
requires - authentication, per-tenant scoping, audit - happen before any
handler body runs.  A handler that forgot one would have to construct its
own session, which is visible in review.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.sql import Select

from aegis import __version__
from aegis.api.deps import TenantContext, platform_access, tenant_access
from aegis.api.schemas import (
    AssetOut,
    AuditEventOut,
    BulletinDetailOut,
    BulletinOut,
    BulletinReviewIn,
    CaseOut,
    HealthOut,
    Page,
    TenantOut,
)
from aegis.auth.audit import AuditTrail
from aegis.auth.rbac import Permission
from aegis.core.enums import AuditAction, AuditOutcome, BulletinStatus, Tier
from aegis.db.models import Asset, Bulletin, Match, Score
from aegis.db.ordering import tier_order

log = structlog.get_logger(__name__)

router = APIRouter()

ReadInventory = Annotated[TenantContext, Depends(tenant_access(Permission.READ_INVENTORY))]
ReadCase = Annotated[TenantContext, Depends(tenant_access(Permission.READ_CASE))]
ReadBulletin = Annotated[TenantContext, Depends(tenant_access(Permission.READ_BULLETIN))]
ReviewBulletin = Annotated[TenantContext, Depends(tenant_access(Permission.REVIEW_BULLETIN))]
ReadAudit = Annotated[TenantContext, Depends(tenant_access(Permission.READ_AUDIT))]
PlatformAudit = Annotated[AuditTrail, Depends(platform_access(Permission.READ_PLATFORM_AUDIT))]

Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0)]


@router.get("/health", response_model=HealthOut, tags=["platform"])
def health() -> HealthOut:
    """Liveness. Deliberately unauthenticated and says nothing else."""
    return HealthOut(version=__version__)


@router.get("/tenants/{slug}", response_model=TenantOut, tags=["tenant"])
def read_tenant(ctx: ReadCase) -> TenantOut:
    """The tenant's own record."""
    return TenantOut(
        slug=ctx.tenant.slug,
        name=ctx.tenant.name,
        region=ctx.tenant.region,
        automation_policy=str(ctx.tenant.automation_policy),
    )


@router.get("/tenants/{slug}/assets", response_model=Page[AssetOut], tags=["inventory"])
def list_assets(
    ctx: ReadInventory,
    limit: Limit = 50,
    offset: Offset = 0,
    hostname: Annotated[str | None, Query(max_length=253)] = None,
) -> Page[AssetOut]:
    """The tenant's active inventory (spec §3)."""
    statement = select(Asset).where(Asset.retired_at.is_(None))
    if hostname:
        statement = statement.where(Asset.hostname.ilike(f"%{hostname}%"))

    total = _count(ctx, statement)
    rows = ctx.session.scalars(
        statement.order_by(Asset.hostname, Asset.product_name).offset(offset).limit(limit)
    ).all()

    return Page[AssetOut](
        items=[AssetOut.model_validate(row) for row in rows],
        count=total,
        next_offset=_next_offset(offset, limit, total),
    )


@router.get("/tenants/{slug}/cases", response_model=Page[CaseOut], tags=["cases"])
def list_cases(
    ctx: ReadCase,
    limit: Limit = 50,
    offset: Offset = 0,
    tier: Annotated[Tier | None, Query()] = None,
    auto_only: Annotated[bool, Query()] = False,
) -> Page[CaseOut]:
    """Scored, open cases, most severe first (spec §7)."""
    statement = (
        select(Match, Asset, Score)
        .join(Asset, Asset.asset_id == Match.asset_id)
        .join(Score, Score.match_id == Match.match_id)
        .where(Match.resolved_at.is_(None))
    )
    if tier is not None:
        statement = statement.where(Score.tier == tier)
    if auto_only:
        statement = statement.where(Score.auto_escalatable.is_(True))

    total = _count(ctx, statement)
    rows = ctx.session.execute(
        statement.order_by(tier_order(Score.tier).desc(), Score.due_at).offset(offset).limit(limit)
    ).all()

    return Page[CaseOut](
        items=[_case_out(match, asset, score) for match, asset, score in rows],
        count=total,
        next_offset=_next_offset(offset, limit, total),
    )


@router.get("/tenants/{slug}/bulletins", response_model=Page[BulletinOut], tags=["bulletins"])
def list_bulletins(
    ctx: ReadBulletin,
    limit: Limit = 50,
    offset: Offset = 0,
    bulletin_status: Annotated[BulletinStatus | None, Query(alias="status")] = None,
) -> Page[BulletinOut]:
    """Bulletins, most severe first (spec §8)."""
    statement = select(Bulletin)
    if bulletin_status is not None:
        statement = statement.where(Bulletin.status == bulletin_status)

    total = _count(ctx, statement)
    rows = ctx.session.scalars(
        statement.order_by(tier_order(Bulletin.tier).desc(), Bulletin.cve_id)
        .offset(offset)
        .limit(limit)
    ).all()

    return Page[BulletinOut](
        items=[BulletinOut.model_validate(row) for row in rows],
        count=total,
        next_offset=_next_offset(offset, limit, total),
    )


@router.get(
    "/tenants/{slug}/bulletins/{bulletin_id}",
    response_model=BulletinDetailOut,
    tags=["bulletins"],
)
def read_bulletin(ctx: ReadBulletin, bulletin_id: int) -> BulletinDetailOut:
    """One bulletin, with its text and the model's draft."""
    bulletin = ctx.session.get(Bulletin, bulletin_id)
    if bulletin is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such bulletin")
    return BulletinDetailOut.model_validate(bulletin)


@router.post(
    "/tenants/{slug}/bulletins/{bulletin_id}/review",
    response_model=BulletinDetailOut,
    tags=["bulletins"],
)
def review_bulletin(
    ctx: ReviewBulletin, bulletin_id: int, decision: BulletinReviewIn
) -> BulletinDetailOut:
    """Release or reject a queued bulletin (spec §8.2).

    Only a queued bulletin can be reviewed: re-deciding one already issued
    would rewrite history that the audit log says happened.
    """
    bulletin = ctx.session.get(Bulletin, bulletin_id)
    if bulletin is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="no such bulletin")
    if not bulletin.awaits_review:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"bulletin is already {bulletin.status}",
        )

    now = datetime.now(UTC)
    bulletin.analyst = ctx.principal.subject
    bulletin.reviewed_at = now
    bulletin.status = BulletinStatus.ISSUED if decision.approve else BulletinStatus.REJECTED
    if decision.approve:
        bulletin.issued_at = now
    if decision.note:
        bulletin.detail = {**bulletin.detail, "analyst_note": decision.note}

    ctx.session.flush()
    ctx.audit.record(
        principal=ctx.principal,
        action=AuditAction.BULLETIN_REVIEWED,
        outcome=AuditOutcome.ALLOWED,
        tenant_slug=ctx.tenant.slug,
        resource_type="bulletin",
        resource_id=bulletin_id,
        reason=("approved" if decision.approve else "rejected"),
        detail={"cve_id": bulletin.cve_id, "tier": str(bulletin.tier)},
    )
    log.info(
        "bulletin.reviewed",
        tenant=ctx.tenant.slug,
        bulletin=bulletin_id,
        analyst=ctx.principal.subject,
        approved=decision.approve,
    )
    return BulletinDetailOut.model_validate(bulletin)


@router.get("/tenants/{slug}/audit", response_model=Page[AuditEventOut], tags=["audit"])
def list_tenant_audit(ctx: ReadAudit, limit: Limit = 50) -> Page[AuditEventOut]:
    """The tenant's own audit trail (spec §11)."""
    events = ctx.audit.events_for_tenant(ctx.tenant.slug, limit=limit)
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(event) for event in events],
        count=len(events),
    )


@router.get("/audit/denials", response_model=Page[AuditEventOut], tags=["platform"])
def list_denials(audit: PlatformAudit, limit: Limit = 50) -> Page[AuditEventOut]:
    """Every refused attempt, across tenants (spec §11).

    The view that exists so a cross-tenant attempt is noticed rather than
    merely blocked.
    """
    events = audit.denials(limit=limit)
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(event) for event in events],
        count=len(events),
    )


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _case_out(match: Match, asset: Asset, score: Score) -> CaseOut:
    return CaseOut(
        match_id=match.match_id,
        cve_id=match.cve_id,
        tier=score.tier,
        tier_before_gate=score.tier_before_gate,
        auto_escalatable=score.auto_escalatable,
        due_at=score.due_at,
        remediation_window=score.tier.remediation_window,
        confidence=match.confidence,
        flags=list(match.flags or []),
        hostname=asset.hostname,
        product=asset.product_name,
        version=asset.version,
        exposure_class=asset.exposure_class,
        criticality=asset.criticality,
        exposure_verified_at=asset.exposure_verified_at,
        matched_range=match.matched_range,
        first_matched_at=match.first_matched_at,
        cap_reasons=list((score.factors or {}).get("cap_reasons") or []),
    )


def _count(ctx: TenantContext, statement: Select[*tuple[Any, ...]]) -> int:
    """Total rows a listing query would return, for the page header."""
    return ctx.session.scalar(select(func.count()).select_from(statement.subquery())) or 0


def _next_offset(offset: int, limit: int, total: int) -> int | None:
    nxt = offset + limit
    return nxt if nxt < total else None
