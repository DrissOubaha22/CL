"""API response shapes (spec §12).

Response models are explicit rather than serialised ORM rows, for a reason
that matters here more than usual: an ORM row serialised wholesale leaks
whatever column is added to it next.  These say exactly what a client sees,
and a new internal column stays internal until someone adds it here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from aegis.core.enums import (
    BulletinStatus,
    Criticality,
    ExposureClass,
    MatchConfidence,
    ProductClass,
    Tier,
)

__all__ = [
    "AssetOut",
    "AuditEventOut",
    "BulletinDetailOut",
    "BulletinOut",
    "BulletinReviewIn",
    "CaseOut",
    "HealthOut",
    "Page",
    "TenantOut",
]


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class HealthOut(BaseModel):
    status: str = "ok"
    version: str


class TenantOut(_Out):
    slug: str
    name: str
    region: str | None = None
    automation_policy: str


class AssetOut(_Out):
    asset_id: int
    hostname: str
    product_name: str
    version: str | None
    exposure_class: ExposureClass
    criticality: Criticality
    product_class: ProductClass
    match_confidence: MatchConfidence
    exposure_verified_at: datetime | None
    first_seen_at: datetime
    last_seen_at: datetime


class CaseOut(BaseModel):
    """A scored match, as the portal shows it."""

    match_id: int
    cve_id: str
    tier: Tier
    #: What §7.2 produced before §5.3's caps, so a Medium can explain itself.
    tier_before_gate: Tier
    auto_escalatable: bool
    due_at: datetime | None
    remediation_window: str
    confidence: MatchConfidence
    flags: list[str] = Field(default_factory=list)
    hostname: str
    product: str
    version: str | None
    exposure_class: ExposureClass
    criticality: Criticality
    exposure_verified_at: datetime | None
    matched_range: str | None
    first_matched_at: datetime
    #: Why the tier was capped, when it was.
    cap_reasons: list[str] = Field(default_factory=list)


class BulletinOut(_Out):
    bulletin_id: int
    match_id: int
    cve_id: str
    tier: Tier
    status: BulletinStatus
    auto_issued: bool
    review_reasons: list[str] = Field(default_factory=list)
    analyst: str | None
    issued_at: datetime | None
    created_at: datetime


class BulletinDetailOut(BulletinOut):
    """A bulletin with its text.

    ``draft_body`` is the half a model wrote, kept separate so a reviewer
    can confirm no client field appears in it (spec §8.1).
    """

    body: str
    draft_body: str | None
    drafted_by: str | None


class BulletinReviewIn(BaseModel):
    """An analyst's decision on a queued bulletin (spec §8.2)."""

    model_config = ConfigDict(extra="forbid")

    approve: bool
    note: str | None = Field(default=None, max_length=1000)


class AuditEventOut(_Out):
    id: int
    occurred_at: datetime
    subject: str
    action: str
    outcome: str
    tenant_slug: str | None
    permission: str | None
    resource_type: str | None
    resource_id: str | None
    reason: str | None


#: The project targets Python 3.11, so PEP 695 generic syntax is not
#: available; this is the same thing spelled the older way.
T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    """A page of results, with the cursor to ask for the next one."""

    items: list[T]
    count: int
    #: Offset to pass as ``offset`` for the next page, or ``None`` at the end.
    next_offset: int | None = None
