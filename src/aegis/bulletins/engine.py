"""Generating bulletins for a tenant (spec §8, §10 steps 7-8).

One bulletin per scored match. The order is fixed by §8.1: draft from the
public intel record, then merge the tenant's own fields into the template.
Routing (§8.2) decides whether the result is issued or queued.

Drafts are cached per CVE within a run: ten hosts running the same
vulnerable FortiOS share one public draft, because the public half of the
bulletin does not depend on which host it is. That is a cost decision and a
consistency one - ten clients reading ten slightly different explanations of
the same CVE is worse than ten reading the same one.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from sqlalchemy import Row, select
from sqlalchemy.orm import Session

from aegis.ai.client import LlmClient
from aegis.bulletins.drafting import Draft, draft_public_prose, public_view_of
from aegis.bulletins.routing import RoutingInputs, route_bulletin
from aegis.bulletins.templates import TenantContext, render_bulletin
from aegis.core.enums import (
    AutomationPolicy,
    BulletinStatus,
    ExploitStatus,
    FeedSource,
)
from aegis.db.models import (
    AffectedCpe,
    Asset,
    Bulletin,
    IntelContribution,
    IntelRecord,
    Match,
    Score,
)

log = structlog.get_logger(__name__)

__all__ = ["BulletinResult", "generate_bulletins"]

BulletinRow = Row[Match, Asset, Score, IntelRecord]

#: Exploitation fields where two sources disagreeing is "conflicting intel"
#: in the sense of spec §8.2.
_EXPLOITATION_FIELDS = ("vendor_confirmed", "exploited_in_wild", "on_kev")


@dataclass(slots=True)
class BulletinResult:
    """Outcome of one bulletin-generation pass."""

    considered: int = 0
    created: int = 0
    auto_issued: int = 0
    queued: int = 0
    skipped_existing: int = 0
    drafts_from_model: int = 0
    drafts_fallback: int = 0
    error: str | None = None
    #: CVEs whose draft the model wrote, for the run detail.
    by_tier: dict[str, int] = field(default_factory=dict)


def generate_bulletins(
    session: Session,
    *,
    llm: LlmClient | None = None,
    model_name: str | None = None,
    automation_policy: AutomationPolicy = AutomationPolicy.REVIEW_ALL,
    match_ids: Iterable[int] | None = None,
    now: datetime | None = None,
    regenerate: bool = False,
) -> BulletinResult:
    """Draft and route a bulletin for each scored, open match.

    Args:
        session: A tenant-scoped session.
        llm: The model client, or ``None`` for the deterministic fallback.
        model_name: Recorded on bulletins the model drafted.
        automation_policy: The tenant's policy (spec §8.2, "under tenant
            policy").
        match_ids: Restrict to these matches.
        now: Timestamp for the pass.
        regenerate: Replace existing bulletins rather than skipping matches
            that already have one.

    Returns:
        Counts, including how many were issued without a human.
    """
    when = now or datetime.now(UTC)
    result = BulletinResult()

    rows = _rows_to_draft(session, match_ids)
    result.considered = len(rows)
    if not rows:
        return result

    existing = _existing_bulletins(session, [row[0].match_id for row in rows])
    drafts: dict[str, Draft] = {}

    for match, asset, score, intel in rows:
        if not regenerate and match.match_id in existing:
            result.skipped_existing += 1
            continue

        draft = drafts.get(intel.cve_id)
        if draft is None:
            view = public_view_of(intel, affected_summary=_affected_summary(session, intel.cve_id))
            draft = draft_public_prose(view, llm=llm, model_name=model_name)
            drafts[intel.cve_id] = draft
            if draft.is_model_written:
                result.drafts_from_model += 1
            else:
                result.drafts_fallback += 1

        decision = route_bulletin(
            RoutingInputs(
                tier=score.tier,
                exploit_status=ExploitStatus(intel.exploit_status),
                vendor_confirmed=intel.vendor_confirmed,
                patch_available=intel.patch_available,
                exposure_verified=asset.exposure_verified_at is not None,
                criticality=asset.criticality,
                auto_escalatable=score.auto_escalatable,
                automation_policy=automation_policy,
                conflicting_intel=_has_conflicting_intel(session, intel.cve_id),
                draft_unavailable=not draft.is_model_written and llm is not None,
            )
        )

        body = render_bulletin(
            cve_id=intel.cve_id,
            draft=draft.text,
            context=_context_for(match, asset, score, intel),
        )

        bulletin = existing.get(match.match_id)
        if bulletin is None:
            bulletin = Bulletin(match_id=match.match_id, cve_id=intel.cve_id)
            session.add(bulletin)

        bulletin.tier = score.tier
        bulletin.body = body
        bulletin.draft_body = draft.text
        bulletin.drafted_by = draft.model
        bulletin.review_reasons = decision.reason_values
        bulletin.detail = {
            "routing": decision.explain(),
            "mandatory_review": decision.mandatory_review,
        }

        if decision.auto_issue:
            bulletin.status = BulletinStatus.AUTO_ISSUED
            bulletin.auto_issued = True
            bulletin.issued_at = when
            result.auto_issued += 1
            # Spec §8.2 row 1: auto-issued, and logged.
            log.info(
                "bulletin.auto_issued",
                cve=intel.cve_id,
                tier=str(score.tier),
                match_id=match.match_id,
            )
        else:
            bulletin.status = BulletinStatus.QUEUED
            bulletin.auto_issued = False
            bulletin.issued_at = None
            result.queued += 1

        result.created += 1
        key = str(score.tier)
        result.by_tier[key] = result.by_tier.get(key, 0) + 1

    session.flush()
    log.info(
        "bulletin.run_finished",
        considered=result.considered,
        created=result.created,
        auto_issued=result.auto_issued,
        queued=result.queued,
    )
    return result


def _context_for(match: Match, asset: Asset, score: Score, intel: IntelRecord) -> TenantContext:
    """The client-specific half, assembled inside the Aegis boundary."""
    verification = match.verifications[0] if match.verifications else None
    return TenantContext(
        hostname=asset.hostname,
        product=asset.product_name,
        version=asset.version,
        exposure_class=asset.exposure_class,
        criticality=asset.criticality,
        tier=score.tier,
        due_at=score.due_at,
        kev_due=_as_datetime(intel.kev_due),
        flags=tuple(match.flags or ()),
        matched_range=match.matched_range,
        exposure_verified_at=asset.exposure_verified_at,
        waf_detected=bool(verification and verification.waf_detected),
    )


def _as_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.combine(value, datetime.min.time(), tzinfo=UTC)  # type: ignore[arg-type]


def _affected_summary(session: Session, cve_id: str) -> list[str]:
    """Human-readable affected ranges, for the public draft.

    Product and version only - these come from the shared intel store and
    name no asset.
    """
    rows = session.scalars(
        select(AffectedCpe)
        .where(AffectedCpe.cve_id == cve_id, AffectedCpe.vulnerable.is_(True))
        .limit(10)
    ).all()

    summary: list[str] = []
    for row in rows:
        bounds = _render_bounds(row)
        line = f"{row.vendor} {row.product} {bounds}".strip()
        if line not in summary:
            summary.append(line)
    return summary


def _render_bounds(row: AffectedCpe) -> str:
    if row.version_exact:
        return row.version_exact
    parts: list[str] = []
    if row.version_start_including:
        parts.append(f">= {row.version_start_including}")
    if row.version_start_excluding:
        parts.append(f"> {row.version_start_excluding}")
    if row.version_end_including:
        parts.append(f"<= {row.version_end_including}")
    if row.version_end_excluding:
        parts.append(f"< {row.version_end_excluding}")
    return " ".join(parts) if parts else "(all versions)"


def _has_conflicting_intel(session: Session, cve_id: str) -> bool:
    """Do two sources disagree about exploitation (spec §8.2)?

    Only exploitation matters here: sources differing on a CVSS score is
    routine, while one source saying a CVE is exploited and another saying
    it is not is exactly the case §8.2 sends to an analyst.
    """
    contributions = session.scalars(
        select(IntelContribution).where(IntelContribution.cve_id == cve_id)
    ).all()

    for name in _EXPLOITATION_FIELDS:
        asserted = {
            bool(row.payload.get(name))
            for row in contributions
            if row.source is not FeedSource.FIRST_EPSS and row.payload.get(name) is not None
        }
        if len(asserted) > 1:
            log.info("bulletin.conflicting_intel", cve=cve_id, field=name)
            return True
    return False


def _rows_to_draft(session: Session, match_ids: Iterable[int] | None) -> list[BulletinRow]:
    """Open, scored matches joined to their asset and intel record."""
    statement = (
        select(Match, Asset, Score, IntelRecord)
        .join(Asset, Asset.asset_id == Match.asset_id)
        .join(Score, Score.match_id == Match.match_id)
        .join(IntelRecord, IntelRecord.cve_id == Match.cve_id)
        .where(Match.resolved_at.is_(None))
    )
    if match_ids is not None:
        ids = list(match_ids)
        if not ids:
            return []
        statement = statement.where(Match.match_id.in_(ids))
    return list(session.execute(statement).all())


def _existing_bulletins(session: Session, match_ids: Sequence[int]) -> dict[int, Bulletin]:
    if not match_ids:
        return {}
    rows = session.scalars(select(Bulletin).where(Bulletin.match_id.in_(list(match_ids)))).all()
    return {row.match_id: row for row in rows}
