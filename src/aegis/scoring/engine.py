"""Scoring a tenant's matches (spec §7, §10 step 5).

Reads each open match together with its asset (tenant schema) and the shared
intel record for its CVE (intel schema), computes the tier, and writes one
:class:`~aegis.db.models.tenant.Score` row per match.

Scoring performs no network access and makes no judgement about whether a
match is real: that was decided by matching (§5) and verification (§6).  It
reads their conclusions - the flags and ``exposure_verified_at`` - and turns
them into a tier and a due date.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import Row, select
from sqlalchemy.orm import Session

from aegis.core.enums import (
    REMEDIATION_HOURS,
    ExploitStatus,
    MatchFlag,
    RunStatus,
    Tier,
)
from aegis.db.models import Asset, IntelRecord, Match, Score, ScoreRun
from aegis.scoring.tiering import ScoreInputs, score_match

log = structlog.get_logger(__name__)

__all__ = ["ScoringResult", "score_matches"]

ScoringRow = Row[Match, Asset, IntelRecord]


@dataclass(slots=True)
class ScoringResult:
    """Outcome of one scoring pass."""

    status: RunStatus = RunStatus.SUCCESS
    considered: int = 0
    scored: int = 0
    tier_changed: int = 0
    skipped_no_intel: int = 0
    error: str | None = None
    #: Count per tier after the pass, for the run journal.
    by_tier: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status is RunStatus.SUCCESS


def score_matches(
    session: Session,
    *,
    match_ids: Iterable[int] | None = None,
    now: datetime | None = None,
    journal: bool = True,
) -> ScoringResult:
    """Score the tenant's open matches.

    Args:
        session: A tenant-scoped session.
        match_ids: Restrict to these matches; defaults to every open match.
        now: Timestamp for the pass.
        journal: Write a ``score_run`` row.  Off when the caller is already
            journalling a combined verify-and-score pass.

    Returns:
        Counts, including how many matches changed tier.
    """
    when = now or datetime.now(UTC)
    result = ScoringResult()

    run = None
    if journal:
        run = ScoreRun(status=RunStatus.RUNNING, started_at=when)
        session.add(run)
        session.flush()

    try:
        rows = _rows_to_score(session, match_ids)
        result.considered = len(rows)

        existing = _existing_scores(session, [row[0].match_id for row in rows])

        for match, asset, intel in rows:
            decision = score_match(_inputs_for(match, asset, intel))
            previous = existing.get(match.match_id)

            if previous is not None and previous.tier is not decision.tier:
                result.tier_changed += 1

            due_at = _due_at(decision.tier, when)

            if previous is None:
                session.add(
                    Score(
                        match_id=match.match_id,
                        tier=decision.tier,
                        tier_before_gate=decision.tier_before_gate,
                        auto_escalatable=decision.auto_escalatable,
                        due_at=due_at,
                        factors=decision.factors,
                        scored_at=when,
                    )
                )
            else:
                previous.tier = decision.tier
                previous.tier_before_gate = decision.tier_before_gate
                previous.auto_escalatable = decision.auto_escalatable
                previous.due_at = due_at
                previous.factors = decision.factors
                previous.scored_at = when

            result.scored += 1
            key = str(decision.tier)
            result.by_tier[key] = result.by_tier.get(key, 0) + 1

        result.skipped_no_intel = _count_unscorable(session, match_ids)
        session.flush()

        if run is not None:
            run.status = RunStatus.SUCCESS
            run.finished_at = datetime.now(UTC)
            run.matches_considered = result.considered
            run.matches_scored = result.scored
            run.tier_changed = result.tier_changed
            run.detail = {
                "by_tier": result.by_tier,
                "skipped_no_intel": result.skipped_no_intel,
            }
            session.flush()

    except Exception as exc:
        result.status = RunStatus.FAILED
        result.error = f"{type(exc).__name__}: {exc}"
        log.error("score.run_failed", error=result.error)
        raise

    log.info(
        "score.run_finished",
        considered=result.considered,
        scored=result.scored,
        tier_changed=result.tier_changed,
        by_tier=result.by_tier,
    )
    return result


def _inputs_for(match: Match, asset: Asset, intel: IntelRecord) -> ScoreInputs:
    """Assemble the §7.1 inputs from the three sources that hold them."""
    return ScoreInputs(
        exploit_status=ExploitStatus(intel.exploit_status),
        on_kev=intel.on_kev,
        vendor_confirmed=intel.vendor_confirmed,
        public_exploit=intel.public_exploit,
        ransomware=intel.ransomware,
        epss=intel.epss,
        exposure_class=asset.exposure_class,
        criticality=asset.criticality,
        flags=_known_flags(match.flags),
        exposure_verified=asset.exposure_verified_at is not None,
        waf_detected=_waf_seen(match),
    )


def _known_flags(flags: Sequence[str]) -> tuple[MatchFlag, ...]:
    """Parse stored flag strings, ignoring any a later release added."""
    parsed: list[MatchFlag] = []
    for value in flags or ():
        try:
            parsed.append(MatchFlag(value))
        except ValueError:
            log.warning("score.unknown_flag", flag=value)
    return tuple(parsed)


def _waf_seen(match: Match) -> bool:
    """Did the most recent verification find a proxy in front (spec §6.1)?"""
    verifications = match.verifications
    return bool(verifications) and bool(verifications[0].waf_detected)


def _due_at(tier: Tier, now: datetime) -> datetime | None:
    """Concrete deadline from the tier's remediation window (spec §7.2)."""
    hours = REMEDIATION_HOURS[tier]
    return None if hours is None else now + timedelta(hours=hours)


def _rows_to_score(session: Session, match_ids: Iterable[int] | None) -> list[ScoringRow]:
    """Open matches joined to their asset and their shared intel record.

    A match whose CVE has no intel record cannot be scored - §7.1's inputs
    all come from it - so the inner join leaves it out rather than scoring it
    on defaults.
    """
    statement = (
        select(Match, Asset, IntelRecord)
        .join(Asset, Asset.asset_id == Match.asset_id)
        .join(IntelRecord, IntelRecord.cve_id == Match.cve_id)
        .where(Match.resolved_at.is_(None))
    )
    if match_ids is not None:
        ids = list(match_ids)
        if not ids:
            return []
        statement = statement.where(Match.match_id.in_(ids))
    return list(session.execute(statement).all())


def _existing_scores(session: Session, match_ids: Sequence[int]) -> dict[int, Score]:
    if not match_ids:
        return {}
    rows = session.scalars(select(Score).where(Score.match_id.in_(list(match_ids)))).all()
    return {row.match_id: row for row in rows}


def _count_unscorable(session: Session, match_ids: Iterable[int] | None) -> int:
    """Open matches with no intel record, which scoring had to skip."""
    statement = (
        select(Match.match_id)
        .outerjoin(IntelRecord, IntelRecord.cve_id == Match.cve_id)
        .where(Match.resolved_at.is_(None), IntelRecord.cve_id.is_(None))
    )
    if match_ids is not None:
        ids = list(match_ids)
        if not ids:
            return 0
        statement = statement.where(Match.match_id.in_(ids))
    return len(session.scalars(statement).all())
