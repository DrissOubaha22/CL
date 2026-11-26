"""The matching engine (spec §5).

Joins the shared intel store's affected-product ranges against one tenant's
inventory and emits candidate matches.  Spec §5.1 states the logic as a
nested loop; running that literally would be
``len(assets) x len(affected_cpe)`` comparisons, so it is executed in two
stages instead, with identical semantics:

1. **SQL narrows.** A single cross-schema join on ``(part, vendor, product)``
   returns only the asset/advisory pairs that name the same product.  Both
   sides carry an index on those columns.
2. **Python decides.** Version-range comparison is Aegis's own ordering
   (spec §5.2) and cannot be expressed in SQL, so each candidate pair is
   tested in process.

The join is possible in one query because per-tenant tables and the intel
schema live in the same database; the tenant side is resolved by the
session's ``schema_translate_map`` and the intel side is fixed and read-only
(spec §11).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from sqlalchemy import Row, func, select
from sqlalchemy.orm import Session

from aegis.core.cpe import ANY
from aegis.core.enums import RunStatus
from aegis.core.versions import UnparseableVersion, version_in_range
from aegis.db.models import AffectedCpe, Asset, AssetCpe, IntelRecord, Match, MatchRun
from aegis.matching.flags import evaluate_match

log = structlog.get_logger(__name__)

#: One candidate pair as the narrowing query returns it.
CandidateRow = Row[Asset, str, AffectedCpe, bool]

__all__ = ["MatchOutcome", "run_matching"]


@dataclass(slots=True)
class MatchOutcome:
    """What one matching pass did."""

    status: RunStatus = RunStatus.SUCCESS
    assets_considered: int = 0
    candidates_tested: int = 0
    matches_open: int = 0
    matches_new: int = 0
    matches_resolved: int = 0
    skipped_unparseable: int = 0
    error: str | None = None
    #: CVE ids newly matched this pass - the delta of spec §10 step 6.
    new_cve_ids: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.status is RunStatus.SUCCESS


def run_matching(
    session: Session,
    *,
    cve_ids: list[str] | None = None,
    now: datetime | None = None,
) -> MatchOutcome:
    """Match one tenant's inventory against the shared intel store.

    Args:
        session: A tenant-scoped session (see
            :func:`aegis.db.tenancy.tenant_session_scope`).
        cve_ids: Restrict to these CVEs.  Used when new intel arrives and
            only the affected CVEs need re-matching, instead of the whole
            catalogue (spec §10 steps 3 and 6).
        now: Timestamp for the pass, defaulting to the current time.

    Returns:
        Counts, plus the CVE ids newly matched.
    """
    when = now or datetime.now(UTC)
    run = MatchRun(status=RunStatus.RUNNING, started_at=when)
    session.add(run)
    session.flush()

    outcome = MatchOutcome()

    try:
        existing = _load_open_matches(session, cve_ids)
        still_matching: set[tuple[int, str, str]] = set()

        outcome.assets_considered = _count_active_assets(session)

        for row in _candidate_pairs(session, cve_ids):
            outcome.candidates_tested += 1
            verdict_key = _apply_candidate(session, row, when, existing, outcome)
            if verdict_key is not None:
                still_matching.add(verdict_key)

        outcome.matches_resolved = _resolve_stale(session, existing, still_matching, when)
        outcome.matches_open = len(still_matching)

        run.status = RunStatus.SUCCESS
        run.finished_at = datetime.now(UTC)
        run.assets_considered = outcome.assets_considered
        run.candidates_tested = outcome.candidates_tested
        run.matches_open = outcome.matches_open
        run.matches_new = outcome.matches_new
        run.matches_resolved = outcome.matches_resolved
        run.detail = {
            "skipped_unparseable": outcome.skipped_unparseable,
            "new_cve_ids": outcome.new_cve_ids[:100],
        }
        session.flush()

    except Exception as exc:
        outcome.status = RunStatus.FAILED
        outcome.error = f"{type(exc).__name__}: {exc}"
        log.error("match.run_failed", error=outcome.error)
        raise

    log.info(
        "match.run_finished",
        assets=outcome.assets_considered,
        candidates=outcome.candidates_tested,
        open=outcome.matches_open,
        new=outcome.matches_new,
        resolved=outcome.matches_resolved,
    )
    return outcome


# --------------------------------------------------------------------------
# stage 1: SQL narrows
# --------------------------------------------------------------------------


def _candidate_pairs(session: Session, cve_ids: list[str] | None) -> Iterator[CandidateRow]:
    """Asset/advisory pairs naming the same product (spec §5.1).

    Only ``vulnerable`` advisory rows take part: a non-vulnerable ``cpeMatch``
    node is platform context, not an affected product.  Retired assets are
    excluded.
    """
    statement = (
        select(
            Asset,
            AssetCpe.cpe.label("asset_cpe"),
            AffectedCpe,
            IntelRecord.config_dependent,
        )
        .join(AssetCpe, AssetCpe.asset_id == Asset.asset_id)
        .join(
            AffectedCpe,
            (AffectedCpe.part == AssetCpe.part)
            & (AffectedCpe.vendor == AssetCpe.vendor)
            & (AffectedCpe.product == AssetCpe.product),
        )
        .join(IntelRecord, IntelRecord.cve_id == AffectedCpe.cve_id)
        .where(
            Asset.retired_at.is_(None),
            AffectedCpe.vulnerable.is_(True),
        )
    )
    if cve_ids:
        statement = statement.where(AffectedCpe.cve_id.in_(cve_ids))

    # Streamed: a large tenant crossed with a full advisory set is more rows
    # than it is reasonable to materialise.
    yield from session.execute(statement).yield_per(500)


def _count_active_assets(session: Session) -> int:
    return (
        session.scalar(select(func.count()).select_from(Asset).where(Asset.retired_at.is_(None)))
        or 0
    )


# --------------------------------------------------------------------------
# stage 2: Python decides
# --------------------------------------------------------------------------


def _apply_candidate(
    session: Session,
    row: CandidateRow,
    when: datetime,
    existing: dict[tuple[int, str, str], Match],
    outcome: MatchOutcome,
) -> tuple[int, str, str] | None:
    """Test one candidate pair and persist the match if it holds."""
    asset: Asset = row[0]
    asset_cpe: str = row[1]
    affected: AffectedCpe = row[2]
    intel_config_dependent: bool = bool(row[3])

    if not _target_sw_compatible(asset_cpe, affected.target_sw):
        return None

    try:
        hit = _version_matches(asset.version, affected)
    except UnparseableVersion:
        # Spec §5.2: an unorderable version downgrades confidence; it must
        # not silently assert a match, nor silently drop a real one.  The
        # asset is matched with the flag so a human can look.
        outcome.skipped_unparseable += 1
        hit = True

    if not hit:
        return None

    verdict = evaluate_match(
        asset_confidence=asset.match_confidence,
        product_class=asset.product_class,
        from_distro_package=asset.from_distro_package,
        version_is_clean=asset.version_is_clean,
        exposure_verified_at=asset.exposure_verified_at,
        intel_config_dependent=intel_config_dependent,
        advisory_has_context_nodes=_has_context_nodes(session, affected.cve_id),
        range_is_unbounded=_is_unbounded(affected),
    )

    key = (asset.asset_id, affected.cve_id, asset_cpe)
    match = existing.get(key)

    if match is None:
        match = Match(
            asset_id=asset.asset_id,
            cve_id=affected.cve_id,
            confidence=verdict.confidence,
            flags=verdict.flag_values,
            matched_cpe=asset_cpe,
            matched_version=asset.version,
            matched_range=_render_range(affected),
            first_matched_at=when,
            last_matched_at=when,
        )
        session.add(match)
        existing[key] = match
        outcome.matches_new += 1
        if affected.cve_id not in outcome.new_cve_ids:
            outcome.new_cve_ids.append(affected.cve_id)
    else:
        match.confidence = verdict.confidence
        match.flags = verdict.flag_values
        match.matched_version = asset.version
        match.matched_range = _render_range(affected)
        match.last_matched_at = when
        # A match that re-appears is open again.
        match.resolved_at = None

    return key


def _version_matches(version: str | None, affected: AffectedCpe) -> bool:
    """Does the asset version fall inside the advisory's range (spec §5.2)?

    A product with no discovered version is matched when the advisory names
    the product without bounds, and otherwise treated as unorderable - the
    caller flags it rather than guessing either way.
    """
    if version is None:
        if _is_unbounded(affected):
            return True
        raise UnparseableVersion("asset has no version")

    return version_in_range(
        version,
        exact=affected.version_exact,
        start_including=affected.version_start_including,
        start_excluding=affected.version_start_excluding,
        end_including=affected.version_end_including,
        end_excluding=affected.version_end_excluding,
    )


def _target_sw_compatible(asset_cpe: str, advisory_target_sw: str | None) -> bool:
    """Compare ``target_sw`` only when both sides state it.

    Inventory often never recorded the hosting platform; requiring a match
    there would drop real findings.
    """
    if advisory_target_sw in (None, ANY):
        return True
    parts = asset_cpe.split(":")
    asset_target_sw = parts[9] if len(parts) > 9 else ANY
    if asset_target_sw in (ANY, "-"):
        return True
    return asset_target_sw == advisory_target_sw


def _is_unbounded(affected: AffectedCpe) -> bool:
    return not any(
        (
            affected.version_exact,
            affected.version_start_including,
            affected.version_start_excluding,
            affected.version_end_including,
            affected.version_end_excluding,
        )
    )


def _has_context_nodes(session: Session, cve_id: str) -> bool:
    """Does the advisory name products that are not themselves vulnerable?

    A ``cpeMatch`` node flagged ``vulnerable: false`` is platform context,
    which means the advisory describes a *combination* rather than a single
    affected product - the structural signal for §5.3 config dependence.
    """
    cached = _context_node_cache.get(cve_id)
    if cached is None:
        cached = (
            session.scalar(
                select(AffectedCpe.id)
                .where(
                    AffectedCpe.cve_id == cve_id,
                    AffectedCpe.vulnerable.is_(False),
                )
                .limit(1)
            )
            is not None
        )
        _context_node_cache[cve_id] = cached
    return cached


#: Per-process cache; the intel store is read-only during a matching pass.
_context_node_cache: dict[str, bool] = {}


def reset_context_cache() -> None:
    """Clear the advisory-context cache (tests, and between long runs)."""
    _context_node_cache.clear()


def _render_range(affected: AffectedCpe) -> str:
    if affected.version_exact:
        return f"== {affected.version_exact}"
    bounds = []
    if affected.version_start_including:
        bounds.append(f">={affected.version_start_including}")
    if affected.version_start_excluding:
        bounds.append(f">{affected.version_start_excluding}")
    if affected.version_end_including:
        bounds.append(f"<={affected.version_end_including}")
    if affected.version_end_excluding:
        bounds.append(f"<{affected.version_end_excluding}")
    return " ".join(bounds) if bounds else "(all versions)"


# --------------------------------------------------------------------------
# bookkeeping
# --------------------------------------------------------------------------


def _load_open_matches(
    session: Session, cve_ids: list[str] | None
) -> dict[tuple[int, str, str], Match]:
    statement = select(Match)
    if cve_ids:
        statement = statement.where(Match.cve_id.in_(cve_ids))
    rows = session.scalars(statement).all()
    return {(row.asset_id, row.cve_id, row.matched_cpe): row for row in rows}


def _resolve_stale(
    session: Session,
    existing: dict[tuple[int, str, str], Match],
    still_matching: set[tuple[int, str, str]],
    when: datetime,
) -> int:
    """Close matches that no longer hold.

    An asset upgraded out of the affected range, or an advisory that
    narrowed, must stop appearing as an open finding.
    """
    resolved = 0
    for key, match in existing.items():
        if key in still_matching or match.resolved_at is not None:
            continue
        match.resolved_at = when
        resolved += 1
    session.flush()
    return resolved
