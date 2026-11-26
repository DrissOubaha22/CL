"""Turning probe observations into a verdict (spec §6.2, §6.3).

The probes report what they saw; this decides what it means for a match.
Two rules from §6.2 govern every branch here:

* **Never escalate on assumption.** A check that cannot confirm reachability
  leaves the match at its pre-verification tier.  ``INCONCLUSIVE`` is a real
  outcome, distinct from ``UNREACHABLE``, because "we could not look" and
  "nothing is there" license different conclusions.
* **Every check is logged.** A :class:`Verification` row is written for every
  attempt, including the ones that concluded nothing, so an escalation can be
  explained from the evidence that produced it.

Version confirmation is the check that cuts false positives (§14 phase 3): a
match resting on a scanner's stale record dies here, when the live service
turns out to run something else.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.config import Settings, get_settings
from aegis.core.enums import MatchFlag, VerificationOutcome
from aegis.core.versions import UnparseableVersion, version_in_range
from aegis.db.models import AffectedCpe, Asset, Match, Verification
from aegis.verification.probes import NetworkProber, ProbeObservation, Prober
from aegis.verification.scope import (
    OutOfScope,
    ProbeTarget,
    assert_host_in_scope,
    is_verifiable,
)

log = structlog.get_logger(__name__)

__all__ = ["VerificationResult", "verify_match", "verify_matches"]

#: Ports to try when the inventory never recorded one.  Deliberately short:
#: §6.2 forbids port scanning, so this is "the obvious port for a web-facing
#: service", not a sweep.
_DEFAULT_PORTS: dict[bool, int] = {True: 443, False: 80}


@dataclass(slots=True)
class VerificationResult:
    """Outcome of verifying one batch of matches."""

    considered: int = 0
    probed: int = 0
    confirmed: int = 0
    unreachable: int = 0
    fronted: int = 0
    version_mismatch: int = 0
    inconclusive: int = 0
    skipped: int = 0
    #: Matches whose live service contradicted the advisory - the false
    #: positives §14 phase 3 is measured by.
    false_positives_cut: int = 0


def verify_matches(
    session: Session,
    *,
    match_ids: Iterable[int] | None = None,
    prober: Prober | None = None,
    settings: Settings | None = None,
    now: datetime | None = None,
    force: bool = False,
) -> VerificationResult:
    """Verify the exposure behind open matches.

    Args:
        session: A tenant-scoped session.
        match_ids: Restrict to these matches; defaults to every open match.
        prober: Override the prober (tests pass a stub).
        settings: Override configuration.
        now: Timestamp for the pass.
        force: Re-verify even matches checked inside the freshness window.

    Returns:
        Counts by outcome.
    """
    config = settings or get_settings()
    when = now or datetime.now(UTC)
    result = VerificationResult()

    matches = _open_matches(session, match_ids)
    result.considered = len(matches)
    if not matches:
        return result

    if not config.verification_enabled:
        # Nothing is probed and nothing is claimed; every match keeps its
        # unverified tier (spec §6.2).
        log.warning("verify.disabled", considered=result.considered)
        result.skipped = result.considered
        return result

    active_prober = prober or NetworkProber(settings=config)
    freshness = timedelta(hours=config.verification_ttl_hours)

    for match in matches:
        asset = match.asset

        if not is_verifiable(asset.exposure_class):
            # Spec §6.3: perimeter reachability is not this asset's risk basis.
            _record(
                session,
                match,
                VerificationOutcome.NOT_APPLICABLE,
                when=when,
                detail={"exposure_class": str(asset.exposure_class)},
            )
            result.skipped += 1
            continue

        if not force and _recently_checked(session, match, when, freshness):
            result.skipped += 1
            continue

        target = _target_for(asset, config)
        if target is None:
            _record(
                session,
                match,
                VerificationOutcome.INCONCLUSIVE,
                when=when,
                error="asset names no probeable host:port",
            )
            result.inconclusive += 1
            continue

        observation = active_prober.probe(target)
        result.probed += 1

        outcome = _interpret(session, match, asset, observation)
        _record(
            session,
            match,
            outcome,
            when=when,
            target=target,
            observation=observation,
        )
        _apply_outcome(session, match, asset, outcome, when)
        _tally(result, outcome)

    session.flush()
    log.info(
        "verify.finished",
        considered=result.considered,
        probed=result.probed,
        confirmed=result.confirmed,
        unreachable=result.unreachable,
        false_positives_cut=result.false_positives_cut,
    )
    return result


def verify_match(
    session: Session,
    match: Match,
    *,
    prober: Prober | None = None,
    settings: Settings | None = None,
    now: datetime | None = None,
) -> VerificationResult:
    """Verify a single match."""
    return verify_matches(
        session,
        match_ids=[match.match_id],
        prober=prober,
        settings=settings,
        now=now,
        force=True,
    )


def _tally(result: VerificationResult, outcome: VerificationOutcome) -> None:
    """Count the outcome, and the false positives it cut."""
    if outcome is VerificationOutcome.CONFIRMED:
        result.confirmed += 1
    elif outcome is VerificationOutcome.FRONTED:
        result.fronted += 1
    elif outcome is VerificationOutcome.VERSION_MISMATCH:
        result.version_mismatch += 1
        result.false_positives_cut += 1
    elif outcome is VerificationOutcome.UNREACHABLE:
        result.unreachable += 1
        # Not reachable from the internet means the exposure that justified
        # the finding is not there (spec §6.1).
        result.false_positives_cut += 1
    else:
        result.inconclusive += 1


# --------------------------------------------------------------------------
# interpretation
# --------------------------------------------------------------------------


def _interpret(
    session: Session, match: Match, asset: Asset, observation: ProbeObservation
) -> VerificationOutcome:
    """Decide what the observation means for this match (spec §6.1)."""
    if observation.detail.get("out_of_scope"):
        return VerificationOutcome.INCONCLUSIVE

    if not observation.reachable:
        # Spec §6.1: behind NAT, WAF or filtering - or simply not there.
        return VerificationOutcome.UNREACHABLE

    # Spec §6.1: a fronted origin must not be escalated as directly
    # exploitable.  Checked before the version, because what answered was the
    # proxy, so its banner says nothing about the origin's version.
    if observation.waf_detected:
        return VerificationOutcome.FRONTED

    confirmation = _confirm_version(session, match, asset, observation)
    if confirmation is False:
        return VerificationOutcome.VERSION_MISMATCH
    if confirmation is True:
        return VerificationOutcome.CONFIRMED

    # Reachable, not fronted, but the service does not publish a version.
    # Reachability is established; the version is not contradicted.
    return VerificationOutcome.CONFIRMED


def _confirm_version(
    session: Session, match: Match, asset: Asset, observation: ProbeObservation
) -> bool | None:
    """Does the live version still fall in the advisory's affected range?

    Returns:
        ``True`` when the live version is affected, ``False`` when the live
        service runs something outside the range - the stale-record case §6.1
        is aimed at - and ``None`` when the banner says nothing, which is
        common and is not evidence either way.
    """
    observed = observation.observed_version
    if not observed:
        return None

    # Only trust the banner when it names the product we believe is there.
    expected_product = asset.product_name.strip().lower()
    seen_product = (observation.observed_product or "").lower()
    if (
        seen_product
        and seen_product not in expected_product
        and expected_product not in seen_product
    ):
        observation.detail["product_mismatch"] = {
            "expected": expected_product,
            "observed": seen_product,
        }
        return None

    ranges = session.scalars(
        select(AffectedCpe).where(
            AffectedCpe.cve_id == match.cve_id,
            AffectedCpe.vulnerable.is_(True),
        )
    ).all()
    if not ranges:
        return None

    for affected in ranges:
        try:
            in_range = version_in_range(
                observed,
                exact=affected.version_exact,
                start_including=affected.version_start_including,
                start_excluding=affected.version_start_excluding,
                end_including=affected.version_end_including,
                end_excluding=affected.version_end_excluding,
            )
        except UnparseableVersion:
            # The live banner is not orderable: no conclusion either way.
            return None
        if in_range:
            return True

    return False


def _apply_outcome(
    session: Session,
    match: Match,
    asset: Asset,
    outcome: VerificationOutcome,
    when: datetime,
) -> None:
    """Write the outcome back onto the asset and the match."""
    if outcome.is_reachable:
        # Exposure is now evidence, not assumption: clears the §5.3 gate.
        asset.exposure_verified_at = when
        match.flags = [flag for flag in match.flags if flag != str(MatchFlag.UNVERIFIED)]

    if outcome is VerificationOutcome.VERSION_MISMATCH:
        # The live service contradicts the advisory: this was a false
        # positive, so it stops being an open finding (spec §14 phase 3).
        match.resolved_at = when

    if outcome is VerificationOutcome.UNREACHABLE:
        # Not reachable from the internet: the asset is not internet-facing
        # after all, whatever discovery recorded (spec §6.1).
        asset.exposure_verified_at = None
        if str(MatchFlag.UNVERIFIED) not in match.flags:
            match.flags = [*match.flags, str(MatchFlag.UNVERIFIED)]


def _record(
    session: Session,
    match: Match,
    outcome: VerificationOutcome,
    *,
    when: datetime,
    target: ProbeTarget | None = None,
    observation: ProbeObservation | None = None,
    error: str | None = None,
    detail: dict[str, object] | None = None,
) -> Verification:
    """Append the audit row §6.2 requires for every check."""
    row = Verification(
        match_id=match.match_id,
        outcome=outcome,
        reachable=bool(observation and observation.reachable),
        version_confirmed=outcome is VerificationOutcome.CONFIRMED,
        waf_detected=bool(observation and observation.waf_detected),
        target_host=target.host if target else None,
        target_port=target.port if target else None,
        observed_version=observation.observed_version if observation else None,
        observed_banner=observation.banner if observation else None,
        waf_vendor=observation.waf_vendor if observation else None,
        latency_ms=observation.latency_ms if observation else None,
        error=error or (observation.error if observation else None),
        evidence={**(observation.detail if observation else {}), **(detail or {})},
        checked_at=when,
    )
    session.add(row)
    return row


# --------------------------------------------------------------------------
# selection
# --------------------------------------------------------------------------


def _open_matches(session: Session, match_ids: Iterable[int] | None) -> Sequence[Match]:
    statement = select(Match).where(Match.resolved_at.is_(None))
    if match_ids is not None:
        ids = list(match_ids)
        if not ids:
            return []
        statement = select(Match).where(Match.match_id.in_(ids))
    return list(session.scalars(statement).all())


def _recently_checked(session: Session, match: Match, now: datetime, freshness: timedelta) -> bool:
    """Has this match been verified inside the freshness window?"""
    latest = session.scalars(
        select(Verification.checked_at)
        .where(Verification.match_id == match.match_id)
        .order_by(Verification.checked_at.desc())
        .limit(1)
    ).first()
    return latest is not None and now - latest < freshness


def _target_for(asset: Asset, settings: Settings) -> ProbeTarget | None:
    """Build the single target this asset's match names (spec §6.2).

    Only the shape is checked here - a malformed host, a port out of range, a
    literal private address.  Name resolution is network I/O and belongs to
    the prober, which also keeps this engine testable without DNS.
    """
    host = asset.address or asset.hostname
    expect_tls = asset.port is None or asset.port not in (80, 8080)
    port = asset.port or _DEFAULT_PORTS[expect_tls]

    try:
        assert_host_in_scope(host, port, allow_private=settings.verification_allow_private_targets)
    except OutOfScope as exc:
        log.info("verify.out_of_scope", host=host, port=port, reason=str(exc))
        return None

    return ProbeTarget(host=host, port=port, expect_tls=expect_tls)
