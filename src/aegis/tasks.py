"""Celery application and scheduled intel jobs (spec §10, §13).

Collection (step 2) and refresh (step 10) run on a schedule across all
tenants; the per-tenant steps arrive in later phases and will be separate
tasks on their own queues.
"""

from __future__ import annotations

from typing import Any

import structlog
from celery import Celery
from celery.schedules import crontab

from aegis.bulletins.runner import generate_all_tenants, generate_for_tenant
from aegis.config import get_settings
from aegis.core.enums import FeedSource
from aegis.delivery.runner import deliver_all_tenants, deliver_for_tenant
from aegis.intel.runner import run_pipeline, run_pipelines
from aegis.logging import configure_logging
from aegis.matching.runner import match_all_tenants, match_tenant
from aegis.scoring.runner import assess_all_tenants, assess_tenant

log = structlog.get_logger(__name__)

settings = get_settings()

celery_app = Celery(
    "aegis",
    broker=settings.broker_url,
    backend=settings.result_backend,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="intel",
    # A feed run is long; let it finish rather than be redelivered.
    broker_transport_options={"visibility_timeout": 3600},
    beat_schedule={
        # KEV is the highest-value signal and the cheapest poll.
        "kev-hourly": {
            "task": "aegis.intel.sync_feed",
            "schedule": crontab(minute="17"),
            "args": (FeedSource.CISA_KEV.value,),
        },
        # NVD is incremental; four passes a day keeps the window small.
        "nvd-6-hourly": {
            "task": "aegis.intel.sync_feed",
            "schedule": crontab(minute="23", hour="*/6"),
            "args": (FeedSource.NVD.value,),
        },
        # EPSS republishes once a day.
        "epss-daily": {
            "task": "aegis.intel.sync_feed",
            "schedule": crontab(minute="41", hour="3"),
            "args": (FeedSource.FIRST_EPSS.value,),
        },
        # Re-match every tenant daily, to catch inventory that changed
        # without new intel.  Intel-driven re-matching is event-based: a feed
        # run that changed CVEs chains straight into match_tenants.
        "match-all-daily": {
            "task": "aegis.match.match_tenants",
            "schedule": crontab(minute="7", hour="5"),
        },
        # Verification is active network traffic, so it runs on its own
        # cadence rather than after every match pass; a fresh check costs a
        # packet, a stale tier costs a wrong decision.
        "assess-all-daily": {
            "task": "aegis.score.assess_tenants",
            "schedule": crontab(minute="29", hour="6"),
        },
        # Bulletins follow assessment: a bulletin quoting yesterday's tier
        # is worse than one that arrives an hour later.
        "bulletins-daily": {
            "task": "aegis.bulletin.generate_tenants",
            "schedule": crontab(minute="53", hour="6"),
        },
        # Delivery runs more often than generation: a bulletin whose
        # webhook was down should not wait a day for the next attempt.
        "delivery-hourly": {
            "task": "aegis.delivery.send_tenants",
            "schedule": crontab(minute="11"),
        },
    },
)


@celery_app.on_after_configure.connect
def _setup_logging(sender: Any, **_: Any) -> None:  # pragma: no cover
    configure_logging()


@celery_app.task(name="aegis.intel.sync_feed", bind=True, max_retries=2)
def sync_feed(self: Any, source: str) -> dict[str, Any]:
    """Run one deterministic feed pipeline."""
    outcome = run_pipeline(FeedSource(source))
    if not outcome.ok:
        # The run is already journalled in feed_run; retry on a backoff in
        # case the failure was the feed being briefly unavailable.
        raise self.retry(exc=RuntimeError(outcome.error or "feed run failed"), countdown=300)
    return _as_dict(outcome)


@celery_app.task(name="aegis.intel.sync_all")
def sync_all() -> list[dict[str, Any]]:
    """Run every implemented feed pipeline in order."""
    return [_as_dict(outcome) for outcome in run_pipelines()]


@celery_app.task(name="aegis.match.match_tenants")
def match_tenants(
    cve_ids: list[str] | None = None, slugs: list[str] | None = None
) -> list[dict[str, Any]]:
    """Match tenant inventory against the shared intel store (spec §10 step 3).

    Args:
        cve_ids: Re-match only these CVEs.  Passed when new intel arrives, so
            a feed run does not force a full re-match of every tenant.
        slugs: Restrict to these tenants; defaults to every active one.
    """
    results = match_all_tenants(cve_ids=cve_ids, slugs=slugs)
    return [_match_as_dict(result) for result in results]


@celery_app.task(name="aegis.match.match_one_tenant", bind=True, max_retries=2)
def match_one_tenant(self: Any, slug: str, cve_ids: list[str] | None = None) -> dict[str, Any]:
    """Match a single tenant, retrying on a transient failure."""
    result = match_tenant(slug, cve_ids=cve_ids)
    if not result.ok:
        raise self.retry(
            exc=RuntimeError(result.outcome.error or "matching failed"),
            countdown=300,
        )
    return _match_as_dict(result)


@celery_app.task(name="aegis.score.assess_tenants")
def assess_tenants(
    slugs: list[str] | None = None, verify: bool = True, force: bool = False
) -> list[dict[str, Any]]:
    """Verify exposure and score matches for every active tenant (§10 steps 4-5)."""
    results = assess_all_tenants(slugs=slugs, verify=verify, force=force)
    return [_assessment_as_dict(result) for result in results]


@celery_app.task(name="aegis.score.assess_one_tenant", bind=True, max_retries=2)
def assess_one_tenant(
    self: Any, slug: str, verify: bool = True, force: bool = False
) -> dict[str, Any]:
    """Verify and score a single tenant, retrying on a transient failure."""
    result = assess_tenant(slug, verify=verify, force=force)
    if not result.ok:
        raise self.retry(
            exc=RuntimeError(result.scoring.error or "assessment failed"),
            countdown=300,
        )
    return _assessment_as_dict(result)


@celery_app.task(name="aegis.bulletin.generate_tenants")
def generate_tenant_bulletins(
    slugs: list[str] | None = None, regenerate: bool = False
) -> list[dict[str, Any]]:
    """Draft and route bulletins for every active tenant (§10 steps 7-8)."""
    results = generate_all_tenants(slugs=slugs, regenerate=regenerate)
    return [_bulletins_as_dict(result) for result in results]


@celery_app.task(name="aegis.bulletin.generate_one_tenant", bind=True, max_retries=2)
def generate_one_tenant_bulletins(self: Any, slug: str, regenerate: bool = False) -> dict[str, Any]:
    """Draft and route one tenant's bulletins."""
    result = generate_for_tenant(slug, regenerate=regenerate)
    if not result.ok:
        raise self.retry(
            exc=RuntimeError(result.result.error or "bulletin generation failed"),
            countdown=300,
        )
    return _bulletins_as_dict(result)


@celery_app.task(name="aegis.delivery.send_tenants")
def send_tenant_deliveries(slugs: list[str] | None = None) -> list[dict[str, Any]]:
    """Send issued bulletins to each tenant's destinations (§10 step 9)."""
    return [_delivery_as_dict(item) for item in deliver_all_tenants(slugs=slugs)]


@celery_app.task(name="aegis.delivery.send_one_tenant", bind=True, max_retries=3)
def send_one_tenant_delivery(self: Any, slug: str) -> dict[str, Any]:
    """Send one tenant's bulletins, retrying a transient webhook failure."""
    item = deliver_for_tenant(slug)
    if not item.ok and not item.result.misconfigured:
        # A missing secret is not retried: retrying will not conjure it.
        raise self.retry(exc=RuntimeError(item.error or "delivery failed"), countdown=300)
    return _delivery_as_dict(item)


def _delivery_as_dict(item: Any) -> dict[str, Any]:
    outcome = item.result
    return {
        "tenant": item.slug,
        "considered": outcome.considered,
        "sent": outcome.sent,
        "failed": outcome.failed,
        "skipped": outcome.skipped,
        "misconfigured": outcome.misconfigured,
        "error": item.error,
    }


def _bulletins_as_dict(item: Any) -> dict[str, Any]:
    outcome = item.result
    return {
        "tenant": item.slug,
        "considered": outcome.considered,
        "created": outcome.created,
        "auto_issued": outcome.auto_issued,
        "queued": outcome.queued,
        "drafts_from_model": outcome.drafts_from_model,
        "drafts_fallback": outcome.drafts_fallback,
        "by_tier": outcome.by_tier,
        "error": outcome.error,
    }


def _assessment_as_dict(result: Any) -> dict[str, Any]:
    check = result.verification
    score = result.scoring
    return {
        "tenant": result.slug,
        "status": str(score.status),
        "probed": check.probed,
        "confirmed": check.confirmed,
        "unreachable": check.unreachable,
        "fronted": check.fronted,
        "false_positives_cut": check.false_positives_cut,
        "scored": score.scored,
        "tier_changed": score.tier_changed,
        "by_tier": score.by_tier,
        "error": score.error,
    }


def _match_as_dict(result: Any) -> dict[str, Any]:
    outcome = result.outcome
    return {
        "tenant": result.slug,
        "status": str(outcome.status),
        "assets_considered": outcome.assets_considered,
        "candidates_tested": outcome.candidates_tested,
        "matches_open": outcome.matches_open,
        "matches_new": outcome.matches_new,
        "matches_resolved": outcome.matches_resolved,
        "error": outcome.error,
    }


def _as_dict(outcome: Any) -> dict[str, Any]:
    return {
        "source": str(outcome.source),
        "status": str(outcome.status),
        "seen": outcome.seen,
        "changed": outcome.changed,
        "rejected": outcome.rejected,
        "duration_seconds": round(outcome.duration_seconds, 2),
        "error": outcome.error,
    }
