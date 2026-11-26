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

from aegis.config import get_settings
from aegis.core.enums import FeedSource
from aegis.intel.runner import run_pipeline, run_pipelines
from aegis.logging import configure_logging

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
