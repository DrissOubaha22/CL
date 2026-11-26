"""Running feed pipelines (spec §10, steps 2 and 10).

Collection runs on a schedule across all tenants because intel is shared, not
tenant-scoped (spec §2).  Nothing here touches tenant data.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import structlog
from sqlalchemy.engine import Engine

from aegis.core.enums import FeedSource, RunStatus
from aegis.db.base import session_scope
from aegis.intel.feeds.base import PipelineOutcome
from aegis.intel.feeds.registry import SYNC_ORDER, get_pipeline

log = structlog.get_logger(__name__)

__all__ = ["run_pipeline", "run_pipelines"]


def run_pipeline(source: FeedSource, *, engine: Engine | None = None) -> PipelineOutcome:
    """Run one feed pipeline to completion."""
    pipeline = get_pipeline(source)()
    try:
        with session_scope(engine) as session:
            return pipeline.run(session)
    finally:
        pipeline.close()


def run_pipelines(
    sources: Iterable[FeedSource] | None = None,
    *,
    engine: Engine | None = None,
    stop_on_error: bool = False,
) -> Sequence[PipelineOutcome]:
    """Run several pipelines in dependency order.

    KEV and NVD introduce CVEs into the store; EPSS annotates the CVEs that
    are already there.  Running them out of order would simply score fewer
    CVEs this cycle, so the order is a correctness nicety, not a hard
    requirement.

    Args:
        sources: Which feeds to run; defaults to every implemented feed.
        stop_on_error: Abort the remaining feeds after the first failure.
            Off by default - one broken feed should not stop the others.
    """
    requested = list(sources) if sources is not None else list(SYNC_ORDER)
    ordered = [source for source in SYNC_ORDER if source in requested]
    ordered.extend(source for source in requested if source not in SYNC_ORDER)

    outcomes: list[PipelineOutcome] = []
    for source in ordered:
        outcome = run_pipeline(source, engine=engine)
        outcomes.append(outcome)
        if outcome.status is RunStatus.FAILED and stop_on_error:
            log.error("intel.sync.aborted", source=str(source))
            break
    return outcomes
