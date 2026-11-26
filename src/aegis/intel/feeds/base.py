"""Scheduled feed pipeline scaffolding (spec §4.1).

Each structured source is a subclass that knows how to fetch its payload and
normalise it into :class:`~aegis.intel.schemas.FeedContribution` objects.
The base class owns everything else: the ``feed_run`` journal entry, the
incremental watermark, schema-validation accounting and the store write.

There is no browsing and no model inference anywhere on this path.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from pydantic import ValidationError
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from aegis.config import Settings, get_settings
from aegis.core.enums import FeedSource, RunStatus
from aegis.db.models import FeedRun
from aegis.intel.http import FeedClient
from aegis.intel.schemas import FeedContribution
from aegis.intel.store import UpsertResult, apply_contributions

log = structlog.get_logger(__name__)

__all__ = ["FeedPipeline", "PipelineOutcome"]


@dataclass(slots=True)
class PipelineOutcome:
    """What a single pipeline run did."""

    source: FeedSource
    status: RunStatus
    seen: int = 0
    changed: int = 0
    rejected: int = 0
    watermark: str | None = None
    duration_seconds: float = 0.0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is RunStatus.SUCCESS


class FeedPipeline(ABC):
    """Base class for a deterministic ETL pipeline."""

    #: The source this pipeline speaks for.
    source: FeedSource
    #: Whether the pipeline reads an incremental watermark from ``feed_run``.
    incremental: bool = False
    #: Rows handed to the store per transaction-flush batch.
    batch_size: int = 500

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        client: FeedClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._client = client
        self._owns_client = client is None

    # -- subclass hooks ----------------------------------------------------

    @abstractmethod
    def fetch(
        self, session: Session, since: str | None
    ) -> Iterator[FeedContribution | ValidationError]:
        """Yield one contribution per CVE this run should write.

        A yielded :class:`ValidationError` counts as a rejected row and is
        logged, letting one malformed entry fail without aborting the run.

        Args:
            session: Open session, for pipelines that need to read the store
                (EPSS scores the CVEs already tracked, for instance).
            since: The watermark from the last successful run, or ``None``.
        """

    def next_watermark(self, started_at: datetime) -> str | None:
        """The watermark to record for this run.  ``None`` to keep the old one."""
        return None

    def finalise(self, session: Session, seen_cve_ids: set[str]) -> None:  # noqa: B027
        """Optional hook run after a successful write, before the journal closes.

        Deliberately concrete and empty: most pipelines need nothing here, and
        only a feed that publishes a *complete* catalogue can act on absence.
        KEV overrides it to retract CVEs that have dropped off.
        """

    # -- orchestration -----------------------------------------------------

    @property
    def client(self) -> FeedClient:
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> FeedClient:
        return FeedClient(settings=self.settings)

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def last_watermark(self, session: Session) -> str | None:
        """The watermark recorded by the most recent successful run."""
        return session.scalars(
            select(FeedRun.watermark)
            .where(
                FeedRun.source == self.source,
                FeedRun.status == RunStatus.SUCCESS,
                FeedRun.watermark.is_not(None),
            )
            .order_by(desc(FeedRun.started_at))
            .limit(1)
        ).first()

    def run(self, session: Session) -> PipelineOutcome:
        """Execute one scheduled run and journal it.

        The ``feed_run`` row is committed even when the run fails, so a
        failing feed is visible rather than silent.
        """
        started_at = datetime.now(UTC)
        monotonic_start = time.monotonic()
        since = self.last_watermark(session) if self.incremental else None

        run_row = FeedRun(
            source=self.source,
            status=RunStatus.RUNNING,
            started_at=started_at,
            watermark=since,
        )
        session.add(run_row)
        session.flush()

        log.info("feed.run.started", source=str(self.source), since=since)

        total = UpsertResult()
        seen_cve_ids: set[str] = set()
        batch: list[FeedContribution] = []

        try:
            for item in self.fetch(session, since):
                if isinstance(item, ValidationError):
                    total.rejected += 1
                    log.warning(
                        "feed.row.rejected",
                        source=str(self.source),
                        errors=item.error_count(),
                    )
                    continue

                batch.append(item)
                seen_cve_ids.add(item.cve_id)
                if len(batch) >= self.batch_size:
                    self._flush(session, batch, total)
                    batch = []

            if batch:
                self._flush(session, batch, total)

            self.finalise(session, seen_cve_ids)

        except Exception as exc:
            session.rollback()
            self._journal_failure(session, run_row, started_at, exc)
            duration = time.monotonic() - monotonic_start
            log.error(
                "feed.run.failed",
                source=str(self.source),
                error=str(exc),
                duration=round(duration, 2),
            )
            return PipelineOutcome(
                source=self.source,
                status=RunStatus.FAILED,
                duration_seconds=duration,
                error=str(exc),
            )

        duration = time.monotonic() - monotonic_start
        watermark = self.next_watermark(started_at) or since

        run_row.status = RunStatus.SUCCESS
        run_row.finished_at = datetime.now(UTC)
        run_row.records_seen = total.seen
        run_row.records_changed = total.changed
        run_row.records_rejected = total.rejected
        run_row.watermark = watermark
        run_row.detail = {"rejections": total.rejections[:50]}
        session.commit()

        log.info(
            "feed.run.finished",
            source=str(self.source),
            seen=total.seen,
            changed=total.changed,
            rejected=total.rejected,
            duration=round(duration, 2),
        )
        return PipelineOutcome(
            source=self.source,
            status=RunStatus.SUCCESS,
            seen=total.seen,
            changed=total.changed,
            rejected=total.rejected,
            watermark=watermark,
            duration_seconds=duration,
        )

    # -- internals ---------------------------------------------------------

    def _flush(
        self,
        session: Session,
        batch: list[FeedContribution],
        total: UpsertResult,
    ) -> None:
        result = apply_contributions(session, batch)
        total.seen += result.seen
        total.changed += result.changed
        total.rejected += result.rejected
        total.rejections.extend(result.rejections)

    def _journal_failure(
        self,
        session: Session,
        run_row: FeedRun,
        started_at: datetime,
        exc: Exception,
    ) -> None:
        """Record the failure on a clean transaction after a rollback."""
        failed = FeedRun(
            source=self.source,
            status=RunStatus.FAILED,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            error=f"{type(exc).__name__}: {exc}"[:4000],
        )
        session.add(failed)
        session.commit()

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(UTC)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.source}>"


def iso_z(value: datetime) -> str:
    """Render a UTC timestamp the way the feed APIs expect it."""
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
