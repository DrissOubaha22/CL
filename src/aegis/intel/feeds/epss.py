"""FIRST EPSS pipeline (spec §4.1).

REST API, batched by CVE.  EPSS re-scores the whole corpus daily, so the run
refreshes every CVE the store already tracks rather than discovering new
ones: a CVE reaches the store through KEV or NVD first, and EPSS annotates
it.

EPSS never establishes exploitation on its own.  It feeds ``epss`` and
``epss_percentile`` only; §7.2 lets those raise a tier but never lower one
derived from confirmed exploitation.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import datetime

import structlog
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.core.enums import FeedSource
from aegis.db.models import IntelRecord
from aegis.intel.feeds.base import FeedPipeline
from aegis.intel.schemas import FeedContribution, SourceRef

log = structlog.get_logger(__name__)


class EpssPipeline(FeedPipeline):
    """Refresh EPSS scores for every CVE in the shared store."""

    source = FeedSource.FIRST_EPSS
    incremental = False

    def fetch(
        self, session: Session, since: str | None
    ) -> Iterator[FeedContribution | ValidationError]:
        cve_ids = self._tracked_cve_ids(session)
        if not cve_ids:
            log.info("feed.epss.no_tracked_cves")
            return

        retrieved_at = self._utcnow()
        batch_size = max(1, self.settings.epss_batch_size)
        log.info("feed.epss.scoring", cves=len(cve_ids), batch_size=batch_size)

        for start in range(0, len(cve_ids), batch_size):
            chunk = cve_ids[start : start + batch_size]
            yield from self._fetch_chunk(chunk, retrieved_at)

    def _fetch_chunk(
        self, chunk: Sequence[str], retrieved_at: datetime
    ) -> Iterator[FeedContribution | ValidationError]:
        url = self.settings.epss_url
        payload = self.client.get_json(url, params={"cve": ",".join(chunk), "limit": len(chunk)})

        if not isinstance(payload, dict) or "data" not in payload:
            raise ValueError(f"unexpected EPSS response shape from {url}")

        for entry in payload["data"]:
            try:
                yield FeedContribution(
                    cve_id=entry["cve"],
                    source=self.source,
                    retrieved_at=retrieved_at,
                    epss=_as_probability(entry.get("epss")),
                    epss_percentile=_as_probability(entry.get("percentile")),
                    sources=[SourceRef(url=url, field="epss")],
                )
            except ValidationError as exc:
                yield exc
            except (KeyError, TypeError, ValueError) as exc:
                log.warning("feed.epss.malformed_entry", error=str(exc))

    def _tracked_cve_ids(self, session: Session) -> list[str]:
        return list(session.scalars(select(IntelRecord.cve_id).order_by(IntelRecord.cve_id)).all())


def _as_probability(value: object) -> float | None:
    """EPSS returns its scores as decimal strings."""
    if value is None or value == "":
        return None
    if not isinstance(value, (str, int, float)):
        raise ValueError(f"EPSS score is not a number: {value!r}")
    score = float(value)
    if not 0.0 <= score <= 1.0:
        raise ValueError(f"EPSS score out of range: {value!r}")
    return score
