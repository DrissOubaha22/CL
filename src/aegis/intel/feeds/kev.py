"""CISA Known Exploited Vulnerabilities pipeline (spec §4.1).

Public JSON catalogue, polled and diffed.  Extracts ``on_kev``,
``date_added``, ``due_date`` and the ransomware flag.

The catalogue is authoritative *and* complete: a CVE absent from it is a CVE
CISA no longer lists.  So the run ends by retracting contributions for CVEs
that dropped off, which re-derives their records without the KEV facts rather
than leaving a claim no source still makes.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date, datetime
from typing import Any

import structlog
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.core.enums import FeedSource
from aegis.db.models import IntelContribution
from aegis.intel.feeds.base import FeedPipeline
from aegis.intel.schemas import FeedContribution, SourceRef
from aegis.intel.store import retract_source

log = structlog.get_logger(__name__)

#: CISA states ransomware use as a word, not a boolean.
_RANSOMWARE_KNOWN = "known"


class KevPipeline(FeedPipeline):
    """Poll the CISA KEV catalogue and diff it against the store."""

    source = FeedSource.CISA_KEV
    incremental = False

    def fetch(
        self, session: Session, since: str | None
    ) -> Iterator[FeedContribution | ValidationError]:
        url = self.settings.kev_url
        payload = self.client.get_json(url)

        if not isinstance(payload, dict) or "vulnerabilities" not in payload:
            raise ValueError(f"unexpected KEV catalogue shape from {url}")

        retrieved_at = self._utcnow()
        catalog_version = payload.get("catalogVersion")
        log.info(
            "feed.kev.fetched",
            count=len(payload["vulnerabilities"]),
            catalog_version=catalog_version,
        )

        for entry in payload["vulnerabilities"]:
            try:
                yield self._to_contribution(entry, url, retrieved_at)
            except ValidationError as exc:
                yield exc
            except (TypeError, ValueError) as exc:
                log.warning(
                    "feed.kev.malformed_entry",
                    cve=str(entry.get("cveID"))[:32] if isinstance(entry, dict) else None,
                    error=str(exc),
                )

    def _to_contribution(
        self, entry: dict[str, Any], url: str, retrieved_at: datetime
    ) -> FeedContribution:
        ransomware = (
            str(entry.get("knownRansomwareCampaignUse", "")).strip().lower() == _RANSOMWARE_KNOWN
        )
        return FeedContribution(
            cve_id=entry["cveID"],
            source=self.source,
            retrieved_at=retrieved_at,
            on_kev=True,
            kev_date_added=_parse_date(entry.get("dateAdded")),
            kev_due=_parse_date(entry.get("dueDate")),
            ransomware=ransomware,
            title=_clean(entry.get("vulnerabilityName")),
            description=_clean(entry.get("shortDescription")),
            sources=[
                SourceRef(
                    url=url,
                    field="on_kev",
                    quote=_clean(entry.get("requiredAction")),
                )
            ],
        )

    def finalise(self, session: Session, seen_cve_ids: set[str]) -> None:
        """Retract CVEs CISA has removed from the catalogue."""
        if not seen_cve_ids:
            # An empty catalogue is far more likely to be a broken fetch than
            # CISA delisting everything; never mass-retract on it.
            log.warning("feed.kev.empty_catalogue_ignored")
            return

        stored = set(
            session.scalars(
                select(IntelContribution.cve_id).where(IntelContribution.source == self.source)
            ).all()
        )
        removed = stored - seen_cve_ids
        if removed:
            log.info("feed.kev.retracting", count=len(removed))
            retract_source(session, self.source, removed)


def _parse_date(value: object) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(str(value).strip()[:10])
    except ValueError:
        return None


def _clean(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
