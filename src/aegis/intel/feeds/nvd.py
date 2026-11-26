"""NVD CVE 2.0 pipeline (spec §4.1).

Extracts CVSS, CWE, affected CPE ranges and references.  The affected-CPE
ranges are the substrate the matching engine joins against (spec §5), so
``cpeMatch`` nodes are preserved with their bounds rather than flattened to a
version string.

Runs incrementally on ``lastModStartDate``/``lastModEndDate``; the watermark
is the run's start time, recorded only when the run succeeds.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pydantic import ValidationError
from sqlalchemy.orm import Session

from aegis.core.enums import FeedSource
from aegis.intel.feeds.base import FeedPipeline, iso_z
from aegis.intel.http import FeedClient, RateLimiter
from aegis.intel.schemas import CpeRange, FeedContribution, SourceRef

log = structlog.get_logger(__name__)

#: NVD rejects a lastModStartDate/EndDate window wider than 120 days.
MAX_WINDOW = timedelta(days=120)

#: CVSS metric keys in descending preference.
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")

#: A reference carrying this tag means a fix exists.
_PATCH_TAGS = frozenset({"Patch", "Vendor Advisory"})


class NvdPipeline(FeedPipeline):
    """Incrementally ingest NVD CVE records."""

    source = FeedSource.NVD
    incremental = True
    batch_size = 200

    def _build_client(self) -> FeedClient:
        limiter = RateLimiter(
            self.settings.nvd_requests_per_window, self.settings.nvd_window_seconds
        )
        return FeedClient(settings=self.settings, rate_limiter=limiter)

    def next_watermark(self, started_at: datetime) -> str | None:
        return iso_z(started_at)

    def fetch(
        self, session: Session, since: str | None
    ) -> Iterator[FeedContribution | ValidationError]:
        now = self._utcnow()
        start = self._window_start(since, now)

        for window_start, window_end in _windows(start, now):
            yield from self._fetch_window(window_start, window_end)

    def _window_start(self, since: str | None, now: datetime) -> datetime:
        if since:
            try:
                parsed = datetime.fromisoformat(since.replace("Z", "+00:00"))
                return parsed.astimezone(UTC)
            except ValueError:
                log.warning("feed.nvd.unparseable_watermark", watermark=since)
        return now - timedelta(days=self.settings.nvd_initial_lookback_days)

    def _headers(self) -> dict[str, str]:
        key = self.settings.nvd_api_key
        return {"apiKey": key.get_secret_value()} if key else {}

    def _fetch_window(
        self, window_start: datetime, window_end: datetime
    ) -> Iterator[FeedContribution | ValidationError]:
        url = self.settings.nvd_url
        page_size = self.settings.nvd_page_size
        start_index = 0
        total = None

        while total is None or start_index < total:
            payload = self.client.get_json(
                url,
                params={
                    "lastModStartDate": iso_z(window_start),
                    "lastModEndDate": iso_z(window_end),
                    "startIndex": start_index,
                    "resultsPerPage": page_size,
                },
                headers=self._headers(),
            )

            if not isinstance(payload, dict) or "vulnerabilities" not in payload:
                raise ValueError(f"unexpected NVD response shape from {url}")

            total = int(payload.get("totalResults", 0))
            page = payload["vulnerabilities"]
            log.info(
                "feed.nvd.page",
                start_index=start_index,
                page=len(page),
                total=total,
            )

            retrieved_at = self._utcnow()
            for item in page:
                cve = (item or {}).get("cve")
                if not isinstance(cve, dict):
                    continue
                try:
                    yield self._to_contribution(cve, url, retrieved_at)
                except ValidationError as exc:
                    yield exc
                except (KeyError, TypeError, ValueError) as exc:
                    log.warning(
                        "feed.nvd.malformed_entry",
                        cve=str(cve.get("id"))[:32],
                        error=str(exc),
                    )

            if not page:
                break
            start_index += len(page)

    def _to_contribution(
        self, cve: dict[str, Any], url: str, retrieved_at: datetime
    ) -> FeedContribution:
        cve_id = cve["id"]
        score, vector = _primary_cvss(cve.get("metrics") or {})
        references = cve.get("references") or []

        sources = [SourceRef(url=f"{url}?cveId={cve_id}", field="cvss")]
        sources.extend(
            SourceRef(url=ref["url"], field="patch_available")
            for ref in references
            if isinstance(ref, dict)
            and ref.get("url")
            and _PATCH_TAGS.intersection(ref.get("tags") or ())
        )

        return FeedContribution(
            cve_id=cve_id,
            source=self.source,
            retrieved_at=retrieved_at,
            cvss=score,
            cvss_vector=vector,
            cwe=_weaknesses(cve.get("weaknesses") or []),
            description=_english_description(cve.get("descriptions") or []),
            published_at=_parse_nvd_timestamp(cve.get("published")),
            last_modified_at=_parse_nvd_timestamp(cve.get("lastModified")),
            patch_available=any(
                isinstance(ref, dict) and "Patch" in (ref.get("tags") or ()) for ref in references
            ),
            affected_cpes=_affected_cpes(cve.get("configurations") or []),
            sources=sources[:25],
        )


def _windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    """Split ``[start, end]`` into chunks NVD will accept."""
    if start >= end:
        return
    cursor = start
    while cursor < end:
        stop = min(cursor + MAX_WINDOW, end)
        yield cursor, stop
        cursor = stop


def _primary_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    """Pick the preferred CVSS base score, favouring the Primary provider."""
    for key in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        return float(score), data.get("vectorString")
    return None, None


def _weaknesses(weaknesses: list[dict[str, Any]]) -> list[str]:
    found: list[str] = []
    for weakness in weaknesses:
        for description in weakness.get("description") or []:
            value = str(description.get("value", "")).strip().upper()
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return found


def _english_description(descriptions: list[dict[str, Any]]) -> str | None:
    for description in descriptions:
        if description.get("lang") == "en":
            text = str(description.get("value", "")).strip()
            if text:
                return text
    return None


def _affected_cpes(configurations: list[dict[str, Any]]) -> list[CpeRange]:
    """Flatten ``configurations -> nodes -> cpeMatch`` into ranges.

    Node operators (AND/OR) express multi-component conditions; those are a
    matching concern (spec §5.3 config-dependence), so every ``cpeMatch`` is
    kept here with its ``vulnerable`` flag intact rather than being filtered.
    """
    ranges: list[CpeRange] = []
    seen: set[tuple[Any, ...]] = set()

    for configuration in configurations:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                key = (
                    criteria,
                    match.get("versionStartIncluding"),
                    match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"),
                    match.get("versionEndExcluding"),
                )
                if key in seen:
                    continue
                seen.add(key)
                try:
                    ranges.append(
                        CpeRange(
                            cpe=criteria,
                            vulnerable=bool(match.get("vulnerable", True)),
                            version_start_including=match.get("versionStartIncluding"),
                            version_start_excluding=match.get("versionStartExcluding"),
                            version_end_including=match.get("versionEndIncluding"),
                            version_end_excluding=match.get("versionEndExcluding"),
                        )
                    )
                except ValidationError as exc:
                    log.warning("feed.nvd.bad_cpe", criteria=str(criteria)[:120], error=str(exc))
    return ranges


def _parse_nvd_timestamp(value: object) -> datetime | None:
    """NVD timestamps are ISO-8601 without a zone; they are UTC."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
