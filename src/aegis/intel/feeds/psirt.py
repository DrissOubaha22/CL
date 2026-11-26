"""The PSIRT extraction pipeline (spec §4.2).

The one non-deterministic intel path.  It exists for a specific gap: a
vendor confirms exploitation in an advisory days before CISA lists the CVE,
and §7.2 treats that confirmation as KEV-equivalent.  Everything a structured
feed already carries is left to the structured feed.

It lives beside the deterministic feeds because it *is* one from the store's
point of view: scheduled, journalled and upserted through exactly the same
path.  Only the way its contributions are produced differs, and the pieces
that differ - fetching, the output schema, validation - live in
:mod:`aegis.intel.extraction`.  What the model
returns is validated (§4.2) before it becomes a contribution, and the CVE id
comes from the store, never from the model.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import structlog
from pydantic import ValidationError
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from aegis.ai.client import LlmClient, LlmError, LlmUnavailable, build_client
from aegis.ai.prompts import (
    ADVISORY_EXTRACTION_INSTRUCTIONS,
    ADVISORY_EXTRACTION_SYSTEM,
)
from aegis.core.enums import Confidence, ExploitStatus, FeedSource
from aegis.db.models import IntelRecord, IntelSource
from aegis.intel.extraction.fetch import AdvisoryFetchError, fetch_advisory_text
from aegis.intel.extraction.schemas import AdvisoryExtraction
from aegis.intel.extraction.validation import ValidatedExtraction, validate_extraction
from aegis.intel.feeds.base import FeedPipeline
from aegis.intel.schemas import FeedContribution, SourceRef

log = structlog.get_logger(__name__)

__all__ = ["PsirtPipeline"]


class PsirtPipeline(FeedPipeline):
    """Read vendor advisories the structured feeds have not caught up with."""

    source = FeedSource.PSIRT
    incremental = False
    batch_size = 25

    def __init__(
        self,
        *,
        llm: LlmClient | None = None,
        max_advisories: int = 25,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._llm = llm
        self.max_advisories = max_advisories
        #: Extractions a human must look at (spec §4.2).
        self.review_queue: list[tuple[str, ValidatedExtraction]] = []

    @property
    def llm(self) -> LlmClient:
        if self._llm is None:
            self._llm = build_client(settings=self.settings)
        return self._llm

    def fetch(
        self, session: Session, since: str | None
    ) -> Iterator[FeedContribution | ValidationError]:
        try:
            llm = self.llm
        except LlmUnavailable as exc:
            log.warning("psirt.llm_unavailable", reason=str(exc))
            return

        retrieved_at = self._utcnow()
        candidates = self._candidates(session)
        log.info("psirt.candidates", count=len(candidates))

        for cve_id, url in candidates:
            try:
                payload = fetch_advisory_text(url, settings=self.settings)
            except AdvisoryFetchError as exc:
                log.info("psirt.fetch_failed", cve=cve_id, url=url, error=str(exc))
                continue

            try:
                extraction = llm.extract(
                    system=ADVISORY_EXTRACTION_SYSTEM,
                    payload=payload,
                    schema=AdvisoryExtraction,
                    instructions=ADVISORY_EXTRACTION_INSTRUCTIONS,
                )
            except LlmError as exc:
                log.warning("psirt.extraction_failed", cve=cve_id, error=str(exc))
                continue

            validated = validate_extraction(extraction, expected_cve_id=cve_id, fetched_from=url)

            if validated.needs_review:
                # Spec §4.2: low-confidence extractions are queued for a
                # human rather than written into the shared store.
                self.review_queue.append((cve_id, validated))
                log.info(
                    "psirt.queued_for_review",
                    cve=cve_id,
                    reasons=validated.review_reasons,
                )
                continue

            if not validated.has_claims:
                continue

            contribution = self._to_contribution(cve_id, url, validated, retrieved_at)
            if contribution is not None:
                yield contribution

    def _to_contribution(
        self,
        cve_id: str,
        url: str,
        validated: ValidatedExtraction,
        retrieved_at: datetime,
    ) -> FeedContribution | None:
        """Turn a validated extraction into a store contribution.

        Only the fields PSIRT owns (see
        :data:`aegis.intel.derive.FIELD_OWNERS`) are carried over.  The
        free-text ``affected_versions`` are kept as provenance rather than
        converted to CPE ranges: the model was told not to invent CPE
        strings, and parsing vendor prose into ranges is deterministic work
        that belongs with the structured feeds.
        """
        extraction = validated.extraction

        sources = [
            SourceRef(url=source.url, quote=source.quote, field=source.field)
            for source in extraction.sources
            if source.url
        ] or [SourceRef(url=url, field="vendor_confirmed")]

        fields: dict[str, object] = {}
        if extraction.vendor_confirmed is not None:
            fields["vendor_confirmed"] = extraction.vendor_confirmed
        if extraction.patch_available is not None:
            fields["patch_available"] = extraction.patch_available
        if extraction.config_dependent is not None:
            fields["config_dependent"] = extraction.config_dependent
        if extraction.exploit_status is ExploitStatus.ACTIVE:
            # PSIRT owns vendor_confirmed, not exploit_status: the merged
            # status is derived from the exploitation signals (spec §7.1).
            fields.setdefault("vendor_confirmed", True)

        if not fields:
            return None

        try:
            return FeedContribution(
                cve_id=cve_id,
                source=self.source,
                retrieved_at=retrieved_at,
                sources=sources,
                **fields,  # type: ignore[arg-type]
            )
        except ValidationError as exc:
            log.warning("psirt.contribution_invalid", cve=cve_id, error=str(exc))
            return None

    def _candidates(self, session: Session) -> list[tuple[str, str]]:
        """CVEs worth reading an advisory for, and the URL to read.

        The advisory URLs are ones NVD already published as vendor
        advisories, so nothing is discovered by browsing.  Worth reading
        means: recently modified, and not already carrying the fact a vendor
        advisory would add.
        """
        cutoff = self._utcnow() - timedelta(days=self.settings.psirt_lookback_days)

        statement = (
            select(IntelRecord.cve_id, IntelSource.url)
            .join(IntelSource, IntelSource.cve_id == IntelRecord.cve_id)
            .where(
                IntelSource.source == FeedSource.NVD,
                IntelSource.field == "patch_available",
                IntelRecord.vendor_confirmed.is_(False),
                or_(
                    IntelRecord.last_modified_at.is_(None),
                    IntelRecord.last_modified_at >= cutoff,
                ),
            )
            .order_by(IntelRecord.last_modified_at.desc().nulls_last())
            .limit(self.max_advisories)
        )

        seen: set[str] = set()
        candidates: list[tuple[str, str]] = []
        for cve_id, url in session.execute(statement).all():
            if cve_id in seen:
                continue
            seen.add(cve_id)
            candidates.append((cve_id, url))
        return candidates

    def finalise(self, session: Session, seen_cve_ids: set[str]) -> None:
        """Record what a human still has to look at."""
        if self.review_queue:
            log.warning(
                "psirt.review_queue",
                count=len(self.review_queue),
                cves=[cve for cve, _ in self.review_queue][:20],
            )

    @staticmethod
    def _utcnow() -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def _confidence_of(validated: ValidatedExtraction) -> Confidence:
        return validated.confidence
