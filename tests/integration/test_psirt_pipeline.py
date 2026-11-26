"""The PSIRT extraction pipeline end to end - spec §4.2.

The one non-deterministic intel path. These drive it with a stub model and
mocked pages, and assert what it writes into the shared store - and, more
importantly, what it refuses to write.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy.orm import Session

from aegis.ai.privacy import PublicPayload
from aegis.config import Settings
from aegis.core.enums import Confidence, ExploitStatus, FeedSource, RunStatus
from aegis.db.models import IntelRecord
from aegis.intel.extraction.schemas import AdvisoryExtraction, ExtractedSource
from aegis.intel.feeds.psirt import PsirtPipeline
from aegis.intel.schemas import FeedContribution, SourceRef
from aegis.intel.store import apply_contributions
from tests.conftest import requires_db

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
CVE = "CVE-2026-104286"
ADVISORY_URL = "https://psirt.vendor.test/FG-IR-26-001"


class StubLlm:
    """Returns a scripted extraction and records the payloads it saw."""

    def __init__(self, extraction: AdvisoryExtraction) -> None:
        self.extraction = extraction
        self.payloads: list[str] = []

    def extract(
        self, *, system: str, payload: PublicPayload, schema: type, instructions: str
    ) -> Any:
        self.payloads.append(payload.text)
        return self.extraction

    def draft(self, **kwargs: Any) -> str:  # pragma: no cover - unused
        raise NotImplementedError


@pytest.fixture
def settings() -> Settings:
    return Settings(psirt_lookback_days=30, advisory_max_chars=10_000)


@pytest.fixture
def candidate(session: Session) -> None:
    """A CVE with an NVD vendor-advisory URL and no vendor confirmation yet."""
    apply_contributions(
        session,
        [
            FeedContribution(
                cve_id=CVE,
                source=FeedSource.NVD,
                retrieved_at=NOW,
                cvss=9.8,
                patch_available=True,
                last_modified_at=NOW,
                sources=[
                    SourceRef(url="https://nvd.test/x", field="cvss"),
                    SourceRef(url=ADVISORY_URL, field="patch_available"),
                ],
            )
        ],
    )
    session.commit()


def _two_sourced() -> AdvisoryExtraction:
    return AdvisoryExtraction(
        exploit_status=ExploitStatus.ACTIVE,
        vendor_confirmed=True,
        patch_available=True,
        affected_versions=["FortiMail < 7.6.3"],
        confidence=Confidence.HIGH,
        sources=[
            ExtractedSource(
                url=ADVISORY_URL,
                quote="exploited in the wild",
                field="vendor_confirmed",
            ),
            ExtractedSource(
                url="https://cisa.gov/alert",
                quote="actively exploited",
                field="vendor_confirmed",
            ),
        ],
    )


def _mock_page(body: str = "<p>Exploited in the wild. Upgrade to 7.6.3.</p>") -> None:
    respx.get(ADVISORY_URL).mock(
        return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=body)
    )


class TestExtraction:
    @respx.mock
    def test_a_well_sourced_advisory_sets_vendor_confirmed(
        self, candidate: None, session: Session, settings: Settings
    ) -> None:
        """The gap this pipeline exists for: §7.2 treats it as KEV-equivalent."""
        _mock_page()
        pipeline = PsirtPipeline(llm=StubLlm(_two_sourced()), settings=settings)

        outcome = pipeline.run(session)

        assert outcome.status is RunStatus.SUCCESS
        assert outcome.changed == 1
        record = session.get(IntelRecord, CVE)
        assert record is not None
        assert record.vendor_confirmed is True
        assert record.exploit_status is ExploitStatus.ACTIVE

    @respx.mock
    def test_a_single_sourced_claim_is_queued_not_stored(
        self, candidate: None, session: Session, settings: Settings
    ) -> None:
        """Spec §4.2: low-confidence goes to a human, not into the store."""
        _mock_page()
        extraction = _two_sourced()
        extraction.sources = [extraction.sources[0]]
        pipeline = PsirtPipeline(llm=StubLlm(extraction), settings=settings)

        outcome = pipeline.run(session)

        assert outcome.changed == 0
        assert len(pipeline.review_queue) == 1
        queued_cve, validated = pipeline.review_queue[0]
        assert queued_cve == CVE
        assert validated.confidence is Confidence.LOW
        assert session.get(IntelRecord, CVE).vendor_confirmed is False  # type: ignore[union-attr]

    @respx.mock
    def test_an_unsourced_claim_is_discarded(
        self, candidate: None, session: Session, settings: Settings
    ) -> None:
        _mock_page()
        extraction = _two_sourced()
        extraction.sources = []
        pipeline = PsirtPipeline(llm=StubLlm(extraction), settings=settings)

        pipeline.run(session)

        assert session.get(IntelRecord, CVE).vendor_confirmed is False  # type: ignore[union-attr]

    @respx.mock
    def test_the_cve_id_comes_from_the_store_not_the_model(
        self, candidate: None, session: Session, settings: Settings
    ) -> None:
        """Spec §4.2: CVE IDs are never generated by the model."""
        _mock_page()
        llm = StubLlm(_two_sourced())
        PsirtPipeline(llm=llm, settings=settings).run(session)

        record = session.get(IntelRecord, CVE)
        assert record is not None
        # The model never saw or returned an id; the store supplied it.
        assert "cve_id" not in AdvisoryExtraction.model_fields

    @respx.mock
    def test_the_page_text_is_what_the_model_receives(
        self, candidate: None, session: Session, settings: Settings
    ) -> None:
        _mock_page("<p>FortiMail is exploited in the wild.</p>")
        llm = StubLlm(_two_sourced())
        PsirtPipeline(llm=llm, settings=settings).run(session)

        assert llm.payloads == ["FortiMail is exploited in the wild."]

    @respx.mock
    def test_an_unfetchable_advisory_is_skipped_quietly(
        self, candidate: None, session: Session, settings: Settings
    ) -> None:
        respx.get(ADVISORY_URL).mock(return_value=httpx.Response(404))
        pipeline = PsirtPipeline(llm=StubLlm(_two_sourced()), settings=settings)

        outcome = pipeline.run(session)

        assert outcome.status is RunStatus.SUCCESS
        assert outcome.changed == 0


class TestCandidateSelection:
    @respx.mock
    def test_cves_already_vendor_confirmed_are_not_re_read(
        self, candidate: None, session: Session, settings: Settings
    ) -> None:
        _mock_page()
        PsirtPipeline(llm=StubLlm(_two_sourced()), settings=settings).run(session)

        llm = StubLlm(_two_sourced())
        PsirtPipeline(llm=llm, settings=settings).run(session)

        assert llm.payloads == [], "a confirmed CVE should not be fetched again"

    @respx.mock
    def test_only_advisory_urls_the_store_already_holds_are_fetched(
        self, session: Session, settings: Settings
    ) -> None:
        """Nothing is discovered by browsing."""
        apply_contributions(
            session,
            [
                FeedContribution(
                    cve_id="CVE-2026-999999",
                    source=FeedSource.NVD,
                    retrieved_at=NOW,
                    cvss=5.0,
                    last_modified_at=NOW,
                    sources=[SourceRef(url="https://nvd.test/y", field="cvss")],
                )
            ],
        )
        session.commit()

        llm = StubLlm(_two_sourced())
        PsirtPipeline(llm=llm, settings=settings).run(session)

        assert llm.payloads == []
