"""Feed normalisation - spec §4.1.

These exercise ``fetch`` alone: HTTP in, validated contributions out, with no
database.  The full fetch-to-record path is covered in the integration tests.
"""

from __future__ import annotations

from datetime import date

import httpx
import pytest
import respx
from pydantic import ValidationError

from aegis.config import Settings
from aegis.core.enums import FeedSource
from aegis.intel.feeds import KevPipeline, NvdPipeline
from aegis.intel.http import FeedClient, FeedHttpError
from aegis.intel.schemas import FeedContribution
from tests.fixtures import KEV_CATALOGUE, NVD_RESPONSE

KEV_URL = "https://feeds.test/kev.json"
NVD_URL = "https://nvd.test/cves/2.0"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        kev_url=KEV_URL,
        nvd_url=NVD_URL,
        http_max_retries=2,
        nvd_initial_lookback_days=7,
        # Keep the unit tests from sleeping on NVD's request budget.
        nvd_requests_per_window=1000,
        nvd_window_seconds=0.001,
    )


def _collect(items) -> tuple[list[FeedContribution], list[ValidationError]]:
    good: list[FeedContribution] = []
    bad: list[ValidationError] = []
    for item in items:
        (bad if isinstance(item, ValidationError) else good).append(item)
    return good, bad


class TestKevParsing:
    @respx.mock
    def test_normalises_the_catalogue(self, settings: Settings) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))
        pipeline = KevPipeline(settings=settings, client=FeedClient(settings=settings))

        good, bad = _collect(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]

        assert [c.cve_id for c in good] == ["CVE-2026-104286", "CVE-2026-200001"]
        assert len(bad) == 1, "the malformed CVE id must be rejected, not repaired"

        first = good[0]
        assert first.source is FeedSource.CISA_KEV
        assert first.on_kev is True
        assert first.ransomware is True
        assert first.kev_date_added == date(2026, 11, 10)
        assert first.kev_due == date(2026, 12, 1)
        assert first.sources[0].field == "on_kev"

    @respx.mock
    def test_ransomware_flag_is_a_word_not_a_boolean(self, settings: Settings) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))
        pipeline = KevPipeline(settings=settings, client=FeedClient(settings=settings))
        good, _ = _collect(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]
        assert good[1].ransomware is False  # "Unknown"

    @respx.mock
    def test_rejects_an_unexpected_payload_shape(self, settings: Settings) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json={"oops": True}))
        pipeline = KevPipeline(settings=settings, client=FeedClient(settings=settings))
        with pytest.raises(ValueError, match="unexpected KEV catalogue shape"):
            list(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]

    @respx.mock
    def test_retries_a_transient_failure(self, settings: Settings) -> None:
        route = respx.get(KEV_URL).mock(
            side_effect=[
                httpx.Response(503),
                httpx.Response(200, json=KEV_CATALOGUE),
            ]
        )
        pipeline = KevPipeline(settings=settings, client=FeedClient(settings=settings))
        good, _ = _collect(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]
        assert route.call_count == 2
        assert len(good) == 2

    @respx.mock
    def test_does_not_retry_a_client_error(self, settings: Settings) -> None:
        route = respx.get(KEV_URL).mock(return_value=httpx.Response(404))
        pipeline = KevPipeline(settings=settings, client=FeedClient(settings=settings))
        with pytest.raises(FeedHttpError):
            list(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]
        assert route.call_count == 1


class TestNvdParsing:
    @respx.mock
    def test_extracts_metrics_cwe_and_ranges(self, settings: Settings) -> None:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        pipeline = NvdPipeline(settings=settings, client=FeedClient(settings=settings))

        good, bad = _collect(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]
        assert not bad
        assert [c.cve_id for c in good] == ["CVE-2026-104286", "CVE-2026-300002"]

        first = good[0]
        assert first.cvss == pytest.approx(9.8), "Primary metric must win"
        assert first.cvss_vector is not None and first.cvss_vector.startswith("CVSS:3.1")
        assert first.cwe == ["CWE-78"], "placeholder weaknesses are dropped"
        assert first.description == "A command injection in FortiMail."
        assert first.patch_available is True
        assert first.published_at is not None and first.published_at.tzinfo is not None

    @respx.mock
    def test_keeps_every_cpe_match_with_its_bounds(self, settings: Settings) -> None:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        pipeline = NvdPipeline(settings=settings, client=FeedClient(settings=settings))
        good, _ = _collect(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]

        ranges = good[0].affected_cpes
        # Three well-formed cpeMatch nodes; the unparseable one is dropped.
        assert len(ranges) == 3
        bounded = [r for r in ranges if r.version_end_excluding == "7.4.8"]
        assert bounded[0].version_start_including == "7.4.0"
        # The non-vulnerable platform node is kept, flagged, for §5.3.
        assert any(not r.vulnerable for r in ranges)

    @respx.mock
    def test_a_cve_without_metrics_still_yields_a_contribution(self, settings: Settings) -> None:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        pipeline = NvdPipeline(settings=settings, client=FeedClient(settings=settings))
        good, _ = _collect(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]

        second = good[1]
        assert second.cvss is None
        assert second.cwe == []
        assert second.affected_cpes == []

    @respx.mock
    def test_sends_an_incremental_window(self, settings: Settings) -> None:
        route = respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        pipeline = NvdPipeline(settings=settings, client=FeedClient(settings=settings))
        list(pipeline.fetch(session=None, since="2026-11-20T00:00:00.000Z"))  # type: ignore[arg-type]

        params = route.calls[0].request.url.params
        assert params["lastModStartDate"].startswith("2026-11-20")
        assert "lastModEndDate" in params

    @respx.mock
    def test_paginates_until_the_total_is_reached(self, settings: Settings) -> None:
        page_one = {
            "totalResults": 2,
            "resultsPerPage": 1,
            "startIndex": 0,
            "vulnerabilities": [NVD_RESPONSE["vulnerabilities"][0]],
        }
        page_two = {
            "totalResults": 2,
            "resultsPerPage": 1,
            "startIndex": 1,
            "vulnerabilities": [NVD_RESPONSE["vulnerabilities"][1]],
        }
        route = respx.get(NVD_URL).mock(
            side_effect=[
                httpx.Response(200, json=page_one),
                httpx.Response(200, json=page_two),
            ]
        )
        pipeline = NvdPipeline(settings=settings, client=FeedClient(settings=settings))
        good, _ = _collect(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]

        assert route.call_count == 2
        assert len(good) == 2
        assert route.calls[1].request.url.params["startIndex"] == "1"

    @respx.mock
    def test_splits_a_window_wider_than_nvd_accepts(self, settings: Settings) -> None:
        """NVD rejects a lastMod window over 120 days."""
        empty = {"totalResults": 0, "resultsPerPage": 0, "vulnerabilities": []}
        route = respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=empty))
        pipeline = NvdPipeline(settings=settings, client=FeedClient(settings=settings))
        list(pipeline.fetch(session=None, since="2026-01-01T00:00:00.000Z"))  # type: ignore[arg-type]
        assert route.call_count >= 3, "a ~330-day gap needs at least three windows"

    @respx.mock
    def test_sends_the_api_key_when_configured(self) -> None:
        settings = Settings(
            nvd_url=NVD_URL,
            nvd_api_key="secret-key",  # type: ignore[arg-type]
            nvd_requests_per_window=1000,
            nvd_window_seconds=0.001,
        )
        route = respx.get(NVD_URL).mock(
            return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
        )
        pipeline = NvdPipeline(settings=settings, client=FeedClient(settings=settings))
        list(pipeline.fetch(session=None, since=None))  # type: ignore[arg-type]
        assert route.calls[0].request.headers["apiKey"] == "secret-key"
