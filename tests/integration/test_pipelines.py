"""End-to-end feed runs: HTTP in, derived records and a journal out.

This is the phase-1 acceptance criterion from spec §14 - "intel records build
& refresh per CVE" - exercised against a live PostgreSQL.
"""

from __future__ import annotations

import copy
from datetime import datetime

import httpx
import pytest
import respx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.config import Settings
from aegis.core.enums import ExploitStatus, FeedSource, RunStatus
from aegis.db.models import AffectedCpe, FeedRun, IntelRecord
from aegis.intel.feeds import EpssPipeline, KevPipeline, NvdPipeline
from aegis.intel.http import FeedClient
from tests.conftest import requires_db
from tests.fixtures import EPSS_RESPONSE, KEV_CATALOGUE, NVD_RESPONSE

pytestmark = [pytest.mark.integration, requires_db]

KEV_URL = "https://feeds.test/kev.json"
EPSS_URL = "https://epss.test/epss"
NVD_URL = "https://nvd.test/cves/2.0"

FORTIMAIL = "CVE-2026-104286"
NETSCALER = "CVE-2026-200001"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        kev_url=KEV_URL,
        epss_url=EPSS_URL,
        nvd_url=NVD_URL,
        http_max_retries=2,
        nvd_requests_per_window=1000,
        nvd_window_seconds=0.001,
        epss_batch_size=100,
    )


def _pipeline(cls, settings: Settings):
    return cls(settings=settings, client=FeedClient(settings=settings))


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


class TestKevRun:
    @respx.mock
    def test_builds_records_and_journals_the_run(
        self, session: Session, settings: Settings
    ) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))

        outcome = _pipeline(KevPipeline, settings).run(session)

        assert outcome.status is RunStatus.SUCCESS
        assert outcome.seen == 2
        assert outcome.changed == 2
        assert outcome.rejected == 1, "the malformed CVE id is rejected"

        record = session.get(IntelRecord, FORTIMAIL)
        assert record is not None
        assert record.exploit_status is ExploitStatus.ACTIVE
        assert record.ransomware is True
        assert record.kev_due is not None

        run = session.scalars(select(FeedRun)).one()
        assert run.source is FeedSource.CISA_KEV
        assert run.status is RunStatus.SUCCESS
        assert (run.records_seen, run.records_changed) == (2, 2)
        assert run.finished_at is not None

    @respx.mock
    def test_second_run_on_an_unchanged_catalogue_changes_nothing(
        self, session: Session, settings: Settings
    ) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))

        _pipeline(KevPipeline, settings).run(session)
        second = _pipeline(KevPipeline, settings).run(session)

        assert second.seen == 2
        assert second.changed == 0, "poll + diff must detect no change"
        assert _count(session, IntelRecord) == 2

    @respx.mock
    def test_delisting_retracts_the_kev_facts(self, session: Session, settings: Settings) -> None:
        """CISA removing a CVE must clear on_kev, not leave it unsourced."""
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))
        _pipeline(KevPipeline, settings).run(session)
        assert session.get(IntelRecord, NETSCALER).on_kev is True  # type: ignore[union-attr]

        shrunk = copy.deepcopy(KEV_CATALOGUE)
        shrunk["vulnerabilities"] = [shrunk["vulnerabilities"][0]]
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=shrunk))
        _pipeline(KevPipeline, settings).run(session)

        delisted = session.get(IntelRecord, NETSCALER)
        assert delisted is not None
        assert delisted.on_kev is False
        assert delisted.exploit_status is ExploitStatus.NONE
        # The still-listed CVE is untouched.
        assert session.get(IntelRecord, FORTIMAIL).on_kev is True  # type: ignore[union-attr]

    @respx.mock
    def test_an_empty_catalogue_never_mass_retracts(
        self, session: Session, settings: Settings
    ) -> None:
        """An empty fetch is a broken feed, not CISA delisting everything."""
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))
        _pipeline(KevPipeline, settings).run(session)

        empty = copy.deepcopy(KEV_CATALOGUE)
        empty["vulnerabilities"] = []
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=empty))
        _pipeline(KevPipeline, settings).run(session)

        assert session.get(IntelRecord, FORTIMAIL).on_kev is True  # type: ignore[union-attr]
        assert session.get(IntelRecord, NETSCALER).on_kev is True  # type: ignore[union-attr]

    @respx.mock
    def test_a_failing_fetch_is_journalled_as_failed(
        self, session: Session, settings: Settings
    ) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(404))

        outcome = _pipeline(KevPipeline, settings).run(session)

        assert outcome.status is RunStatus.FAILED
        assert outcome.error
        runs = session.scalars(select(FeedRun)).all()
        assert any(run.status is RunStatus.FAILED for run in runs)
        assert _count(session, IntelRecord) == 0


class TestNvdRun:
    @respx.mock
    def test_stores_metrics_and_affected_ranges(self, session: Session, settings: Settings) -> None:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))

        outcome = _pipeline(NvdPipeline, settings).run(session)

        assert outcome.status is RunStatus.SUCCESS
        record = session.get(IntelRecord, FORTIMAIL)
        assert record is not None
        assert record.cvss == pytest.approx(9.8)
        assert record.cwe == ["CWE-78"]
        assert record.patch_available is True
        # NVD alone establishes no exploitation.
        assert record.exploit_status is ExploitStatus.NONE

        cpes = session.scalars(select(AffectedCpe).where(AffectedCpe.cve_id == FORTIMAIL)).all()
        assert len(cpes) == 3
        assert {cpe.vendor for cpe in cpes} == {"fortinet"}

    @respx.mock
    def test_records_and_reuses_the_watermark(self, session: Session, settings: Settings) -> None:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))

        first = _pipeline(NvdPipeline, settings).run(session)
        assert first.watermark is not None

        route = respx.get(NVD_URL).mock(
            return_value=httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
        )
        _pipeline(NvdPipeline, settings).run(session)

        # respx reuses the route for an identical pattern, so the second run's
        # request is the last one recorded, not the first.
        sent = route.calls[-1].request.url.params["lastModStartDate"]
        assert sent[:10] == first.watermark[:10]

    @respx.mock
    def test_a_failed_run_does_not_advance_the_watermark(
        self, session: Session, settings: Settings
    ) -> None:
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        first = _pipeline(NvdPipeline, settings).run(session)

        respx.get(NVD_URL).mock(return_value=httpx.Response(500))
        failed = _pipeline(NvdPipeline, settings).run(session)
        assert failed.status is RunStatus.FAILED

        pipeline = _pipeline(NvdPipeline, settings)
        assert pipeline.last_watermark(session) == first.watermark


class TestEpssRun:
    @respx.mock
    def test_annotates_tracked_cves_only(self, session: Session, settings: Settings) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))
        _pipeline(KevPipeline, settings).run(session)

        route = respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json=EPSS_RESPONSE))
        outcome = _pipeline(EpssPipeline, settings).run(session)

        assert outcome.status is RunStatus.SUCCESS
        queried = route.calls[0].request.url.params["cve"].split(",")
        assert sorted(queried) == [FORTIMAIL, NETSCALER]

        record = session.get(IntelRecord, FORTIMAIL)
        assert record is not None
        assert record.epss == pytest.approx(0.94132)
        assert record.epss_percentile == pytest.approx(0.99871)

    @respx.mock
    def test_epss_alone_never_implies_exploitation(
        self, session: Session, settings: Settings
    ) -> None:
        """Spec §7.2: EPSS raises a tier, it never establishes exploitation."""
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        _pipeline(NvdPipeline, settings).run(session)

        respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json=EPSS_RESPONSE))
        _pipeline(EpssPipeline, settings).run(session)

        record = session.get(IntelRecord, FORTIMAIL)
        assert record is not None
        assert record.epss == pytest.approx(0.94132)
        assert record.exploit_status is ExploitStatus.NONE

    @respx.mock
    def test_no_tracked_cves_is_a_clean_no_op(self, session: Session, settings: Settings) -> None:
        route = respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json=EPSS_RESPONSE))
        outcome = _pipeline(EpssPipeline, settings).run(session)

        assert outcome.status is RunStatus.SUCCESS
        assert outcome.seen == 0
        assert route.call_count == 0, "no CVEs to score means no request"


class TestFullSync:
    @respx.mock
    def test_three_feeds_compose_into_one_record(
        self, session: Session, settings: Settings
    ) -> None:
        """The shared intel record is the union of what each source owns."""
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json=EPSS_RESPONSE))

        for cls in (KevPipeline, NvdPipeline, EpssPipeline):
            assert _pipeline(cls, settings).run(session).ok

        record = session.get(IntelRecord, FORTIMAIL)
        assert record is not None
        # CISA KEV
        assert record.on_kev is True
        assert record.ransomware is True
        assert record.kev_due == datetime(2026, 12, 1).date()
        # NVD
        assert record.cvss == pytest.approx(9.8)
        assert record.cwe == ["CWE-78"]
        assert record.patch_available is True
        # FIRST EPSS
        assert record.epss == pytest.approx(0.94132)
        # Derived
        assert record.exploit_status is ExploitStatus.ACTIVE

        assert _count(session, AffectedCpe) == 3
        assert _count(session, FeedRun) == 3

    @respx.mock
    def test_a_full_resync_is_idempotent(self, session: Session, settings: Settings) -> None:
        respx.get(KEV_URL).mock(return_value=httpx.Response(200, json=KEV_CATALOGUE))
        respx.get(NVD_URL).mock(return_value=httpx.Response(200, json=NVD_RESPONSE))
        respx.get(EPSS_URL).mock(return_value=httpx.Response(200, json=EPSS_RESPONSE))

        for cls in (KevPipeline, NvdPipeline, EpssPipeline):
            _pipeline(cls, settings).run(session)

        records_before = _count(session, IntelRecord)
        cpes_before = _count(session, AffectedCpe)

        second_pass = [_pipeline(cls, settings).run(session) for cls in (KevPipeline, EpssPipeline)]

        assert all(outcome.changed == 0 for outcome in second_pass)
        assert _count(session, IntelRecord) == records_before
        assert _count(session, AffectedCpe) == cpes_before
