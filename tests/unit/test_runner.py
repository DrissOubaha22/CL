"""Pipeline registry and run ordering."""

from __future__ import annotations

import pytest

from aegis.core.enums import FeedSource, RunStatus
from aegis.intel import runner
from aegis.intel.feeds.base import PipelineOutcome
from aegis.intel.feeds.registry import PIPELINES, SYNC_ORDER, get_pipeline


class TestRegistry:
    def test_resolves_an_implemented_pipeline(self) -> None:
        assert get_pipeline(FeedSource.CISA_KEV).source is FeedSource.CISA_KEV

    def test_reports_what_is_implemented_when_asked_for_a_missing_feed(self) -> None:
        with pytest.raises(KeyError, match="no pipeline for"):
            get_pipeline(FeedSource.VULNCHECK_KEV)

    def test_sync_order_covers_every_implemented_pipeline(self) -> None:
        assert set(SYNC_ORDER) == set(PIPELINES)

    def test_annotating_feeds_run_after_feeds_that_introduce_cves(self) -> None:
        """EPSS scores what is already in the store, so it must run last."""
        assert SYNC_ORDER.index(FeedSource.FIRST_EPSS) > SYNC_ORDER.index(FeedSource.CISA_KEV)
        assert SYNC_ORDER.index(FeedSource.FIRST_EPSS) > SYNC_ORDER.index(FeedSource.NVD)


class TestRunPipelines:
    @pytest.fixture
    def recorder(self, monkeypatch: pytest.MonkeyPatch) -> list[FeedSource]:
        calls: list[FeedSource] = []

        def fake_run(source: FeedSource, *, engine=None) -> PipelineOutcome:
            calls.append(source)
            return PipelineOutcome(source=source, status=RunStatus.SUCCESS)

        monkeypatch.setattr(runner, "run_pipeline", fake_run)
        return calls

    def test_runs_every_feed_in_dependency_order_by_default(
        self, recorder: list[FeedSource]
    ) -> None:
        runner.run_pipelines()
        assert recorder == list(SYNC_ORDER)

    def test_reorders_a_caller_supplied_subset(self, recorder: list[FeedSource]) -> None:
        runner.run_pipelines([FeedSource.FIRST_EPSS, FeedSource.CISA_KEV])
        assert recorder == [FeedSource.CISA_KEV, FeedSource.FIRST_EPSS]

    def test_unordered_feeds_run_after_the_known_ones(self, recorder: list[FeedSource]) -> None:
        runner.run_pipelines([FeedSource.EXPLOIT_DB, FeedSource.CISA_KEV])
        assert recorder == [FeedSource.CISA_KEV, FeedSource.EXPLOIT_DB]

    def test_one_broken_feed_does_not_stop_the_others(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(source: FeedSource, *, engine=None) -> PipelineOutcome:
            status = RunStatus.FAILED if source is FeedSource.CISA_KEV else RunStatus.SUCCESS
            return PipelineOutcome(source=source, status=status)

        monkeypatch.setattr(runner, "run_pipeline", fake_run)
        outcomes = runner.run_pipelines()

        assert len(outcomes) == len(SYNC_ORDER)
        assert [o.ok for o in outcomes] == [False, True, True]

    def test_stop_on_error_aborts_the_rest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_run(source: FeedSource, *, engine=None) -> PipelineOutcome:
            return PipelineOutcome(source=source, status=RunStatus.FAILED)

        monkeypatch.setattr(runner, "run_pipeline", fake_run)
        assert len(runner.run_pipelines(stop_on_error=True)) == 1
