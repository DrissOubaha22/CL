"""Feed HTTP client behaviour."""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from aegis.config import Settings
from aegis.intel.http import FeedClient, FeedHttpError, RateLimiter

URL = "https://feeds.test/data.json"


@pytest.fixture
def settings() -> Settings:
    return Settings(http_max_retries=3, http_timeout_seconds=5.0)


class TestFeedClient:
    @respx.mock
    def test_returns_decoded_json(self, settings: Settings) -> None:
        respx.get(URL).mock(return_value=httpx.Response(200, json={"ok": True}))
        with FeedClient(settings=settings) as client:
            assert client.get_json(URL) == {"ok": True}

    @respx.mock
    def test_sends_a_generic_user_agent(self, settings: Settings) -> None:
        """No client-identifying data ever reaches a feed (spec §1, §11)."""
        route = respx.get(URL).mock(return_value=httpx.Response(200, json={}))
        with FeedClient(settings=settings) as client:
            client.get_json(URL)

        agent = route.calls[0].request.headers["user-agent"]
        assert agent == settings.user_agent
        assert "aegis-intel-etl" in agent

    @respx.mock
    @pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
    def test_retries_retryable_statuses(self, settings: Settings, status: int) -> None:
        route = respx.get(URL).mock(
            side_effect=[
                httpx.Response(status),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        with FeedClient(settings=settings) as client:
            assert client.get_json(URL) == {"ok": True}
        assert route.call_count == 2

    @respx.mock
    @pytest.mark.parametrize("status", [400, 401, 403, 404])
    def test_does_not_retry_client_errors(self, settings: Settings, status: int) -> None:
        route = respx.get(URL).mock(return_value=httpx.Response(status))
        with FeedClient(settings=settings) as client, pytest.raises(FeedHttpError) as err:
            client.get_json(URL)
        assert err.value.status_code == status
        assert route.call_count == 1

    @respx.mock
    def test_gives_up_after_the_retry_budget(self, settings: Settings) -> None:
        route = respx.get(URL).mock(return_value=httpx.Response(503))
        with FeedClient(settings=settings) as client, pytest.raises(FeedHttpError):
            client.get_json(URL)
        assert route.call_count == settings.http_max_retries

    @respx.mock
    def test_retries_a_transport_error(self, settings: Settings) -> None:
        route = respx.get(URL).mock(
            side_effect=[
                httpx.ConnectError("reset"),
                httpx.Response(200, json={"ok": True}),
            ]
        )
        with FeedClient(settings=settings) as client:
            assert client.get_json(URL) == {"ok": True}
        assert route.call_count == 2

    @respx.mock
    def test_rejects_a_non_json_body(self, settings: Settings) -> None:
        respx.get(URL).mock(return_value=httpx.Response(200, text="<html>nope"))
        with (
            FeedClient(settings=settings) as client,
            pytest.raises(FeedHttpError, match="non-JSON"),
        ):
            client.get_json(URL)


class TestRateLimiter:
    def test_allows_the_budget_without_waiting(self) -> None:
        limiter = RateLimiter(max_requests=5, window_seconds=10.0)
        start = time.monotonic()
        for _ in range(5):
            limiter.acquire()
        assert time.monotonic() - start < 0.1

    def test_blocks_once_the_budget_is_spent(self) -> None:
        """NVD answers 403 to clients that outrun their budget."""
        limiter = RateLimiter(max_requests=2, window_seconds=0.25)
        for _ in range(2):
            limiter.acquire()

        start = time.monotonic()
        limiter.acquire()
        waited = time.monotonic() - start
        assert waited >= 0.2, f"expected to wait out the window, waited {waited:.3f}s"
