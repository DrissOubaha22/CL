"""HTTP access for the deterministic feed pipelines.

Only public intel endpoints are fetched here, and only data goes out that the
endpoint needs: no client identity ever reaches a feed (spec §1, §11).  The
user agent is a generic tool name for the same reason.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Mapping
from types import TracebackType
from typing import Any

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from aegis.config import Settings, get_settings

log = structlog.get_logger(__name__)

__all__ = ["FeedClient", "FeedHttpError", "RateLimiter"]

#: Transport failures and 5xx/429 responses are worth another attempt;
#: a 4xx other than 429 is a bug or a bad key and is raised immediately.
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


class FeedHttpError(RuntimeError):
    """A feed request failed in a way the pipeline should report."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class _RetryableHttpError(FeedHttpError):
    """Internal marker: the request may succeed if tried again."""


class RateLimiter:
    """Sliding-window limiter, shared across threads.

    NVD publishes a request budget per 30-second window and answers 403 to
    clients that exceed it, so the pipeline paces itself rather than relying
    on retries.
    """

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self._max_requests = max(1, max_requests)
        self._window = window_seconds
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self._window:
                    self._calls.popleft()
                if len(self._calls) < self._max_requests:
                    self._calls.append(now)
                    return
                sleep_for = self._window - (now - self._calls[0])
            time.sleep(max(sleep_for, 0.01))


class FeedClient:
    """Thin ``httpx`` wrapper with retries, pacing and JSON decoding."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        rate_limiter: RateLimiter | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._rate_limiter = rate_limiter
        self._owns_client = client is None
        self._client = client or httpx.Client(
            timeout=self._settings.http_timeout_seconds,
            headers={
                "User-Agent": self._settings.user_agent,
                "Accept": "application/json",
            },
            follow_redirects=True,
        )

    def __enter__(self) -> FeedClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Any:
        """GET ``url`` and decode the JSON body.

        Raises:
            FeedHttpError: on a non-retryable status, an exhausted retry
                budget, or a body that is not JSON.
        """
        attempts = max(1, self._settings.http_max_retries)

        @retry(
            retry=retry_if_exception_type((_RetryableHttpError, httpx.TransportError)),
            stop=stop_after_attempt(attempts),
            wait=wait_exponential_jitter(initial=1, max=30),
            reraise=True,
        )
        def _request() -> Any:
            if self._rate_limiter is not None:
                self._rate_limiter.acquire()
            try:
                response = self._client.get(
                    url, params=dict(params or {}), headers=dict(headers or {})
                )
            except httpx.TransportError:
                log.warning("feed.http.transport_error", url=url)
                raise

            if response.status_code in _RETRYABLE_STATUS:
                log.warning(
                    "feed.http.retryable",
                    url=url,
                    status=response.status_code,
                )
                raise _RetryableHttpError(
                    f"{response.status_code} from {url}",
                    status_code=response.status_code,
                )
            if response.status_code >= 400:
                raise FeedHttpError(
                    f"{response.status_code} from {url}",
                    status_code=response.status_code,
                )

            try:
                return response.json()
            except ValueError as exc:
                raise FeedHttpError(f"non-JSON body from {url}: {exc}") from exc

        try:
            return _request()
        except httpx.TransportError as exc:
            raise FeedHttpError(f"transport failure for {url}: {exc}") from exc
