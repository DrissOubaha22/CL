"""Fetching a vendor advisory page as text (spec §4.2).

The LLM path is the only part of Aegis that reads unstructured pages, and
what comes back is untrusted: it is wrapped as data before any model sees it
(spec §8.3).  This module's job is narrow - get the page, reduce it to
readable text, and hand back a :class:`PublicPayload`.
"""

from __future__ import annotations

import html
import re

import httpx
import structlog

from aegis.ai.privacy import PublicPayload
from aegis.config import Settings, get_settings

log = structlog.get_logger(__name__)

__all__ = ["AdvisoryFetchError", "fetch_advisory_text", "html_to_text"]

_SCRIPT_OR_STYLE = re.compile(r"<(script|style|noscript|svg)\b[^>]*>.*?</\1>", re.I | re.S)
_TAG = re.compile(r"<[^>]+>")
_BLOCK_END = re.compile(r"</(p|div|li|tr|h[1-6]|br|section)\s*>", re.I)
_WHITESPACE = re.compile(r"[ \t\f\v]+")
_BLANK_LINES = re.compile(r"\n{3,}")


class AdvisoryFetchError(RuntimeError):
    """The advisory page could not be retrieved or read."""


def html_to_text(markup: str) -> str:
    """Reduce an HTML page to the text a reader would see.

    Deliberately simple: scripts and styles go, block ends become newlines,
    tags are stripped and entities decoded.  A full renderer would add a
    dependency and a parser's attack surface for no gain - the model is
    reading prose, not a layout.
    """
    without_code = _SCRIPT_OR_STYLE.sub(" ", markup)
    with_breaks = _BLOCK_END.sub("\n", without_code)
    text = html.unescape(_TAG.sub(" ", with_breaks))
    text = _WHITESPACE.sub(" ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    return _BLANK_LINES.sub("\n\n", text).strip()


def fetch_advisory_text(
    url: str,
    *,
    settings: Settings | None = None,
    client: httpx.Client | None = None,
) -> PublicPayload:
    """Fetch a public advisory page and return it as untrusted text.

    Args:
        url: The advisory URL, taken from intel the store already holds.
        settings: Override configuration.
        client: Override the HTTP client (tests).

    Raises:
        AdvisoryFetchError: on a non-2xx response, a transport failure, or a
            body with no readable text.
    """
    config = settings or get_settings()
    owns_client = client is None
    http = client or httpx.Client(
        timeout=config.http_timeout_seconds,
        follow_redirects=True,
        headers={
            "User-Agent": config.user_agent,
            "Accept": "text/html,application/xhtml+xml,text/plain",
        },
    )

    try:
        response = http.get(url)
    except httpx.HTTPError as exc:
        raise AdvisoryFetchError(f"cannot fetch {url}: {exc}") from exc
    finally:
        if owns_client:
            http.close()

    if response.status_code >= 400:
        raise AdvisoryFetchError(f"{response.status_code} from {url}")

    content_type = response.headers.get("content-type", "")
    body = response.text
    text = body if "text/plain" in content_type else html_to_text(body)

    if not text.strip():
        raise AdvisoryFetchError(f"no readable text at {url}")

    log.info("advisory.fetched", url=url, characters=len(text))
    return PublicPayload(kind="advisory_page", text=text, source_url=url)
