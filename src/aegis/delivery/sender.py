"""Sending issued bulletins to a tenant's destinations (spec §12).

Only *issued* bulletins are sent - auto-issued under §8.2, or released by
an analyst.  A queued bulletin is a draft waiting for a human, and pushing
drafts into an on-call channel is how an alerting integration gets muted.

Delivery is idempotent: a bulletin already delivered to a destination is
not sent again, enforced by a partial unique index on successful rows
rather than by the sender remembering.  Failures are retried on the next
run and leave a row each time, because "the webhook was down for an hour"
is a question someone will ask.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from aegis.auth.secrets import SecretNotFound, SecretStore
from aegis.config import Settings, get_settings
from aegis.core.enums import BulletinStatus, DeliveryStatus
from aegis.db.models import Bulletin, Delivery, DeliveryDestination
from aegis.delivery.formatters import format_payload

log = structlog.get_logger(__name__)

__all__ = ["DeliveryResult", "send_bulletins"]

#: Status codes worth another attempt; a 4xx other than 429 is a bad
#: webhook URL, which retrying will not fix.
_RETRYABLE = frozenset({408, 425, 429, 500, 502, 503, 504})


class _Retryable(RuntimeError):
    """Internal marker for a transient webhook failure."""


@dataclass(slots=True)
class DeliveryResult:
    """What one delivery pass did."""

    considered: int = 0
    sent: int = 0
    failed: int = 0
    skipped: int = 0
    #: Destinations whose secret is missing - a misconfiguration, not a
    #: transient failure, so it is counted separately.
    misconfigured: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.failed == 0 and not self.misconfigured


def send_bulletins(
    session: Session,
    destinations: Sequence[DeliveryDestination],
    *,
    secrets: SecretStore,
    settings: Settings | None = None,
    bulletin_ids: Iterable[int] | None = None,
    client: httpx.Client | None = None,
    now: datetime | None = None,
) -> DeliveryResult:
    """Send this tenant's issued bulletins to its destinations.

    Args:
        session: A tenant-scoped session.
        destinations: The tenant's destinations, read from the control
            schema by the caller - tenant workers never see the control
            schema themselves.
        secrets: Where webhook URLs are looked up (spec §11).
        settings: Override configuration.
        bulletin_ids: Restrict to these bulletins.
        client: Override the HTTP client (tests).
        now: Timestamp for the pass.

    Returns:
        Counts, plus any destination whose secret could not be resolved.
    """
    config = settings or get_settings()
    when = now or datetime.now(UTC)
    result = DeliveryResult()

    if not config.delivery_enabled:
        log.warning("delivery.disabled")
        return result

    active = [item for item in destinations if item.active]
    if not active:
        return result

    bulletins = _issued_bulletins(session, bulletin_ids)
    result.considered = len(bulletins)
    if not bulletins:
        return result

    already = _already_delivered(session, [item.bulletin_id for item in bulletins])

    owns_client = client is None
    http = client or httpx.Client(
        timeout=config.delivery_timeout_seconds,
        headers={"User-Agent": config.user_agent, "Content-Type": "application/json"},
    )

    try:
        for bulletin in bulletins:
            for destination in active:
                if not destination.accepts(bulletin.tier, auto_issued=bulletin.auto_issued):
                    result.skipped += 1
                    continue
                if (bulletin.bulletin_id, destination.id) in already:
                    result.skipped += 1
                    continue

                _deliver_one(
                    session,
                    bulletin,
                    destination,
                    secrets=secrets,
                    settings=config,
                    http=http,
                    when=when,
                    result=result,
                )
    finally:
        if owns_client:
            http.close()

    session.flush()
    log.info(
        "delivery.finished",
        considered=result.considered,
        sent=result.sent,
        failed=result.failed,
        skipped=result.skipped,
    )
    return result


def _deliver_one(
    session: Session,
    bulletin: Bulletin,
    destination: DeliveryDestination,
    *,
    secrets: SecretStore,
    settings: Settings,
    http: httpx.Client,
    when: datetime,
    result: DeliveryResult,
) -> None:
    """Send one bulletin to one destination, recording the attempt."""
    attempt = Delivery(
        bulletin_id=bulletin.bulletin_id,
        destination_id=destination.id,
        destination_label=destination.label,
        channel=destination.channel,
        attempted_at=when,
        attempt=_next_attempt(session, bulletin.bulletin_id, destination.id),
    )
    session.add(attempt)

    try:
        url = secrets.get(destination.webhook_secret_name)
    except SecretNotFound as exc:
        # A misconfiguration, not a transient failure: retrying will not
        # conjure the secret, so it is surfaced rather than retried.
        attempt.status = DeliveryStatus.FAILED
        attempt.error = str(exc)
        result.misconfigured.append(destination.label)
        log.error(
            "delivery.secret_missing",
            destination=destination.label,
            secret=destination.webhook_secret_name,
        )
        return

    asset = bulletin.match.asset
    payload = format_payload(
        channel=destination.channel,
        cve_id=bulletin.cve_id,
        tier=bulletin.tier,
        hostname=asset.hostname,
        product=asset.product_name,
        body=bulletin.body,
        auto_issued=bulletin.auto_issued,
        due_at=_due_text(bulletin),
        review_reasons=list(bulletin.review_reasons or []),
    )

    try:
        status_code = _post_with_retry(http, url, payload, settings=settings)
    except Exception as exc:
        attempt.status = DeliveryStatus.FAILED
        attempt.error = str(exc)[:1000]
        result.failed += 1
        log.warning(
            "delivery.failed",
            destination=destination.label,
            bulletin=bulletin.bulletin_id,
            error=str(exc),
        )
        return

    attempt.status = DeliveryStatus.DELIVERED
    attempt.status_code = status_code
    result.sent += 1
    log.info(
        "delivery.sent",
        destination=destination.label,
        channel=str(destination.channel),
        bulletin=bulletin.bulletin_id,
        cve=bulletin.cve_id,
    )


def _post_with_retry(
    http: httpx.Client,
    url: str,
    payload: dict[str, Any],
    *,
    settings: Settings,
) -> int:
    """POST the payload, retrying only what retrying can fix."""
    attempts = max(1, settings.delivery_max_retries)

    @retry(
        retry=retry_if_exception_type((_Retryable, httpx.TransportError)),
        stop=stop_after_attempt(attempts),
        wait=wait_exponential_jitter(initial=1, max=20),
        reraise=True,
    )
    def _send() -> int:
        response = http.post(url, json=payload)
        if response.status_code in _RETRYABLE:
            raise _Retryable(f"{response.status_code} from webhook")
        if response.status_code >= 400:
            raise RuntimeError(f"{response.status_code} from webhook: {response.text[:200]}")
        return int(response.status_code)

    return _send()


def _issued_bulletins(session: Session, bulletin_ids: Iterable[int] | None) -> list[Bulletin]:
    """Bulletins a client should actually receive.

    Queued ones are excluded: they are drafts awaiting a human, and sending
    drafts to an on-call channel is how an integration gets muted.
    """
    statement = select(Bulletin).where(
        Bulletin.status.in_([BulletinStatus.AUTO_ISSUED, BulletinStatus.ISSUED])
    )
    if bulletin_ids is not None:
        ids = list(bulletin_ids)
        if not ids:
            return []
        statement = statement.where(Bulletin.bulletin_id.in_(ids))
    return list(session.scalars(statement).all())


def _already_delivered(session: Session, bulletin_ids: Sequence[int]) -> set[tuple[int, int]]:
    if not bulletin_ids:
        return set()
    rows = session.execute(
        select(Delivery.bulletin_id, Delivery.destination_id).where(
            Delivery.bulletin_id.in_(list(bulletin_ids)),
            Delivery.status == DeliveryStatus.DELIVERED,
        )
    ).all()
    return {(bulletin_id, destination_id) for bulletin_id, destination_id in rows}


def _next_attempt(session: Session, bulletin_id: int, destination_id: int) -> int:
    from sqlalchemy import func

    previous = (
        session.scalar(
            select(func.count())
            .select_from(Delivery)
            .where(
                Delivery.bulletin_id == bulletin_id,
                Delivery.destination_id == destination_id,
            )
        )
        or 0
    )
    return previous + 1


def _due_text(bulletin: Bulletin) -> str | None:
    score = bulletin.match.score
    if score is None or score.due_at is None:
        return None
    return f"{score.due_at:%Y-%m-%d}"
