"""Rendering a bulletin for each destination (spec §12).

Slack and Teams both accept an incoming webhook, but they read different
JSON.  Both formatters take the same bulletin and produce the payload that
destination expects, with a plain-text fallback so a client that renders
neither still gets something readable.

What goes over the webhook is tenant data - hostnames, tiers, due dates -
and that is correct: the destination is the tenant's own channel.  The
privacy boundary of §8.1 is about the *model*, not about the client's own
alerts.
"""

from __future__ import annotations

from typing import Any

from aegis.core.enums import DeliveryChannel, Tier

__all__ = ["format_payload", "summary_line"]

#: Slack's colour bar, and the closest Teams theme colour.
_TIER_COLOUR: dict[Tier, str] = {
    Tier.CRITICAL: "#B00020",
    Tier.HIGH: "#E65100",
    Tier.MEDIUM: "#F9A825",
    Tier.LOW: "#546E7A",
}

#: Slack and Teams both truncate long blocks; keep the body readable.
_MAX_BODY_CHARS = 2800


def summary_line(*, cve_id: str, tier: Tier, hostname: str, product: str, auto_issued: bool) -> str:
    """One line that is useful on a phone notification."""
    origin = "auto-issued" if auto_issued else "analyst-released"
    return f"[{str(tier).upper()}] {cve_id} on {hostname} ({product}) - {origin}"


def format_payload(
    *,
    channel: DeliveryChannel,
    cve_id: str,
    tier: Tier,
    hostname: str,
    product: str,
    body: str,
    auto_issued: bool,
    due_at: str | None = None,
    review_reasons: list[str] | None = None,
) -> dict[str, Any]:
    """Build the webhook payload for ``channel``."""
    summary = summary_line(
        cve_id=cve_id,
        tier=tier,
        hostname=hostname,
        product=product,
        auto_issued=auto_issued,
    )
    trimmed = _trim(body)

    if channel is DeliveryChannel.SLACK:
        return _slack(summary, trimmed, tier, due_at, review_reasons)
    if channel is DeliveryChannel.TEAMS:
        return _teams(summary, trimmed, tier, cve_id, hostname, due_at, review_reasons)

    raise ValueError(f"no formatter for channel {channel!r}")


def _slack(
    summary: str,
    body: str,
    tier: Tier,
    due_at: str | None,
    review_reasons: list[str] | None,
) -> dict[str, Any]:
    fields: list[dict[str, str]] = [
        {"type": "mrkdwn", "text": f"*Tier*\n{str(tier).upper()}"},
        {"type": "mrkdwn", "text": f"*Remediate by*\n{due_at or 'out-of-band'}"},
    ]
    if review_reasons:
        fields.append({"type": "mrkdwn", "text": f"*Held for review*\n{', '.join(review_reasons)}"})

    return {
        # `text` is the notification preview and the fallback for clients
        # that cannot render blocks.
        "text": summary,
        "attachments": [
            {
                "color": _TIER_COLOUR.get(tier, "#546E7A"),
                "blocks": [
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*{summary}*"},
                    },
                    {"type": "section", "fields": fields},
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"```{body}```"},
                    },
                ],
            }
        ],
    }


def _teams(
    summary: str,
    body: str,
    tier: Tier,
    cve_id: str,
    hostname: str,
    due_at: str | None,
    review_reasons: list[str] | None,
) -> dict[str, Any]:
    facts = [
        {"name": "Tier", "value": str(tier).upper()},
        {"name": "Asset", "value": hostname},
        {"name": "Remediate by", "value": due_at or "out-of-band"},
    ]
    if review_reasons:
        facts.append({"name": "Held for review", "value": ", ".join(review_reasons)})

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": summary,
        "themeColor": _TIER_COLOUR.get(tier, "#546E7A").lstrip("#"),
        "title": summary,
        "sections": [
            {"facts": facts, "markdown": False},
            {"text": body.replace("\n", "\n\n"), "markdown": False},
        ],
    }


def _trim(body: str) -> str:
    if len(body) <= _MAX_BODY_CHARS:
        return body
    return body[:_MAX_BODY_CHARS].rstrip() + "\n[...] see the portal for the full bulletin"
