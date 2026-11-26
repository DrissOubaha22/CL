"""Template injection (spec §8.1).

The second half of §8.1: the model's public draft goes in, the tenant's own
details are merged around it, and the result never leaves the Aegis
environment to be assembled.

Everything in :class:`TenantContext` is client-identifying.  It is built
from tenant rows, it is rendered here, and it is never passed to anything
in :mod:`aegis.ai`.  The separation is the point: this module imports no
model client, and :mod:`aegis.bulletins.drafting` imports nothing
tenant-scoped.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aegis.core.enums import Criticality, ExposureClass, MatchFlag, Tier

__all__ = ["TenantContext", "render_bulletin"]


@dataclass(frozen=True, slots=True)
class TenantContext:
    """The client-specific half of a bulletin.

    Built from the tenant's asset, match, verification and score - i.e.
    exactly the data spec §8.1 keeps away from the model.
    """

    hostname: str
    product: str
    version: str | None
    exposure_class: ExposureClass
    criticality: Criticality
    tier: Tier
    due_at: datetime | None
    kev_due: datetime | None
    flags: tuple[str, ...] = ()
    matched_range: str | None = None
    exposure_verified_at: datetime | None = None
    waf_detected: bool = False


def render_bulletin(
    *,
    cve_id: str,
    draft: str,
    context: TenantContext,
) -> str:
    """Merge the public draft with this tenant's specifics.

    Args:
        cve_id: The CVE the bulletin is about.
        draft: Prose written from public facts only.
        context: The client-specific fields.

    Returns:
        The bulletin as the client receives it.
    """
    lines: list[str] = [
        f"[{str(context.tier).upper()}] {cve_id} - {context.product}",
        "",
        f"Affected asset:   {context.hostname}",
        f"Product/version:  {context.product} {context.version or '(version unknown)'}",
        f"Exposure:         {_exposure_line(context)}",
        f"Asset criticality:{_criticality_line(context.criticality)}",
    ]

    if context.matched_range:
        lines.append(f"Advisory range:   {context.matched_range}")

    lines.extend(
        [
            f"Risk tier:        {str(context.tier).upper()} ({context.tier.remediation_window})",
            f"Remediate by:     {_due_line(context)}",
            "",
            "What this is",
            "------------",
            draft,
            "",
        ]
    )

    caveats = _caveats(context)
    if caveats:
        lines.extend(["Before you act on this", "----------------------"])
        lines.extend(f"- {caveat}" for caveat in caveats)
        lines.append("")

    lines.append(
        "This bulletin was produced by correlating public exploitation "
        "intelligence against your own inventory. The affected asset and its "
        "exposure were determined inside your tenant; no host, address or "
        "organisation name was sent to any external service."
    )
    return "\n".join(lines)


def _exposure_line(context: TenantContext) -> str:
    if context.exposure_class is ExposureClass.INTERNET:
        if context.waf_detected:
            return "internet-facing, behind a WAF or proxy (verified)"
        if context.exposure_verified_at is not None:
            return (
                f"internet-facing, confirmed reachable on {context.exposure_verified_at:%Y-%m-%d}"
            )
        return "internet-facing per discovery, not yet confirmed by an active check"
    if context.exposure_class is ExposureClass.CLIENT_SIDE:
        return "client-side software (risk is weaponised content, not perimeter)"
    if context.exposure_class is ExposureClass.INTERNAL:
        return "internal only, not reachable from the internet"
    return "unknown"


def _criticality_line(criticality: Criticality) -> str:
    return f" {criticality}" if criticality is not Criticality.UNKNOWN else " untagged"


def _due_line(context: TenantContext) -> str:
    if context.tier is Tier.CRITICAL:
        base = "out-of-band - do not wait for the next maintenance window"
    elif context.due_at is not None:
        base = f"{context.due_at:%Y-%m-%d} ({context.tier.remediation_window})"
    else:
        base = context.tier.remediation_window

    if context.kev_due is not None:
        return f"{base}; CISA KEV due date {context.kev_due:%Y-%m-%d}"
    return base


def _caveats(context: TenantContext) -> list[str]:
    """Turn the match's flags into plain warnings (spec §5.3).

    A client acting on a flagged match needs to know what the flag means,
    not the flag's name.
    """
    caveats: list[str] = []
    flags = set(context.flags)

    if str(MatchFlag.UNVERIFIED) in flags:
        caveats.append(
            "Exposure has not been confirmed by an active check, so this has "
            "not been escalated on reachability alone."
        )
    if str(MatchFlag.BACKPORT) in flags:
        caveats.append(
            "This is a distribution-packaged component. Distributions backport "
            "fixes without changing the version string, so confirm the "
            "installed package's changelog before treating it as vulnerable."
        )
    if str(MatchFlag.CONFIG_DEPENDENT) in flags:
        caveats.append(
            "The advisory states exploitation requires a specific feature or "
            "configuration. Confirm whether this deployment is in that "
            "configuration."
        )
    if str(MatchFlag.UNPARSEABLE_VERSION) in flags:
        caveats.append(
            "The discovered version string could not be compared against the "
            "advisory's range, so this match rests on the product identity "
            "alone."
        )
    if str(MatchFlag.UNBOUNDED_RANGE) in flags:
        caveats.append(
            "The advisory names the product without a version bound, so the "
            "affected range may be broader than the vendor intended."
        )
    if context.waf_detected:
        caveats.append(
            "A WAF or proxy answered on this service, so the origin is not "
            "directly exploitable; the underlying version still needs fixing."
        )
    return caveats
