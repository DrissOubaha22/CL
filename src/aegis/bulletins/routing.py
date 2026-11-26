"""Automation tiers (spec §8.2).

Spec §8.2 is a three-row table:

================================================== ==========================
Exploited + patch available + exposure verified    Auto-issued under tenant
                                                   policy (logged)
Conflicting intel / no patch / unverified exposure Queued for analyst review
Critical on crown-jewel asset                      Mandatory review
================================================== ==========================

Two things are worth stating about the order. The third row *overrides* the
first: a Critical finding on a crown-jewel asset is exactly the case that
satisfies row one, and §8.2 still sends it to a human. And "under tenant
policy" means a tenant can decline automation entirely - the platform's
judgement that something is safe to auto-issue does not override the
client's decision that nothing is.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import structlog

from aegis.core.enums import (
    AutomationPolicy,
    Criticality,
    ExploitStatus,
    ReviewReason,
    Tier,
)

log = structlog.get_logger(__name__)

__all__ = ["RoutingDecision", "RoutingInputs", "route_bulletin"]


@dataclass(frozen=True, slots=True)
class RoutingInputs:
    """Everything §8.2 keys on."""

    tier: Tier
    exploit_status: ExploitStatus
    vendor_confirmed: bool
    patch_available: bool
    exposure_verified: bool
    criticality: Criticality
    #: From scoring: whether §5.3's caveats left this escalatable at all.
    auto_escalatable: bool
    automation_policy: AutomationPolicy = AutomationPolicy.REVIEW_ALL
    #: Sources disagree about exploitation - §8.2's "conflicting intel".
    conflicting_intel: bool = False
    #: The draft could not be produced from the model.
    draft_unavailable: bool = False

    @property
    def exploited(self) -> bool:
        return self.exploit_status is ExploitStatus.ACTIVE or self.vendor_confirmed


@dataclass(slots=True)
class RoutingDecision:
    """Where a bulletin goes, and why."""

    auto_issue: bool
    reasons: list[ReviewReason] = field(default_factory=list)
    #: Mandatory review cannot be waived by tenant policy (spec §8.2 row 3).
    mandatory_review: bool = False

    @property
    def reason_values(self) -> list[str]:
        return [str(reason) for reason in self.reasons]

    def explain(self) -> str:
        if self.auto_issue:
            return "auto-issued: exploited, patch available, exposure verified"
        return "; ".join(_REASON_TEXT[reason] for reason in self.reasons)


_REASON_TEXT: dict[ReviewReason, str] = {
    ReviewReason.NONE: "no caveat",
    ReviewReason.NOT_AUTO_ESCALATABLE: (
        "the match carries a caveat that bars automatic escalation"
    ),
    ReviewReason.NO_PATCH: "no vendor patch is available yet",
    ReviewReason.EXPOSURE_UNVERIFIED: "exposure has not been confirmed by an active check",
    ReviewReason.CONFLICTING_INTEL: "sources disagree about exploitation",
    ReviewReason.CROWN_JEWEL: "critical finding on a crown-jewel asset",
    ReviewReason.TENANT_POLICY: "this tenant reviews every bulletin",
    ReviewReason.DRAFT_UNAVAILABLE: "the advisory text could not be drafted",
}


def route_bulletin(inputs: RoutingInputs) -> RoutingDecision:
    """Decide whether a bulletin may be issued without a human (spec §8.2).

    Returns:
        The decision, with every reason a human is needed.  All reasons are
        collected rather than short-circuiting on the first: an analyst
        picking up the queue should see the whole picture.
    """
    reasons: list[ReviewReason] = []

    # --- Row 3 first: it overrides row 1 ----------------------------------
    mandatory = inputs.tier is Tier.CRITICAL and inputs.criticality is Criticality.HIGH
    if mandatory:
        reasons.append(ReviewReason.CROWN_JEWEL)

    # --- Row 2: the conditions that send a case to an analyst -------------
    if not inputs.exploited:
        # Row 1 requires exploitation; without it there is nothing to
        # auto-issue, and the bulletin is routine work for a human queue.
        reasons.append(ReviewReason.NOT_AUTO_ESCALATABLE)
    if not inputs.patch_available:
        reasons.append(ReviewReason.NO_PATCH)
    if not inputs.exposure_verified:
        reasons.append(ReviewReason.EXPOSURE_UNVERIFIED)
    if inputs.conflicting_intel:
        reasons.append(ReviewReason.CONFLICTING_INTEL)
    if not inputs.auto_escalatable and ReviewReason.NOT_AUTO_ESCALATABLE not in reasons:
        reasons.append(ReviewReason.NOT_AUTO_ESCALATABLE)
    if inputs.draft_unavailable:
        reasons.append(ReviewReason.DRAFT_UNAVAILABLE)

    # --- Tenant policy: "under tenant policy", spec §8.2 row 1 ------------
    if inputs.automation_policy is not AutomationPolicy.AUTO_ISSUE_VERIFIED:
        reasons.append(ReviewReason.TENANT_POLICY)

    decision = RoutingDecision(
        auto_issue=not reasons,
        reasons=reasons,
        mandatory_review=mandatory,
    )
    log.info(
        "bulletin.routed",
        tier=str(inputs.tier),
        auto_issue=decision.auto_issue,
        reasons=decision.reason_values,
    )
    return decision
