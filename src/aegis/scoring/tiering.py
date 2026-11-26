"""Risk tiering (spec §7.2).

The tier is computed in two steps, kept separate on purpose:

1. :func:`base_tier` - the specification's own rule, transcribed as written.
   It answers "how bad would this be if the match is real?"
2. :func:`apply_gates` - the caps from §5.3 and §6.2.  They answer "how far
   has that been established?"

Keeping them apart is what lets a score explain itself: a case sitting at
Medium records that it *would* be Critical, and which caveat is holding it
there.  Collapsing the two would produce a tier nobody can argue with, which
in practice means a tier nobody acts on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.core.enums import (
    Criticality,
    ExploitStatus,
    ExposureClass,
    MatchFlag,
    Tier,
)

__all__ = ["ScoreInputs", "TierDecision", "apply_gates", "base_tier", "score_match"]

#: EPSS at or above this reaches Medium on its own (spec §7.2).
EPSS_MEDIUM_THRESHOLD = 0.5

#: Caveats that bar automatic escalation to High or Critical (spec §5.3).
#: Each means the match might not be real, which is a different question from
#: how severe it would be.
_GATING_FLAGS = frozenset(
    {
        MatchFlag.UNVERIFIED,
        MatchFlag.BACKPORT,
        MatchFlag.CONFIG_DEPENDENT,
        MatchFlag.UNPARSEABLE_VERSION,
    }
)


@dataclass(frozen=True, slots=True)
class ScoreInputs:
    """Everything §7.1 lists as an input to the tier."""

    # From the shared intel record.
    exploit_status: ExploitStatus = ExploitStatus.NONE
    on_kev: bool = False
    vendor_confirmed: bool = False
    public_exploit: bool = False
    ransomware: bool = False
    epss: float | None = None

    # From the tenant's asset.
    exposure_class: ExposureClass = ExposureClass.UNKNOWN
    criticality: Criticality = Criticality.UNKNOWN

    # From the match and its verification.
    flags: tuple[MatchFlag, ...] = ()
    exposure_verified: bool = False
    waf_detected: bool = False

    @property
    def exploited(self) -> bool:
        """Spec §7.2: ``exploited := on_kev or vendor_confirmed``.

        ``exploit_status`` already folds in a third-party in-the-wild report
        (§7.1 names VulnCheck), so it is the authority here; the two booleans
        remain because §7.2 writes the rule in terms of them.
        """
        return self.exploit_status is ExploitStatus.ACTIVE or self.on_kev or self.vendor_confirmed


@dataclass(slots=True)
class TierDecision:
    """A tier, what it would have been, and why."""

    tier: Tier
    tier_before_gate: Tier
    auto_escalatable: bool
    factors: dict[str, Any] = field(default_factory=dict)

    @property
    def was_capped(self) -> bool:
        return self.tier is not self.tier_before_gate


def base_tier(inputs: ScoreInputs) -> Tier:
    """The tier §7.2 assigns, assuming the match is real.

    Transcribed from the specification's pseudocode, in its order:

    .. code-block:: text

        if exploited and exposure==INTERNET and (criticality==HIGH or ransomware):
            CRITICAL
        elif exploited and (exposure==INTERNET or criticality==HIGH or ransomware):
            HIGH
        elif exposure==CLIENT_SIDE and exploited:
            HIGH
        elif exploited or public_exploit or epss >= 0.5:
            MEDIUM
        else:
            LOW
    """
    exploited = inputs.exploited
    internet = inputs.exposure_class is ExposureClass.INTERNET
    high_value = inputs.criticality is Criticality.HIGH
    ransomware = inputs.ransomware

    if exploited and internet and (high_value or ransomware):
        return Tier.CRITICAL
    if exploited and (internet or high_value or ransomware):
        return Tier.HIGH
    # Weaponised content: the risk basis is user interaction, not perimeter
    # reachability (spec §6.3), so client-side exploitation is High in its
    # own right.
    if inputs.exposure_class is ExposureClass.CLIENT_SIDE and exploited:
        return Tier.HIGH
    if (
        exploited
        or inputs.public_exploit
        or (inputs.epss is not None and inputs.epss >= EPSS_MEDIUM_THRESHOLD)
    ):
        return Tier.MEDIUM
    return Tier.LOW


def apply_gates(inputs: ScoreInputs, tier: Tier) -> TierDecision:
    """Cap a tier by how well the match has been established.

    Spec §5.3: "No match becomes a Critical/High case until exposure
    verification (§6) confirms it."  Spec §6.1: a WAF-fronted origin "is not
    escalated as directly exploitable".  Spec §6.2: a check that cannot
    confirm reachability leaves the match at its pre-verification tier.

    EPSS is absent from this function on purpose.  Spec §7.2: "EPSS raises
    but never lowers a tier derived from confirmed exploitation" - it only
    ever appears in :func:`base_tier`, and only to *reach* Medium.
    """
    gating = sorted(str(flag) for flag in inputs.flags if flag in _GATING_FLAGS)
    reasons: list[str] = []
    capped = tier

    if gating:
        # Any of these means "this might not be real", so the case needs a
        # human before it is treated as High or Critical.
        if capped.rank > Tier.MEDIUM.rank:
            reasons.append(f"capped at medium by: {', '.join(gating)}")
        capped = min(capped, Tier.MEDIUM, key=lambda value: value.rank)

    if inputs.waf_detected and capped is Tier.CRITICAL:
        # Reachable, but what answered was the proxy; the origin is not
        # directly exploitable (spec §6.1).
        reasons.append("capped at high: origin is fronted by a WAF or proxy")
        capped = Tier.HIGH

    auto_escalatable = not gating and not inputs.waf_detected

    return TierDecision(
        tier=capped,
        tier_before_gate=tier,
        auto_escalatable=auto_escalatable,
        factors={
            "exploited": inputs.exploited,
            "exploit_status": str(inputs.exploit_status),
            "on_kev": inputs.on_kev,
            "vendor_confirmed": inputs.vendor_confirmed,
            "public_exploit": inputs.public_exploit,
            "ransomware": inputs.ransomware,
            "epss": inputs.epss,
            "exposure_class": str(inputs.exposure_class),
            "criticality": str(inputs.criticality),
            "exposure_verified": inputs.exposure_verified,
            "waf_detected": inputs.waf_detected,
            "gating_flags": gating,
            "cap_reasons": reasons,
        },
    )


def score_match(inputs: ScoreInputs) -> TierDecision:
    """Compute the effective tier for one match."""
    return apply_gates(inputs, base_tier(inputs))
