"""Risk tiering - spec §7.2.

The specification states the rule as pseudocode, so these tests walk its
branches in order and then check the interactions its prose describes.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegis.core.enums import (
    Criticality,
    ExploitStatus,
    ExposureClass,
    MatchFlag,
    Tier,
)
from aegis.scoring.tiering import ScoreInputs, apply_gates, base_tier, score_match

INTERNET = ExposureClass.INTERNET
INTERNAL = ExposureClass.INTERNAL
CLIENT_SIDE = ExposureClass.CLIENT_SIDE
ACTIVE = ExploitStatus.ACTIVE


def inputs(**overrides: Any) -> ScoreInputs:
    return ScoreInputs(**overrides)


def kev(**overrides: Any) -> ScoreInputs:
    """A KEV-listed, actively exploited CVE."""
    return inputs(exploit_status=ACTIVE, on_kev=True, **overrides)


class TestBaseTier:
    """Each branch of the §7.2 pseudocode, in its order."""

    def test_exploited_internet_crown_jewel_is_critical(self) -> None:
        assert (
            base_tier(kev(exposure_class=INTERNET, criticality=Criticality.HIGH)) is Tier.CRITICAL
        )

    def test_exploited_internet_ransomware_is_critical(self) -> None:
        assert base_tier(kev(exposure_class=INTERNET, ransomware=True)) is Tier.CRITICAL

    def test_exploited_internet_alone_is_high(self) -> None:
        assert base_tier(kev(exposure_class=INTERNET)) is Tier.HIGH

    def test_exploited_crown_jewel_but_internal_is_high(self) -> None:
        assert base_tier(kev(exposure_class=INTERNAL, criticality=Criticality.HIGH)) is Tier.HIGH

    def test_exploited_ransomware_but_internal_is_high(self) -> None:
        assert base_tier(kev(exposure_class=INTERNAL, ransomware=True)) is Tier.HIGH

    def test_exploited_client_side_is_high(self) -> None:
        """Weaponised content: user interaction, not perimeter (spec §6.3)."""
        assert base_tier(kev(exposure_class=CLIENT_SIDE)) is Tier.HIGH

    def test_exploited_internal_and_unremarkable_is_medium(self) -> None:
        assert base_tier(kev(exposure_class=INTERNAL)) is Tier.MEDIUM

    def test_public_exploit_alone_is_medium(self) -> None:
        assert base_tier(inputs(public_exploit=True, exposure_class=INTERNET)) is Tier.MEDIUM

    @pytest.mark.parametrize(
        ("epss", "expected"),
        [(0.95, Tier.MEDIUM), (0.5, Tier.MEDIUM), (0.49, Tier.LOW), (None, Tier.LOW)],
    )
    def test_epss_threshold(self, epss: float | None, expected: Tier) -> None:
        assert base_tier(inputs(epss=epss, exposure_class=INTERNET)) is expected

    def test_nothing_is_low(self) -> None:
        assert base_tier(inputs(exposure_class=INTERNET)) is Tier.LOW

    def test_client_side_without_exploitation_is_not_high(self) -> None:
        assert base_tier(inputs(exposure_class=CLIENT_SIDE, epss=0.9)) is Tier.MEDIUM


class TestExploitedDefinition:
    """Spec §7.2: ``exploited := on_kev or vendor_confirmed``."""

    def test_kev_counts(self) -> None:
        assert inputs(on_kev=True).exploited

    def test_vendor_confirmation_counts_before_cisa_lists_it(self) -> None:
        """Spec §7.2 prose: it forces High/Critical ahead of KEV."""
        assert inputs(vendor_confirmed=True).exploited
        assert (
            base_tier(
                inputs(
                    vendor_confirmed=True,
                    exposure_class=INTERNET,
                    criticality=Criticality.HIGH,
                )
            )
            is Tier.CRITICAL
        )

    def test_active_exploit_status_counts(self) -> None:
        """A third-party in-the-wild report (spec §7.1 names VulnCheck)."""
        assert inputs(exploit_status=ACTIVE).exploited

    def test_public_exploit_alone_does_not_count_as_exploited(self) -> None:
        assert not inputs(public_exploit=True, exploit_status=ExploitStatus.POC).exploited


class TestEpssNeverLowers:
    """Spec §7.2: "EPSS raises but never lowers a tier derived from
    confirmed exploitation"."""

    @pytest.mark.parametrize("epss", [None, 0.0, 0.01, 0.49])
    def test_low_epss_does_not_reduce_a_critical(self, epss: float | None) -> None:
        tier = base_tier(
            kev(
                exposure_class=INTERNET,
                criticality=Criticality.HIGH,
                epss=epss,
            )
        )
        assert tier is Tier.CRITICAL

    def test_low_epss_does_not_reduce_a_high(self) -> None:
        assert base_tier(kev(exposure_class=INTERNET, epss=0.001)) is Tier.HIGH

    def test_high_epss_can_only_raise_to_medium(self) -> None:
        """It reaches Medium; it never reaches High on its own."""
        assert base_tier(inputs(epss=0.99, exposure_class=INTERNET)) is Tier.MEDIUM


class TestVerificationGate:
    """Spec §5.3: no match becomes a Critical/High case until §6 confirms."""

    def test_unverified_caps_at_medium(self) -> None:
        decision = score_match(
            kev(
                exposure_class=INTERNET,
                criticality=Criticality.HIGH,
                flags=(MatchFlag.UNVERIFIED,),
            )
        )
        assert decision.tier is Tier.MEDIUM
        assert decision.tier_before_gate is Tier.CRITICAL
        assert decision.was_capped
        assert not decision.auto_escalatable

    def test_the_uncapped_tier_is_preserved_for_explanation(self) -> None:
        decision = score_match(kev(exposure_class=INTERNET, flags=(MatchFlag.UNVERIFIED,)))
        assert decision.tier_before_gate is Tier.HIGH
        assert any("unverified" in reason for reason in decision.factors["cap_reasons"])

    @pytest.mark.parametrize(
        "flag",
        [
            MatchFlag.BACKPORT,
            MatchFlag.CONFIG_DEPENDENT,
            MatchFlag.UNPARSEABLE_VERSION,
            MatchFlag.UNVERIFIED,
        ],
    )
    def test_every_gating_flag_blocks_escalation(self, flag: MatchFlag) -> None:
        decision = score_match(
            kev(
                exposure_class=INTERNET,
                criticality=Criticality.HIGH,
                flags=(flag,),
            )
        )
        assert decision.tier is Tier.MEDIUM
        assert not decision.auto_escalatable

    def test_a_non_gating_flag_does_not_cap(self) -> None:
        """An unbounded advisory range is a precision caveat, not a doubt."""
        decision = score_match(
            kev(
                exposure_class=INTERNET,
                criticality=Criticality.HIGH,
                flags=(MatchFlag.UNBOUNDED_RANGE,),
            )
        )
        assert decision.tier is Tier.CRITICAL
        assert decision.auto_escalatable

    def test_gates_never_raise_a_tier(self) -> None:
        decision = score_match(inputs(exposure_class=INTERNET))
        assert decision.tier is Tier.LOW
        assert not decision.was_capped

    def test_a_gate_on_a_low_tier_changes_nothing(self) -> None:
        decision = apply_gates(inputs(flags=(MatchFlag.UNVERIFIED,)), Tier.LOW)
        assert decision.tier is Tier.LOW
        assert decision.factors["cap_reasons"] == []


class TestWafAwareness:
    """Spec §6.1: a fronted origin is not escalated as directly exploitable."""

    def test_waf_caps_critical_at_high(self) -> None:
        decision = score_match(
            kev(
                exposure_class=INTERNET,
                criticality=Criticality.HIGH,
                exposure_verified=True,
                waf_detected=True,
            )
        )
        assert decision.tier is Tier.HIGH
        assert decision.tier_before_gate is Tier.CRITICAL
        assert not decision.auto_escalatable

    def test_waf_does_not_reduce_a_high_further(self) -> None:
        decision = score_match(
            kev(exposure_class=INTERNET, exposure_verified=True, waf_detected=True)
        )
        assert decision.tier is Tier.HIGH


class TestFactors:
    def test_every_input_is_recorded(self) -> None:
        """A tier nobody can explain is a tier nobody acts on."""
        decision = score_match(
            kev(
                exposure_class=INTERNET,
                criticality=Criticality.HIGH,
                ransomware=True,
                epss=0.94,
                exposure_verified=True,
            )
        )
        for key in (
            "exploited",
            "on_kev",
            "vendor_confirmed",
            "public_exploit",
            "ransomware",
            "epss",
            "exposure_class",
            "criticality",
            "exposure_verified",
            "waf_detected",
            "gating_flags",
            "cap_reasons",
        ):
            assert key in decision.factors, f"{key} missing from factors"


class TestRemediationWindows:
    """Spec §7.2's SLA table."""

    @pytest.mark.parametrize(
        ("tier", "window"),
        [
            (Tier.CRITICAL, "out-of-band"),
            (Tier.HIGH, "~72h"),
            (Tier.MEDIUM, "expedited"),
            (Tier.LOW, "routine"),
        ],
    )
    def test_window_per_tier(self, tier: Tier, window: str) -> None:
        assert tier.remediation_window == window

    def test_tiers_order_by_severity(self) -> None:
        ranks = [tier.rank for tier in (Tier.LOW, Tier.MEDIUM, Tier.HIGH, Tier.CRITICAL)]
        assert ranks == sorted(ranks)
