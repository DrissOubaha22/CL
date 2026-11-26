"""False-positive controls - spec §5.3."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from aegis.core.enums import MatchConfidence, MatchFlag, ProductClass
from aegis.matching.flags import evaluate_match

VERIFIED = datetime(2026, 11, 26, tzinfo=UTC)

CLEAN: dict[str, Any] = {
    "asset_confidence": MatchConfidence.HIGH,
    "product_class": ProductClass.APPLIANCE,
    "from_distro_package": False,
    "version_is_clean": True,
    "exposure_verified_at": VERIFIED,
    "intel_config_dependent": False,
    "advisory_has_context_nodes": False,
    "range_is_unbounded": False,
}


def verdict(**overrides: Any):
    return evaluate_match(**{**CLEAN, **overrides})


class TestVerificationGate:
    def test_unverified_exposure_flags_the_match(self) -> None:
        """Spec §5.3: no match escalates until §6 confirms exposure."""
        result = verdict(exposure_verified_at=None)
        assert MatchFlag.UNVERIFIED in result.flags
        assert not result.auto_escalatable

    def test_verified_clean_match_may_escalate(self) -> None:
        result = verdict()
        assert result.flags == ()
        assert result.auto_escalatable
        assert result.confidence is MatchConfidence.HIGH

    def test_the_gate_does_not_lower_confidence(self) -> None:
        """Unverified means "not yet proven", not "probably wrong"."""
        assert verdict(exposure_verified_at=None).confidence is MatchConfidence.HIGH


class TestBackportAwareness:
    def test_distro_package_is_flagged_and_dropped_to_low(self) -> None:
        result = verdict(from_distro_package=True, product_class=ProductClass.OS_PACKAGE)
        assert MatchFlag.BACKPORT in result.flags
        assert result.confidence is MatchConfidence.LOW
        assert not result.auto_escalatable

    def test_os_package_class_alone_triggers_it(self) -> None:
        """Even when the source did not say it came from a package manager."""
        result = verdict(product_class=ProductClass.OS_PACKAGE)
        assert MatchFlag.BACKPORT in result.flags


class TestConfigDependence:
    def test_advisory_flag_caps_confidence(self) -> None:
        result = verdict(intel_config_dependent=True)
        assert MatchFlag.CONFIG_DEPENDENT in result.flags
        assert result.confidence is MatchConfidence.MEDIUM
        assert not result.auto_escalatable

    def test_platform_context_nodes_are_a_structural_signal(self) -> None:
        """An advisory naming non-vulnerable products describes a combination."""
        result = verdict(advisory_has_context_nodes=True)
        assert MatchFlag.CONFIG_DEPENDENT in result.flags


class TestVersionCaveats:
    def test_unorderable_version_is_flagged_not_dropped(self) -> None:
        """Spec §5.2: downgrade confidence, do not silently assert or discard."""
        result = verdict(version_is_clean=False)
        assert MatchFlag.UNPARSEABLE_VERSION in result.flags
        assert result.confidence is MatchConfidence.LOW

    def test_unbounded_range_caps_at_medium(self) -> None:
        result = verdict(range_is_unbounded=True)
        assert MatchFlag.UNBOUNDED_RANGE in result.flags
        assert result.confidence is MatchConfidence.MEDIUM

    def test_an_unbounded_range_alone_does_not_block_escalation(self) -> None:
        """It is a precision caveat, not a reason to doubt the match."""
        assert verdict(range_is_unbounded=True).auto_escalatable


def test_caveats_accumulate() -> None:
    result = verdict(
        exposure_verified_at=None,
        product_class=ProductClass.OS_PACKAGE,
        intel_config_dependent=True,
    )
    assert set(result.flags) == {
        MatchFlag.UNVERIFIED,
        MatchFlag.BACKPORT,
        MatchFlag.CONFIG_DEPENDENT,
    }
    assert result.confidence is MatchConfidence.LOW


@pytest.mark.parametrize(
    "blocking",
    [
        {"exposure_verified_at": None},
        {"product_class": ProductClass.OS_PACKAGE},
        {"intel_config_dependent": True},
        {"version_is_clean": False},
    ],
)
def test_every_substantive_caveat_blocks_auto_escalation(
    blocking: dict[str, Any],
) -> None:
    assert not verdict(**blocking).auto_escalatable
