"""Version ordering - spec §5.2."""

from __future__ import annotations

import pytest

from aegis.core.versions import (
    UnparseableVersion,
    compare,
    parse_version,
    version_in_range,
)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        # Numeric ordering, including the multi-digit case string sorting gets wrong.
        ("7.4.2", "7.4.8", -1),
        ("7.4.10", "7.4.9", 1),
        ("1.2", "1.2.0", 0),
        ("12.2.1.4.0", "12.2.1.3.0", 1),
        ("2021.1", "2020.4", 1),
        # Leading marker.
        ("v1.2.3", "1.2.3", 0),
        # Pre-releases sort below the release.
        ("2.0.0-beta", "2.0.0", -1),
        ("1.0.0-rc.1", "1.0.0", -1),
        ("2.0.0-beta.2", "2.0.0-beta.10", -1),
        ("1.0.0-alpha", "1.0.0-beta", -1),
        # Vendor patch letters and build suffixes sort above it.
        ("7.4.2b", "7.4.2", 1),
        ("7.4.2c", "7.4.2b", 1),
        ("10.0.1_build1234", "10.0.1", 1),
        ("9.1.0 SP2", "9.1.0", 1),
        ("6.0.0-hotfix1", "6.0.0", 1),
    ],
)
def test_compare_orders_vendor_versions(left: str, right: str, expected: int) -> None:
    assert compare(left, right) == expected
    assert compare(right, left) == -expected


def test_equality_ignores_trailing_zeros() -> None:
    assert parse_version("1.2") == parse_version("1.2.0.0")
    assert hash(parse_version("1.2")) == hash(parse_version("1.2.0.0"))


@pytest.mark.parametrize("value", ["", "*", "-", "n/a", "unknown", "   "])
def test_wildcards_are_unparseable(value: str) -> None:
    """A placeholder is absence of information, not version zero."""
    with pytest.raises(UnparseableVersion):
        parse_version(value)


def test_alphabetic_only_version_is_unparseable() -> None:
    with pytest.raises(UnparseableVersion):
        parse_version("latest")


class TestVersionInRange:
    """NVD-style bounds; spec §5.2 requires ranges, not equality."""

    def test_half_open_range(self) -> None:
        in_range = {"start_including": "7.4.0", "end_excluding": "7.4.8"}
        assert version_in_range("7.4.0", **in_range)
        assert version_in_range("7.4.2", **in_range)
        assert not version_in_range("7.4.8", **in_range)
        assert not version_in_range("7.3.9", **in_range)

    def test_exclusive_lower_inclusive_upper(self) -> None:
        bounds = {"start_excluding": "1.0", "end_including": "2.0"}
        assert not version_in_range("1.0", **bounds)
        assert version_in_range("1.0.1", **bounds)
        assert version_in_range("2.0", **bounds)
        assert not version_in_range("2.0.1", **bounds)

    def test_exact_short_circuits(self) -> None:
        assert version_in_range("7.4.2", exact="7.4.2")
        assert not version_in_range("7.4.3", exact="7.4.2")

    def test_no_bounds_covers_every_version(self) -> None:
        """NVD does publish "all versions affected" advisories."""
        assert version_in_range("0.1")
        assert version_in_range("99.0")

    def test_unparseable_target_raises_rather_than_matching(self) -> None:
        """Spec §5.2: downgrade confidence, never assert a match."""
        with pytest.raises(UnparseableVersion):
            version_in_range("unknown", start_including="7.4.0")
