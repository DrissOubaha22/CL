"""Product classification and match confidence - spec §3.3, §5.3."""

from __future__ import annotations

import pytest

from aegis.core.classification import classify_product, match_confidence
from aegis.core.enums import ExposureClass, MatchConfidence, ProductClass


class TestClassifyProduct:
    @pytest.mark.parametrize(
        ("part", "vendor", "product", "expected"),
        [
            # Spec §3.3 names these vendors as the high-precision scope.
            ("o", "fortinet", "fortios", ProductClass.APPLIANCE),
            ("a", "fortinet", "fortimail", ProductClass.APPLIANCE),
            ("a", "citrix", "netscaler_gateway", ProductClass.APPLIANCE),
            ("a", "ivanti", "connect_secure", ProductClass.APPLIANCE),
            ("h", "cisco", "asa_5500", ProductClass.APPLIANCE),
            # "web/app servers" and Exchange.
            ("a", "apache", "tomcat", ProductClass.SERVER_SOFTWARE),
            ("a", "microsoft", "exchange_server", ProductClass.SERVER_SOFTWARE),
            ("a", "f5", "nginx", ProductClass.APPLIANCE),
            # Client-side (spec §6.3).
            ("a", "mozilla", "firefox", ProductClass.CLIENT_SIDE),
            ("a", "adobe", "acrobat_reader", ProductClass.CLIENT_SIDE),
            # General-purpose OS and distro packages backport.
            ("o", "canonical", "ubuntu_linux", ProductClass.OS_PACKAGE),
            ("a", "redhat", "openssl", ProductClass.OS_PACKAGE),
            # Unknown stays unknown rather than being assumed safe to trust.
            ("a", "acme", "widget", ProductClass.OTHER),
        ],
    )
    def test_classification(
        self, part: str, vendor: str, product: str, expected: ProductClass
    ) -> None:
        assert classify_product(part=part, vendor=vendor, product=product) is expected

    def test_package_manager_origin_overrides_vendor(self) -> None:
        """A dpkg listing is a distro package whatever upstream is called."""
        assert (
            classify_product(
                part="a",
                vendor="openssl",
                product="openssl",
                from_distro_package=True,
            )
            is ProductClass.OS_PACKAGE
        )

    def test_classification_is_case_insensitive(self) -> None:
        assert (
            classify_product(part="o", vendor="Fortinet", product="FortiOS")
            is ProductClass.APPLIANCE
        )


class TestMatchConfidence:
    def test_internet_facing_appliance_is_the_only_high(self) -> None:
        """Spec §3.3/§5.3 appliance-first."""
        assert (
            match_confidence(
                product_class=ProductClass.APPLIANCE,
                exposure=ExposureClass.INTERNET,
                version_is_clean=True,
            )
            is MatchConfidence.HIGH
        )

    def test_internal_appliance_is_capped_at_medium(self) -> None:
        assert (
            match_confidence(
                product_class=ProductClass.APPLIANCE,
                exposure=ExposureClass.INTERNAL,
                version_is_clean=True,
            )
            is MatchConfidence.MEDIUM
        )

    @pytest.mark.parametrize("exposure", [ExposureClass.INTERNET, ExposureClass.INTERNAL])
    def test_distro_package_is_never_above_low(self, exposure: ExposureClass) -> None:
        """Backporting makes an upstream-version comparison unsound."""
        assert (
            match_confidence(
                product_class=ProductClass.OS_PACKAGE,
                exposure=exposure,
                version_is_clean=True,
            )
            is MatchConfidence.LOW
        )

    def test_unorderable_version_caps_everything(self) -> None:
        assert (
            match_confidence(
                product_class=ProductClass.APPLIANCE,
                exposure=ExposureClass.INTERNET,
                version_is_clean=False,
            )
            is MatchConfidence.LOW
        )

    def test_unknown_product_never_earns_high(self) -> None:
        assert (
            match_confidence(
                product_class=ProductClass.OTHER,
                exposure=ExposureClass.INTERNET,
                version_is_clean=True,
            )
            is MatchConfidence.LOW
        )
