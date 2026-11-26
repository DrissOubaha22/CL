"""Product classification and match confidence (spec §3.3, §5.3).

Spec §3.3 states the operating reality plainly: matching precision is best
for internet-facing appliances and services with clean version banners, and
worst for endpoint/OS package versions, because distributions backport fixes
without changing the version string.

This module turns that into two decisions the inventory and the matcher need:

* :func:`classify_product` - which class of software an asset is.
* :func:`match_confidence` - how much a match against it can be trusted.

Classification is deliberately conservative: an unrecognised product is
``OTHER`` and never earns high confidence on vendor identity alone.
"""

from __future__ import annotations

from aegis.core.enums import ExposureClass, MatchConfidence, ProductClass

__all__ = [
    "APPLIANCE_VENDORS",
    "classify_product",
    "match_confidence",
]

#: Vendors whose products in scope are network/security appliances with
#: reliable version banners.  Spec §3.3 names Fortinet, Cisco, Citrix, Ivanti
#: and Barracuda; the rest are the same category of device.
APPLIANCE_VENDORS = frozenset(
    {
        "arista",
        "barracuda",
        "checkpoint",
        "check_point",
        "cisco",
        "citrix",
        "f5",
        "fortinet",
        "ivanti",
        "juniper",
        "netgear",
        "palo_alto_networks",
        "paloaltonetworks",
        "pulsesecure",
        "sonicwall",
        "sophos",
        "vmware",
        "watchguard",
        "zyxel",
    }
)

#: Products that are server-side software rather than appliances, but still
#: expose a clean version over the network.  Spec §3.3: "Exchange, web/app
#: servers".
SERVER_PRODUCTS = frozenset(
    {
        "activemq",
        "apache",
        "confluence",
        "exchange_server",
        "gitlab",
        "http_server",
        "iis",
        "internet_information_services",
        "jboss",
        "jenkins",
        "jira",
        "nginx",
        "openssh",
        "postfix",
        "sharepoint",
        "tomcat",
        "weblogic_server",
        "websphere_application_server",
    }
)

#: Products whose risk basis is weaponised content reaching a user, not
#: perimeter reachability (spec §6.3).
CLIENT_SIDE_PRODUCTS = frozenset(
    {
        "acrobat",
        "acrobat_reader",
        "chrome",
        "edge",
        "firefox",
        "office",
        "outlook",
        "safari",
        "thunderbird",
        "word",
        "excel",
        "powerpoint",
    }
)

#: Vendors whose ``:a:`` packages are distribution-packaged and therefore
#: subject to backporting (spec §5.3).
DISTRO_VENDORS = frozenset(
    {
        "almalinux",
        "canonical",
        "debian",
        "fedoraproject",
        "opensuse",
        "oracle",
        "redhat",
        "rocky",
        "suse",
        "ubuntu",
    }
)


def classify_product(
    *,
    part: str,
    vendor: str,
    product: str,
    from_distro_package: bool = False,
) -> ProductClass:
    """Classify an inventory entry from its CPE identity.

    Args:
        part: CPE part - ``a`` application, ``o`` operating system,
            ``h`` hardware.
        vendor: CPE vendor component, lower-cased.
        product: CPE product component, lower-cased.
        from_distro_package: True when the entry came from a distribution
            package manager, which is authoritative regardless of vendor.

    Returns:
        The product class driving confidence and false-positive flags.
    """
    vendor = vendor.strip().lower()
    product = product.strip().lower()

    # The ingestion source knows best: a dpkg/rpm listing is a distro package
    # whatever the upstream vendor happens to be called.
    if from_distro_package:
        return ProductClass.OS_PACKAGE

    if product in CLIENT_SIDE_PRODUCTS:
        return ProductClass.CLIENT_SIDE

    # Appliance firmware and the appliance's own applications both count: a
    # FortiOS (o) and a FortiMail (a) are the same kind of match target.
    if vendor in APPLIANCE_VENDORS and part in ("o", "h", "a"):
        return ProductClass.APPLIANCE

    if product in SERVER_PRODUCTS:
        return ProductClass.SERVER_SOFTWARE

    # A general-purpose OS is not an appliance: its packages backport.
    if part == "o":
        return ProductClass.OS_PACKAGE

    if vendor in DISTRO_VENDORS:
        return ProductClass.OS_PACKAGE

    return ProductClass.OTHER


def match_confidence(
    *,
    product_class: ProductClass,
    exposure: ExposureClass,
    version_is_clean: bool,
) -> MatchConfidence:
    """How far a match on this asset can be trusted (spec §3.3, §5.3).

    Spec §5.3 "appliance-first": high confidence is reserved for
    internet-facing appliances and services with reliable version banners.
    Everything else is capped below it, which is what stops a backported
    distro package from being auto-escalated.

    Args:
        product_class: What kind of software the asset is.
        exposure: How the asset can be reached.
        version_is_clean: Whether the discovered version string could be
            ordered (spec §5.2).  An unorderable version never earns more
            than low confidence.

    Returns:
        The confidence stored on every match produced for this asset.
    """
    if not version_is_clean:
        return MatchConfidence.LOW

    # Backporting makes an upstream-version comparison unsound, whatever the
    # exposure; §5.3 requires these to be flagged needs-verification.
    if product_class is ProductClass.OS_PACKAGE:
        return MatchConfidence.LOW

    if product_class in (ProductClass.APPLIANCE, ProductClass.SERVER_SOFTWARE):
        if exposure is ExposureClass.INTERNET:
            return MatchConfidence.HIGH
        return MatchConfidence.MEDIUM

    if product_class is ProductClass.CLIENT_SIDE:
        # Version banners for desktop software are reliable; what is uncertain
        # is reachability, which is not a confidence question (spec §6.3).
        return MatchConfidence.MEDIUM

    return MatchConfidence.LOW
