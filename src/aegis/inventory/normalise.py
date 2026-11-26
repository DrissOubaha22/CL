"""Resolving a discovered product to CPE strings (spec §3.2).

Spec §3.2: "Each discovered product/version is resolved to one or more CPE
strings."  One or more, because the same product is spelled differently by
different publishers - ``fortinet:fortios`` as an OS and an application,
``apache:http_server`` vs ``apache:httpd`` - and intel may name any of them.
Emitting every plausible spelling and joining on all of them is what stops a
naming mismatch from silently hiding a vulnerable asset.

Resolution happens in three passes, most to least reliable:

1. **Source-supplied CPEs.** Scanners often already know; those are trusted
   and kept verbatim.
2. **Curated aliases.** The products §3.3 puts in scope - appliances and
   common server software - mapped explicitly, including their known
   alternative spellings.
3. **Heuristic.** Slugify vendor and product into a CPE and mark the asset
   accordingly.  A heuristic CPE still matches, but the asset cannot reach
   high confidence on it alone.

A production deployment should additionally import the official NVD CPE
dictionary; :func:`known_product_keys` lets the resolver confirm a guess
against the vendor/product pairs that actually appear in collected advisories,
which is the same idea at the scale of data already on hand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.core.cpe import ANY, Cpe, InvalidCpe, parse_cpe
from aegis.db.models import AffectedCpe

log = structlog.get_logger(__name__)

__all__ = [
    "PRODUCT_ALIASES",
    "ResolvedProduct",
    "known_product_keys",
    "resolve_product",
    "slugify_component",
]

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
#: Noise words vendors put in product banners.
_DROP_TOKENS = frozenset({"inc", "corp", "corporation", "ltd", "llc", "gmbh", "the", "software"})


def slugify_component(value: str) -> str:
    """Normalise a free-text name into a CPE component.

    CPE components are lower-case with underscores for spaces: "Apache HTTP
    Server" becomes ``apache_http_server``.
    """
    lowered = (value or "").strip().lower()
    tokens = [token for token in _NON_ALNUM.split(lowered) if token]
    kept = [token for token in tokens if token not in _DROP_TOKENS] or tokens
    return "_".join(kept)


@dataclass(frozen=True, slots=True)
class ResolvedProduct:
    """The CPE spellings a discovered product resolves to."""

    cpes: tuple[Cpe, ...]
    #: True when every CPE came from the source or the curated table, so the
    #: identity is trustworthy; False when any of it was guessed.
    is_authoritative: bool

    @property
    def product_keys(self) -> tuple[tuple[str, str, str], ...]:
        return tuple((c.part, c.vendor, c.product) for c in self.cpes)


#: Curated product aliases for the scope §3.3 calls high-confidence.
#: Keys are slugified product names; values are ``(part, vendor, product)``
#: tuples, the first being the canonical spelling.
PRODUCT_ALIASES: dict[str, tuple[tuple[str, str, str], ...]] = {
    # --- Appliances and network security (spec §3.3) --------------------
    "fortios": (("o", "fortinet", "fortios"),),
    "fortigate": (("o", "fortinet", "fortios"), ("h", "fortinet", "fortigate")),
    "fortimail": (("a", "fortinet", "fortimail"),),
    "fortiproxy": (("a", "fortinet", "fortiproxy"),),
    "netscaler": (
        ("a", "citrix", "netscaler_application_delivery_controller"),
        ("a", "citrix", "netscaler_gateway"),
    ),
    "citrix_adc": (("a", "citrix", "netscaler_application_delivery_controller"),),
    "citrix_gateway": (("a", "citrix", "netscaler_gateway"),),
    "ivanti_connect_secure": (("a", "ivanti", "connect_secure"),),
    "pulse_connect_secure": (("a", "ivanti", "connect_secure"),),
    "big_ip": (("a", "f5", "big_ip"),),
    "pan_os": (("o", "palo_alto_networks", "pan-os"),),
    "asa": (("o", "cisco", "adaptive_security_appliance_software"),),
    "ios_xe": (("o", "cisco", "ios_xe"),),
    "esxi": (("o", "vmware", "esxi"),),
    "vcenter_server": (("a", "vmware", "vcenter_server"),),
    "barracuda_email_security_gateway": (("a", "barracuda", "email_security_gateway"),),
    # --- Server software (spec §3.3: "Exchange, web/app servers") -------
    "exchange": (("a", "microsoft", "exchange_server"),),
    "exchange_server": (("a", "microsoft", "exchange_server"),),
    "apache_http_server": (
        ("a", "apache", "http_server"),
        ("a", "apache", "httpd"),
    ),
    "apache": (("a", "apache", "http_server"),),
    "httpd": (("a", "apache", "http_server"),),
    "nginx": (("a", "f5", "nginx"), ("a", "nginx", "nginx")),
    "tomcat": (("a", "apache", "tomcat"),),
    "apache_tomcat": (("a", "apache", "tomcat"),),
    "openssh": (("a", "openbsd", "openssh"),),
    "openssl": (("a", "openssl", "openssl"),),
    "iis": (("a", "microsoft", "internet_information_services"),),
    "confluence": (("a", "atlassian", "confluence"),),
    "jira": (("a", "atlassian", "jira"),),
    "gitlab": (("a", "gitlab", "gitlab"),),
    "jenkins": (("a", "jenkins", "jenkins"),),
    "log4j": (("a", "apache", "log4j"),),
    # --- Client-side (spec §6.3) ----------------------------------------
    "firefox": (("a", "mozilla", "firefox"),),
    "chrome": (("a", "google", "chrome"),),
    "google_chrome": (("a", "google", "chrome"),),
    "edge": (("a", "microsoft", "edge"),),
    "outlook": (("a", "microsoft", "outlook"),),
    "acrobat_reader": (("a", "adobe", "acrobat_reader"),),
}


#: Vendor slugs that may legitimately prefix a product name in a banner, so
#: "Microsoft Exchange Server" can be recognised as "exchange_server".
_KNOWN_VENDOR_SLUGS: frozenset[str] = frozenset(
    vendor for entries in PRODUCT_ALIASES.values() for _, vendor, _ in entries
) | frozenset({"microsoft", "apache", "citrix", "fortinet", "ivanti", "cisco"})


def _lookup_alias(slug: str, vendor: str | None) -> tuple[tuple[str, str, str], ...] | None:
    """Find a curated alias for a slugified product name.

    Tries, in order: the slug itself; "vendor product" joined, for sources
    that split the two; and the slug with a leading vendor token removed,
    which is how banners usually spell it.
    """
    direct = PRODUCT_ALIASES.get(slug)
    if direct is not None:
        return direct

    if vendor:
        joined = PRODUCT_ALIASES.get(slugify_component(f"{vendor} {slug}"))
        if joined is not None:
            return joined

    head, _, tail = slug.partition("_")
    if tail and head in _KNOWN_VENDOR_SLUGS:
        return PRODUCT_ALIASES.get(tail)
    return None


def resolve_product(
    *,
    product: str,
    vendor: str | None = None,
    version: str | None = None,
    supplied_cpes: list[str] | None = None,
) -> ResolvedProduct:
    """Resolve a discovered product into one or more CPEs.

    Args:
        product: Product name as discovery reported it.
        vendor: Vendor, when the source separates it from the product.
        version: Version to place in the CPE, or ``None`` for a wildcard.
            Matching uses the advisory's range, not this value, but keeping
            it makes the stored CPE self-describing.
        supplied_cpes: CPEs the source already resolved; trusted verbatim.

    Returns:
        The resolved spellings and whether any guessing was involved.
    """
    version_component = version if version else ANY
    resolved: list[Cpe] = []
    authoritative = True

    for raw in supplied_cpes or []:
        try:
            resolved.append(parse_cpe(raw))
        except InvalidCpe as exc:
            log.warning("inventory.bad_supplied_cpe", cpe=str(raw)[:120], error=str(exc))

    slug = slugify_component(product)
    aliases = _lookup_alias(slug, vendor)

    if aliases is not None:
        for part, alias_vendor, alias_product in aliases:
            resolved.append(
                Cpe(
                    part=part,
                    vendor=alias_vendor,
                    product=alias_product,
                    version=version_component,
                )
            )
    elif not resolved:
        # Nothing authoritative: fall back to a slugified guess.
        authoritative = False
        resolved.append(
            Cpe(
                part="a",
                vendor=slugify_component(vendor) if vendor else ANY,
                product=slug or ANY,
                version=version_component,
            )
        )

    return ResolvedProduct(cpes=tuple(_dedupe(resolved)), is_authoritative=authoritative)


def known_product_keys(session: Session) -> set[tuple[str, str, str]]:
    """``(part, vendor, product)`` triples that appear in collected advisories.

    Lets a resolver check a heuristic guess against identities the intel
    store has actually seen, instead of against nothing.  Read-only on the
    shared intel schema (spec §11).
    """
    rows = session.execute(
        select(AffectedCpe.part, AffectedCpe.vendor, AffectedCpe.product).distinct()
    ).all()
    return {(part, vendor, product) for part, vendor, product in rows}


def _dedupe(cpes: list[Cpe]) -> list[Cpe]:
    seen: set[str] = set()
    unique: list[Cpe] = []
    for cpe in cpes:
        key = cpe.to_string()
        if key not in seen:
            seen.add(key)
            unique.append(cpe)
    return unique
