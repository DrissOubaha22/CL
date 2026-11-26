"""Deriving the merged intel record from per-source contributions.

The merged :class:`~aegis.db.models.intel.IntelRecord` is a pure function of
the contributions held for a CVE.  Keeping it derived rather than
incrementally patched buys two things the spec needs:

* **Idempotence** - re-running a pipeline cannot drift the record (spec §4.1
  upserts, §10 step 10 refresh).
* **Retraction** - when CISA removes a CVE from KEV, dropping that
  contribution and re-deriving clears ``on_kev`` instead of leaving a fact
  that no source still asserts.

Field ownership is explicit: a source can only write the fields listed for it
in :data:`FIELD_OWNERS`.  Where two sources own the same field, the one
earlier in that field's list wins.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from aegis.core.enums import ExploitStatus, FeedSource

__all__ = [
    "FIELD_OWNERS",
    "DerivedIntel",
    "derive_exploit_status",
    "merge_contributions",
]

#: Which sources may write which merged field, in descending precedence.
#: A source not listed for a field has its value for that field ignored, so a
#: feed drifting outside its remit cannot silently overwrite better data.
FIELD_OWNERS: Mapping[str, tuple[FeedSource, ...]] = {
    # Exploitation
    "on_kev": (FeedSource.CISA_KEV,),
    "kev_date_added": (FeedSource.CISA_KEV,),
    "kev_due": (FeedSource.CISA_KEV,),
    "ransomware": (FeedSource.CISA_KEV,),
    "vendor_confirmed": (FeedSource.PSIRT,),
    "exploited_in_wild": (FeedSource.VULNCHECK_KEV, FeedSource.CISA_KEV),
    "exploit_maturity": (FeedSource.VULNCHECK_KEV,),
    "public_exploit": (
        FeedSource.EXPLOIT_DB,
        FeedSource.METASPLOIT,
        FeedSource.NUCLEI,
        FeedSource.VULNCHECK_KEV,
    ),
    # Likelihood
    "epss": (FeedSource.FIRST_EPSS,),
    "epss_percentile": (FeedSource.FIRST_EPSS,),
    # Severity & description
    "cvss": (FeedSource.NVD,),
    "cvss_vector": (FeedSource.NVD,),
    "cwe": (FeedSource.NVD,),
    "title": (FeedSource.PSIRT, FeedSource.CISA_KEV),
    "description": (FeedSource.NVD, FeedSource.CISA_KEV),
    "published_at": (FeedSource.NVD,),
    "last_modified_at": (FeedSource.NVD,),
    # Remediation: a vendor advisory outranks an NVD reference tag.
    "patch_available": (FeedSource.PSIRT, FeedSource.NVD, FeedSource.CISA_KEV),
    # Only a vendor advisory states this reliably; NVD's configuration
    # nodes are a weaker, structural hint the matcher reads separately.
    "config_dependent": (FeedSource.PSIRT,),
}

#: Boolean fields where any owning source asserting ``True`` wins, regardless
#: of precedence.  Exploitation evidence is additive: one source proving a
#: public exploit exists is not cancelled by another not knowing about it.
_ANY_TRUE_FIELDS = frozenset({"public_exploit", "exploited_in_wild"})


@dataclass(slots=True)
class DerivedIntel:
    """The merged view of a CVE, before it is written to the store."""

    cve_id: str
    exploit_status: ExploitStatus = ExploitStatus.NONE
    on_kev: bool = False
    vendor_confirmed: bool = False
    public_exploit: bool = False
    ransomware: bool = False
    kev_due: date | None = None
    kev_date_added: date | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    cvss: float | None = None
    cvss_vector: str | None = None
    cwe: list[str] = field(default_factory=list)
    patch_available: bool = False
    config_dependent: bool = False
    title: str | None = None
    description: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None

    #: Not persisted on the record; kept so callers can explain a derivation.
    exploited_in_wild: bool = False
    exploit_maturity: str | None = None


def derive_exploit_status(
    *,
    on_kev: bool,
    vendor_confirmed: bool,
    exploited_in_wild: bool = False,
    public_exploit: bool = False,
) -> ExploitStatus:
    """Collapse exploitation evidence into a single status (spec §7.1).

    ``active`` means a credible source states the vulnerability is being
    exploited: CISA KEV, VulnCheck, or a vendor PSIRT advisory.  Per spec §7.2
    a vendor-confirmed advisory is treated as KEV-equivalent, so it reaches
    ``active`` before CISA lists the CVE.

    ``poc`` means exploit code is public but no in-the-wild use is confirmed.
    """
    if on_kev or vendor_confirmed or exploited_in_wild:
        return ExploitStatus.ACTIVE
    if public_exploit:
        return ExploitStatus.POC
    return ExploitStatus.NONE


def _select(
    field_name: str,
    payloads: Mapping[FeedSource, Mapping[str, Any]],
) -> Any:
    """Pick the winning value for ``field_name`` across contributions."""
    owners = FIELD_OWNERS.get(field_name, ())

    if field_name in _ANY_TRUE_FIELDS:
        return any(
            bool(payloads[owner].get(field_name))
            for owner in owners
            if owner in payloads and payloads[owner].get(field_name) is not None
        )

    for owner in owners:
        payload = payloads.get(owner)
        if payload is None:
            continue
        value = payload.get(field_name)
        if value is not None:
            return value
    return None


def merge_contributions(
    cve_id: str,
    contributions: Iterable[tuple[FeedSource, Mapping[str, Any]]],
) -> DerivedIntel:
    """Merge per-source payloads into the record for ``cve_id``.

    Args:
        cve_id: The CVE the contributions describe.
        contributions: ``(source, payload)`` pairs, where payload holds only
            the scalar fields that source asserts.

    Returns:
        The merged record, with ``exploit_status`` derived last from the
        merged exploitation signals.
    """
    payloads: dict[FeedSource, Mapping[str, Any]] = dict(contributions)

    on_kev = bool(_select("on_kev", payloads))
    vendor_confirmed = bool(_select("vendor_confirmed", payloads))
    exploited_in_wild = bool(_select("exploited_in_wild", payloads))
    public_exploit = bool(_select("public_exploit", payloads))

    return DerivedIntel(
        cve_id=cve_id,
        exploit_status=derive_exploit_status(
            on_kev=on_kev,
            vendor_confirmed=vendor_confirmed,
            exploited_in_wild=exploited_in_wild,
            public_exploit=public_exploit,
        ),
        on_kev=on_kev,
        vendor_confirmed=vendor_confirmed,
        public_exploit=public_exploit,
        exploited_in_wild=exploited_in_wild,
        exploit_maturity=_select("exploit_maturity", payloads),
        ransomware=bool(_select("ransomware", payloads)),
        kev_due=_coerce_date(_select("kev_due", payloads)),
        kev_date_added=_coerce_date(_select("kev_date_added", payloads)),
        epss=_select("epss", payloads),
        epss_percentile=_select("epss_percentile", payloads),
        cvss=_select("cvss", payloads),
        cvss_vector=_select("cvss_vector", payloads),
        cwe=list(_select("cwe", payloads) or []),
        patch_available=bool(_select("patch_available", payloads)),
        config_dependent=bool(_select("config_dependent", payloads)),
        title=_select("title", payloads),
        description=_select("description", payloads),
        published_at=_coerce_datetime(_select("published_at", payloads)),
        last_modified_at=_coerce_datetime(_select("last_modified_at", payloads)),
    )


def _coerce_date(value: Any) -> date | None:
    """Accept the ISO strings that come back out of the JSON payload column."""
    if value is None or (isinstance(value, date) and not isinstance(value, datetime)):
        return value
    if isinstance(value, datetime):
        return value.date()
    return date.fromisoformat(str(value))


def _coerce_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))
