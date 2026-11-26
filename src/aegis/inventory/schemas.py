"""The inventory import contract (spec §3.1, §3.2).

Every discovery input - external attack surface, a scanner export, a cloud
API, a CMDB or SBOM - is normalised by its adapter into
:class:`InventoryItem` before it reaches the store.  Adapters therefore own
only parsing; classification, CPE resolution and exposure handling happen
once, here and in :mod:`aegis.inventory.normalise`.

Spec §3.2 is explicit that ``exposure`` comes from discovery *evidence*, not
from a self-declared field.  That is enforced structurally: an item declares
what was observed (reachable from outside, seen only internally, a desktop
application), and the exposure class is derived from it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegis.core.enums import Criticality, ExposureClass

__all__ = [
    "DiscoveryEvidence",
    "InventoryBatch",
    "InventoryItem",
    "InventorySource",
]

Hostname = Annotated[str, Field(min_length=1, max_length=253)]


class InventorySource(StrEnum):
    """Which §3.1 input produced an item."""

    #: External attack surface management over the client's public footprint.
    ASM = "asm"
    #: Read-only export from the client's own scanner.
    SCANNER = "scanner"
    CLOUD = "cloud"
    CMDB = "cmdb"
    SBOM = "sbom"
    #: Operator-supplied list, and the format adapters normalise into.
    MANUAL = "manual"


class DiscoveryEvidence(StrEnum):
    """What discovery actually observed about reachability (spec §3.2).

    This is the only input to ``exposure_class``.  There is deliberately no
    way for an import to assert "this is internet-facing" directly.
    """

    #: A service answered on a public address during external discovery.
    ANSWERED_PUBLICLY = "answered_publicly"
    #: Seen only by an authenticated/internal source (scanner, cloud, CMDB).
    SEEN_INTERNALLY = "seen_internally"
    #: Desktop software: browsers, mail clients, office suites (spec §6.3).
    INSTALLED_ON_ENDPOINT = "installed_on_endpoint"
    #: Nothing conclusive was observed.
    UNKNOWN = "unknown"


#: Evidence to exposure.  Spec §6.3: client-side software is never scored as
#: internet-facing, whatever host it sits on.
_EXPOSURE_FROM_EVIDENCE: dict[DiscoveryEvidence, ExposureClass] = {
    DiscoveryEvidence.ANSWERED_PUBLICLY: ExposureClass.INTERNET,
    DiscoveryEvidence.SEEN_INTERNALLY: ExposureClass.INTERNAL,
    DiscoveryEvidence.INSTALLED_ON_ENDPOINT: ExposureClass.CLIENT_SIDE,
    DiscoveryEvidence.UNKNOWN: ExposureClass.UNKNOWN,
}


class InventoryItem(BaseModel):
    """One discovered product/version on one host."""

    model_config = ConfigDict(extra="forbid")

    hostname: Hostname
    product: str = Field(min_length=1, max_length=200)
    version: str | None = Field(default=None, max_length=64)

    address: str | None = Field(default=None, max_length=64)
    port: int | None = Field(default=None, ge=1, le=65535)

    source: InventorySource = InventorySource.MANUAL
    evidence: DiscoveryEvidence = DiscoveryEvidence.UNKNOWN
    #: Confirmed at onboarding, not discovered (spec §3.2).
    criticality: Criticality = Criticality.UNKNOWN

    #: Set by package-manager inventories; forces OS_PACKAGE classification
    #: and the backport flag (spec §5.3), whatever the upstream vendor is.
    from_distro_package: bool = False

    #: CPEs the source already resolved, if it knows them (scanners often do).
    #: Merged with the ones Aegis infers rather than replacing them.
    cpes: list[str] = Field(default_factory=list)

    #: Vendor hint, when the source separates vendor from product name.
    vendor: str | None = Field(default=None, max_length=128)

    observed_at: datetime | None = None
    #: Free-form provenance kept for audit: banner text, scanner plugin id.
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("hostname")
    @classmethod
    def _normalise_hostname(cls, value: str) -> str:
        return value.strip().lower().rstrip(".")

    @field_validator("product", "vendor")
    @classmethod
    def _strip(cls, value: str | None) -> str | None:
        return value.strip() if value else value

    @field_validator("version")
    @classmethod
    def _clean_version(cls, value: str | None) -> str | None:
        """Drop placeholders rather than storing them as versions."""
        if value is None:
            return None
        cleaned = value.strip()
        if cleaned.lower() in ("", "-", "n/a", "na", "unknown", "none", "*"):
            return None
        return cleaned

    @property
    def exposure_class(self) -> ExposureClass:
        """Derived from evidence; never self-declared (spec §3.2)."""
        return _EXPOSURE_FROM_EVIDENCE[self.evidence]


class InventoryBatch(BaseModel):
    """A whole import, as accepted by ``aegis inventory import``."""

    model_config = ConfigDict(extra="forbid")

    source: InventorySource = InventorySource.MANUAL
    observed_at: datetime | None = None
    items: list[InventoryItem] = Field(default_factory=list)

    @property
    def hostnames(self) -> set[str]:
        return {item.hostname for item in self.items}
