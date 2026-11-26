"""Validated contract between a feed pipeline and the shared intel store.

Every pipeline normalises its source into a :class:`FeedContribution`.  A
pipeline fills only the fields its source *owns* (see
:data:`aegis.intel.derive.FIELD_OWNERS`); everything else stays ``None`` and
is supplied by another source.  Validation happens here, so malformed feed
rows are rejected before they can reach the store (spec §4.1).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime
from typing import Annotated, Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from aegis.core.cpe import InvalidCpe, parse_cpe
from aegis.core.enums import FeedSource

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

CveId = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=24)]


def normalise_cve_id(value: str) -> str:
    """Upper-case and validate a CVE identifier.

    Raises:
        ValueError: if the identifier is not a syntactically valid CVE id.
            CVE ids are never invented downstream (spec §4.2), so a bad id is
            a rejected row, not a corrected one.
    """
    candidate = (value or "").strip().upper()
    if not CVE_PATTERN.match(candidate):
        raise ValueError(f"malformed CVE id: {value!r}")
    return candidate


class SourceRef(BaseModel):
    """A citation backing one or more fields (spec §9 ``intel_source``)."""

    model_config = ConfigDict(frozen=True)

    url: str = Field(min_length=1)
    quote: str | None = None
    field: str | None = None


class CpeRange(BaseModel):
    """An affected product and version range (spec §5.2)."""

    model_config = ConfigDict(frozen=True)

    cpe: str
    vulnerable: bool = True
    version_exact: str | None = None
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    @field_validator("cpe")
    @classmethod
    def _validate_cpe(cls, value: str) -> str:
        try:
            return parse_cpe(value).to_string()
        except InvalidCpe as exc:
            raise ValueError(str(exc)) from exc

    @model_validator(mode="after")
    def _reject_contradictory_bounds(self) -> CpeRange:
        if self.version_exact and any(
            (
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        ):
            raise ValueError("version_exact cannot be combined with range bounds")
        if self.version_start_including and self.version_start_excluding:
            raise ValueError("two lower bounds on the same range")
        if self.version_end_including and self.version_end_excluding:
            raise ValueError("two upper bounds on the same range")
        return self

    @property
    def is_unbounded(self) -> bool:
        """True when the range names a product with no version constraint."""
        return not any(
            (
                self.version_exact,
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            )
        )


class FeedContribution(BaseModel):
    """What one source asserts about one CVE at one point in time."""

    model_config = ConfigDict(extra="forbid")

    cve_id: CveId
    source: FeedSource
    retrieved_at: datetime

    # --- Exploitation (CISA KEV, VulnCheck, PSIRT) -------------------------
    on_kev: bool | None = None
    kev_date_added: date | None = None
    kev_due: date | None = None
    ransomware: bool | None = None
    vendor_confirmed: bool | None = None
    public_exploit: bool | None = None
    #: VulnCheck "exploited in the wild" assertion, independent of CISA KEV.
    exploited_in_wild: bool | None = None
    exploit_maturity: str | None = None

    # --- Likelihood (FIRST EPSS) -------------------------------------------
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)

    # --- Severity & description (NVD) --------------------------------------
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: str | None = None
    cwe: list[str] | None = None
    title: str | None = None
    description: str | None = None
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    patch_available: bool | None = None

    # --- Affected products --------------------------------------------------
    affected_cpes: list[CpeRange] = Field(default_factory=list)

    # --- Provenance ----------------------------------------------------------
    sources: list[SourceRef] = Field(default_factory=list)

    @field_validator("cve_id", mode="before")
    @classmethod
    def _normalise_cve(cls, value: Any) -> str:
        return normalise_cve_id(str(value))

    @field_validator("cwe")
    @classmethod
    def _clean_cwe(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        seen: list[str] = []
        for item in value:
            cleaned = item.strip().upper()
            # NVD emits placeholders for unmapped / insufficient-info entries.
            if not cleaned.startswith("CWE-"):
                continue
            if cleaned not in seen:
                seen.append(cleaned)
        return seen

    @model_validator(mode="after")
    def _require_provenance(self) -> FeedContribution:
        """Every contribution must cite where it came from (spec §4.2)."""
        if not self.sources:
            raise ValueError(f"contribution from {self.source} for {self.cve_id} has no source URL")
        return self

    def owned_payload(self) -> dict[str, Any]:
        """The scalar fields this contribution actually asserts.

        ``affected_cpes`` and ``sources`` are stored in their own tables and
        are excluded, as are fields left ``None`` (meaning "no opinion").
        """
        payload = self.model_dump(
            mode="json",
            exclude_none=True,
            exclude={"cve_id", "source", "retrieved_at", "affected_cpes", "sources"},
        )
        return payload

    def digest(self) -> str:
        """Stable content hash of the asserted facts.

        ``retrieved_at`` is excluded so that re-polling an unchanged feed is a
        no-op (the poll+diff of spec §4.1).
        """
        material = {
            "payload": self.owned_payload(),
            "affected_cpes": [
                cpe.model_dump(mode="json")
                for cpe in sorted(self.affected_cpes, key=lambda item: item.model_dump_json())
            ],
            "sources": sorted(
                (ref.model_dump(mode="json") for ref in self.sources),
                key=lambda item: json.dumps(item, sort_keys=True),
            ),
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
