"""Per-tenant store: inventory and matches (spec §9).

Every table here is declared against the placeholder schema
:data:`~aegis.db.base.TENANT_SCHEMA_TOKEN` and resolved to a real
``tenant_<slug>`` schema per session.  Consequently none of them carries a
``tenant_id`` column: the schema *is* the tenant, so a query cannot
accidentally span two of them (spec §11, "hard tenant isolation").

Spec §9 lists ``tenant_id`` on each entity because it describes the logical
model; with schema-per-tenant the column would be a constant per schema and
the isolation would depend on every query remembering to filter by it.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.core.enums import (
    Criticality,
    ExposureClass,
    MatchConfidence,
    ProductClass,
    RunStatus,
)
from aegis.db.base import TenantBase
from aegis.db.types import StrEnumType

JSONType = JSON().with_variant(JSONB(), "postgresql")

CVE_ID_LEN = 24
_TS = DateTime(timezone=True)


class TenantTimestampMixin:
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Asset(TenantTimestampMixin, TenantBase):
    """One discovered product/version on one host (spec §3.2, §9).

    The grain is *(host, product, port)*, not *host* and not
    *(host, product, version)*: a server running nginx and OpenSSH is two
    assets because each matches independently, but upgrading nginx updates
    that asset rather than creating a second one.

    Spec §9 lists ``version`` as a column on the asset, which is what makes
    this the right grain: if the version were part of the identity, patching
    a host would leave the vulnerable row behind and its matches open
    forever.  The one-or-more CPE spellings a product resolves to live in
    :class:`AssetCpe`.
    """

    __tablename__ = "asset"

    asset_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    #: Address the service answers on, when discovery observed one.
    address: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer)

    product_name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64))
    #: False when the version string could not be ordered (spec §5.2); caps
    #: match confidence rather than being treated as "no match".
    version_is_clean: Mapped[bool] = mapped_column(default=False, nullable=False)

    product_class: Mapped[ProductClass] = mapped_column(
        StrEnumType(ProductClass, 20), default=ProductClass.OTHER, nullable=False
    )
    #: Set from discovery evidence, never from a self-declared field
    #: (spec §3.2).
    exposure_class: Mapped[ExposureClass] = mapped_column(
        StrEnumType(ExposureClass, 16), default=ExposureClass.UNKNOWN, nullable=False
    )
    #: When an active check last confirmed the exposure (spec §6).  Null means
    #: unverified, which the verification gate of §5.3 reads.
    exposure_verified_at: Mapped[datetime | None] = mapped_column(_TS)
    criticality: Mapped[Criticality] = mapped_column(
        StrEnumType(Criticality, 16), default=Criticality.UNKNOWN, nullable=False
    )
    match_confidence: Mapped[MatchConfidence] = mapped_column(
        StrEnumType(MatchConfidence, 8), default=MatchConfidence.LOW, nullable=False
    )

    #: Which inventory input produced this asset (spec §3.1).
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    #: True when the entry came from a distribution package manager, which
    #: makes it subject to backporting (spec §5.3).
    from_distro_package: Mapped[bool] = mapped_column(default=False, nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    #: Discovery stopped reporting it; kept for history, excluded from matching.
    retired_at: Mapped[datetime | None] = mapped_column(_TS)

    evidence: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    cpes: Mapped[list[AssetCpe]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="selectin"
    )
    matches: Mapped[list[Match]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("hostname", "product_name", "port", name="host_product_port"),
        Index("ix_asset_exposure_class", "exposure_class"),
        Index("ix_asset_hostname", "hostname"),
    )

    @property
    def is_active(self) -> bool:
        return self.retired_at is None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Asset {self.hostname} {self.product_name} {self.version}>"


class AssetCpe(TenantBase):
    """A CPE spelling this asset resolves to (spec §3.2).

    One product can map to several CPEs - vendor renames, a product listed
    under both an application and an OS part - and intel may name any of
    them, so all are kept and all are joined against.
    """

    __tablename__ = "asset_cpe"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("asset.asset_id", ondelete="CASCADE"), nullable=False
    )

    cpe: Mapped[str] = mapped_column(Text, nullable=False)
    #: Denormalised components the matcher joins on (spec §5.1).
    part: Mapped[str] = mapped_column(String(1), nullable=False)
    vendor: Mapped[str] = mapped_column(String(128), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    target_sw: Mapped[str | None] = mapped_column(String(128))

    asset: Mapped[Asset] = relationship(back_populates="cpes")

    __table_args__ = (
        UniqueConstraint("asset_id", "cpe", name="asset_cpe_unique"),
        CheckConstraint("part IN ('a', 'o', 'h')", name="cpe_part_vocab"),
        # Mirrors ix_affected_cpe_vendor_product: this is the join key.
        Index("ix_asset_cpe_vendor_product", "vendor", "product"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AssetCpe {self.vendor}:{self.product}>"


class Match(TenantTimestampMixin, TenantBase):
    """A candidate match between an asset and a CVE (spec §5.1, §9).

    "Candidate" is the operative word: §5.3 requires exposure verification
    before a match becomes a Critical/High case, so every match is born with
    the ``unverified`` flag.
    """

    __tablename__ = "match"

    match_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("asset.asset_id", ondelete="CASCADE"), nullable=False
    )
    #: References ``intel.intel_record`` across schemas; deliberately not a
    #: foreign key, because the intel store is read-only to tenant workers
    #: and must not be constrained by tenant rows (spec §11).
    cve_id: Mapped[str] = mapped_column(String(CVE_ID_LEN), nullable=False)

    confidence: Mapped[MatchConfidence] = mapped_column(
        StrEnumType(MatchConfidence, 8), default=MatchConfidence.LOW, nullable=False
    )
    #: Caveats from §5.3: backport, config, unverified, unparseable_version.
    flags: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)

    #: Which CPE spelling and which advisory range produced the match, so a
    #: disputed match can be explained without re-deriving it.
    matched_cpe: Mapped[str] = mapped_column(Text, nullable=False)
    matched_version: Mapped[str | None] = mapped_column(String(64))
    matched_range: Mapped[str | None] = mapped_column(String(128))

    first_matched_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), nullable=False
    )
    last_matched_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), nullable=False
    )
    #: The asset or the advisory changed and the match no longer holds.
    resolved_at: Mapped[datetime | None] = mapped_column(_TS)

    asset: Mapped[Asset] = relationship(back_populates="matches")

    __table_args__ = (
        UniqueConstraint("asset_id", "cve_id", "matched_cpe", name="asset_cve_cpe"),
        Index("ix_match_cve_id", "cve_id"),
        Index("ix_match_confidence", "confidence"),
    )

    @property
    def is_open(self) -> bool:
        return self.resolved_at is None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Match asset={self.asset_id} {self.cve_id} {self.confidence}>"


class MatchRun(TenantBase):
    """Append-only journal of a matching pass (spec §11)."""

    __tablename__ = "match_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    status: Mapped[RunStatus] = mapped_column(
        StrEnumType(RunStatus, 16), default=RunStatus.RUNNING, nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(_TS)

    assets_considered: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    candidates_tested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    matches_open: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    matches_new: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    matches_resolved: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    __table_args__ = (Index("ix_match_run_started_at", "started_at"),)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<MatchRun {self.status} new={self.matches_new}>"
