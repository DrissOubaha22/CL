"""Shared (per-CVE) intel store - spec §9.

One row per CVE in :class:`IntelRecord`, collected once and shared across all
tenants.  Nothing here is tenant-scoped.

Beyond the entities the spec names, two tables exist for operational reasons:

``intel_contribution``
    The raw, per-source view of a CVE as that feed last reported it.  The
    merged :class:`IntelRecord` is *derived* from these rows, so a re-run is
    idempotent and a retracted claim (e.g. a CVE removed from KEV) can be
    undone instead of being baked in permanently.

``feed_run``
    Append-only journal of pipeline executions, for the audit requirement of
    spec §11 and for incremental watermarks.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.core.enums import ExploitStatus, FeedSource, RunStatus
from aegis.db.base import Base
from aegis.db.types import StrEnumType

#: ``JSONB`` on PostgreSQL, plain ``JSON`` elsewhere (keeps unit tests able to
#: run against SQLite without a server).
JSONType = JSON().with_variant(JSONB(), "postgresql")

CVE_ID_LEN = 24
_TS = DateTime(timezone=True)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )


class IntelRecord(TimestampMixin, Base):
    """The merged intelligence view of a single CVE (spec §9)."""

    __tablename__ = "intel_record"

    cve_id: Mapped[str] = mapped_column(String(CVE_ID_LEN), primary_key=True)

    # Exploitation --------------------------------------------------------
    exploit_status: Mapped[ExploitStatus] = mapped_column(
        StrEnumType(ExploitStatus, 16),
        default=ExploitStatus.NONE,
        nullable=False,
    )
    on_kev: Mapped[bool] = mapped_column(default=False, nullable=False)
    vendor_confirmed: Mapped[bool] = mapped_column(default=False, nullable=False)
    public_exploit: Mapped[bool] = mapped_column(default=False, nullable=False)
    ransomware: Mapped[bool] = mapped_column(default=False, nullable=False)
    kev_due: Mapped[date | None] = mapped_column(Date)
    kev_date_added: Mapped[date | None] = mapped_column(Date)

    # Severity / likelihood ------------------------------------------------
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cwe: Mapped[list[str]] = mapped_column(JSONType, default=list, nullable=False)

    # Remediation ----------------------------------------------------------
    patch_available: Mapped[bool] = mapped_column(default=False, nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(_TS)
    last_modified_at: Mapped[datetime | None] = mapped_column(_TS)

    #: When the merged view was last recomputed from its contributions.
    as_of: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)

    affected_cpes: Mapped[list[AffectedCpe]] = relationship(
        back_populates="record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    sources: Mapped[list[IntelSource]] = relationship(
        back_populates="record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    contributions: Mapped[list[IntelContribution]] = relationship(
        back_populates="record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint(
            "exploit_status IN ('none', 'poc', 'active')",
            name="exploit_status_vocab",
        ),
        CheckConstraint("epss IS NULL OR (epss >= 0 AND epss <= 1)", name="epss_range"),
        CheckConstraint("cvss IS NULL OR (cvss >= 0 AND cvss <= 10)", name="cvss_range"),
        # The matching engine (phase 2) sweeps on exploitation first.
        Index("ix_intel_record_exploit_status", "exploit_status"),
        # Partial: the matcher sweeps KEV-listed CVEs, never the complement.
        Index(
            "ix_intel_record_on_kev",
            "on_kev",
            postgresql_where=text("on_kev"),
        ),
        Index("ix_intel_record_epss", "epss"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<IntelRecord {self.cve_id} {self.exploit_status}>"


class IntelContribution(TimestampMixin, Base):
    """What one source last said about one CVE.

    ``payload`` holds only the fields that source owns, already validated and
    normalised by its pipeline.  :class:`IntelRecord` is a pure function of
    the contributions for a CVE.
    """

    __tablename__ = "intel_contribution"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("intel_record.cve_id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[FeedSource] = mapped_column(StrEnumType(FeedSource, 32), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    #: Content hash of ``payload``; lets a poll+diff run skip unchanged rows.
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    retrieved_at: Mapped[datetime] = mapped_column(_TS, nullable=False)

    record: Mapped[IntelRecord] = relationship(back_populates="contributions")

    __table_args__ = (
        UniqueConstraint("cve_id", "source", name="cve_id_source"),
        Index("ix_intel_contribution_source", "source"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<IntelContribution {self.cve_id} {self.source}>"


class IntelSource(TimestampMixin, Base):
    """Provenance for a claim (spec §9: source_id, cve_id, url, quote).

    Every material claim must be traceable to a source; unsourced claims are
    discarded upstream (spec §4.2).
    """

    __tablename__ = "intel_source"

    source_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("intel_record.cve_id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[FeedSource] = mapped_column(StrEnumType(FeedSource, 32), nullable=False)
    #: Which field of the merged record this reference backs, if specific.
    field: Mapped[str | None] = mapped_column(String(64))
    url: Mapped[str] = mapped_column(Text, nullable=False)
    quote: Mapped[str | None] = mapped_column(Text)
    retrieved_at: Mapped[datetime] = mapped_column(_TS, nullable=False)

    record: Mapped[IntelRecord] = relationship(back_populates="sources")

    __table_args__ = (
        UniqueConstraint("cve_id", "source", "field", "url", name="cve_source_field_url"),
        Index("ix_intel_source_cve_id", "cve_id"),
    )


class AffectedCpe(TimestampMixin, Base):
    """One affected product/version range for a CVE (spec §5.2).

    Version bounds follow NVD ``cpeMatch`` semantics; matching uses the range,
    never equality.  ``version`` on the CPE itself is kept separately for the
    exact-version form (``cpe:2.3:o:fortinet:fortios:7.4.2:*:...``).
    """

    __tablename__ = "affected_cpe"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(
        ForeignKey("intel_record.cve_id", ondelete="CASCADE"), nullable=False
    )
    source: Mapped[FeedSource] = mapped_column(StrEnumType(FeedSource, 32), nullable=False)

    #: Full CPE 2.3 URI as published.
    cpe: Mapped[str] = mapped_column(Text, nullable=False)
    #: Denormalised CPE components the matcher joins on (spec §5.1).
    part: Mapped[str] = mapped_column(String(1), nullable=False)
    vendor: Mapped[str] = mapped_column(String(128), nullable=False)
    product: Mapped[str] = mapped_column(String(128), nullable=False)
    target_sw: Mapped[str | None] = mapped_column(String(128))

    version_exact: Mapped[str | None] = mapped_column(String(64))
    version_start_including: Mapped[str | None] = mapped_column(String(64))
    version_start_excluding: Mapped[str | None] = mapped_column(String(64))
    version_end_including: Mapped[str | None] = mapped_column(String(64))
    version_end_excluding: Mapped[str | None] = mapped_column(String(64))

    #: NVD ``vulnerable`` flag - a non-vulnerable node is platform context.
    vulnerable: Mapped[bool] = mapped_column(default=True, nullable=False)

    record: Mapped[IntelRecord] = relationship(back_populates="affected_cpes")

    __table_args__ = (
        UniqueConstraint(
            "cve_id",
            "cpe",
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
            name="cve_cpe_range",
        ),
        CheckConstraint("part IN ('a', 'o', 'h')", name="cpe_part_vocab"),
        # The matching join is vendor+product first, then version compare.
        Index("ix_affected_cpe_vendor_product", "vendor", "product"),
        Index("ix_affected_cpe_cve_id", "cve_id"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AffectedCpe {self.cve_id} {self.vendor}:{self.product}>"


class FeedRun(Base):
    """Append-only journal of a scheduled pipeline execution (spec §11)."""

    __tablename__ = "feed_run"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[FeedSource] = mapped_column(StrEnumType(FeedSource, 32), nullable=False)
    status: Mapped[RunStatus] = mapped_column(
        StrEnumType(RunStatus, 16), default=RunStatus.RUNNING, nullable=False
    )
    started_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(_TS)

    records_seen: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_changed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_rejected: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    #: Incremental cursor this run consumed/produced (e.g. NVD lastModStartDate).
    watermark: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    __table_args__ = (Index("ix_feed_run_source_started_at", "source", "started_at"),)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<FeedRun {self.source} {self.status}>"
