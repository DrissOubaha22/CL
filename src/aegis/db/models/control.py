"""Tenant registry - the global control plane (spec §9, §11).

Spec §9 lists ``tenant`` among the per-tenant entities.  It lives in a
separate ``control`` schema here for a practical reason: every scheduled job
has to *enumerate* tenants before it can scope itself to one, and a registry
stored inside each tenant's own schema cannot be enumerated without first
knowing the tenants.  No tenant payload data lives here - only identity,
routing and policy.
"""

from __future__ import annotations

import re
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
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aegis.config import get_settings
from aegis.core.enums import AutomationPolicy, DeliveryChannel, Tier
from aegis.db.base import ControlBase
from aegis.db.types import StrEnumType

_TS = DateTime(timezone=True)
JSONType = JSON().with_variant(JSONB(), "postgresql")

#: A slug must be a safe, unambiguous SQL identifier fragment: it is
#: concatenated into a schema name, so nothing that needs quoting is allowed.
SLUG_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,38}$")


class InvalidTenantSlug(ValueError):
    """The slug cannot be used to build a schema name."""


def validate_slug(slug: str) -> str:
    """Normalise and check a tenant slug.

    Raises:
        InvalidTenantSlug: if the slug is not a lower-case identifier of 2-39
            characters starting with a letter.
    """
    candidate = (slug or "").strip().lower()
    if not SLUG_PATTERN.match(candidate):
        raise InvalidTenantSlug(f"tenant slug must match {SLUG_PATTERN.pattern}, got {slug!r}")
    return candidate


def schema_name_for(slug: str) -> str:
    """The PostgreSQL schema that holds this tenant's data."""
    return f"{get_settings().tenant_schema_prefix}{validate_slug(slug)}"


class Tenant(ControlBase):
    """One client of the platform."""

    __tablename__ = "tenant"

    tenant_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: Stable, human-readable key; also the suffix of the tenant's schema.
    slug: Mapped[str] = mapped_column(String(40), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: Resolved once at provisioning so a prefix change cannot orphan data.
    schema_name: Mapped[str] = mapped_column(String(63), nullable=False, unique=True)

    #: How far bulletins may be issued without a human (spec §8.2).
    automation_policy: Mapped[AutomationPolicy] = mapped_column(
        StrEnumType(AutomationPolicy, 24),
        default=AutomationPolicy.REVIEW_ALL,
        nullable=False,
    )
    region: Mapped[str | None] = mapped_column(String(32))

    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    provisioned_at: Mapped[datetime | None] = mapped_column(_TS)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    destinations: Mapped[list[DeliveryDestination]] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        CheckConstraint("slug ~ '^[a-z][a-z0-9_]{1,38}$'", name="slug_is_identifier"),
        # Partial: scheduled jobs iterate active tenants, never the rest.
        Index("ix_tenant_active", "active", postgresql_where=text("active")),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Tenant {self.slug}>"


class DeliveryDestination(ControlBase):
    """Where a tenant's issued bulletins are sent (spec §12).

    Lives in the control schema beside the tenant it belongs to, because
    the webhook URL is a platform-held credential rather than tenant
    payload: the tenant's own workers never need it, and keeping it out of
    their schema keeps it out of reach of anything that reads tenant data.

    The URL itself is stored as a *secret name*, not a value.  Spec §11
    puts credentials in a vault; a webhook URL is a bearer credential, so
    this table records which secret to look up and never the secret.
    """

    __tablename__ = "delivery_destination"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenant.tenant_id", ondelete="CASCADE"), nullable=False
    )

    channel: Mapped[DeliveryChannel] = mapped_column(
        StrEnumType(DeliveryChannel, 16), nullable=False
    )
    #: Human label, e.g. "SOC on-call".
    label: Mapped[str] = mapped_column(String(100), nullable=False)
    #: The vault key holding the webhook URL (spec §11).
    webhook_secret_name: Mapped[str] = mapped_column(String(128), nullable=False)

    #: Only send bulletins at or above this tier; null means all of them.
    min_tier: Mapped[Tier | None] = mapped_column(StrEnumType(Tier, 12))
    #: Send bulletins an analyst released as well as auto-issued ones.
    include_reviewed: Mapped[bool] = mapped_column(default=True, nullable=False)

    active: Mapped[bool] = mapped_column(default=True, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        _TS, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    tenant: Mapped[Tenant] = relationship(back_populates="destinations")

    __table_args__ = (
        UniqueConstraint("tenant_id", "label", name="tenant_destination_label"),
        Index("ix_delivery_destination_tenant_id", "tenant_id"),
    )

    def accepts(self, tier: Tier, *, auto_issued: bool) -> bool:
        """Should this destination receive a bulletin at ``tier``?"""
        if not self.active:
            return False
        if not auto_issued and not self.include_reviewed:
            return False
        # Kept as a guard rather than one negated expression: each
        # condition reads the same way, and a fourth is easy to add.
        if self.min_tier is not None and tier.rank < self.min_tier.rank:  # noqa: SIM103
            return False
        return True

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<DeliveryDestination {self.channel} {self.label}>"
