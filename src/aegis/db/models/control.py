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

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from aegis.config import get_settings
from aegis.core.enums import AutomationPolicy
from aegis.db.base import ControlBase
from aegis.db.types import StrEnumType

_TS = DateTime(timezone=True)

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

    __table_args__ = (
        CheckConstraint("slug ~ '^[a-z][a-z0-9_]{1,38}$'", name="slug_is_identifier"),
        # Partial: scheduled jobs iterate active tenants, never the rest.
        Index("ix_tenant_active", "active", postgresql_where=text("active")),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Tenant {self.slug}>"
