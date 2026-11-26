"""The audit log (spec §11).

Spec §11 requires an "append-only log of access, matches, verifications,
bulletin issuance".  Two decisions shape this table:

**It lives in the control schema, not per tenant.** A denied cross-tenant
read is exactly the event the log exists to surface, and it cannot be
written into a schema the principal has no access to.  One table answers
"who touched what" across the platform, including the attempts that failed.
The cost is that a tenant's own audit trail is a filtered view rather than a
physically separate one; `tenant_slug` is indexed for that reason.

**Append-only is enforced by the database.** A migration installs a trigger
that raises on UPDATE and DELETE.  A log that the application merely
promises not to rewrite is a log an attacker with application access can
rewrite.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aegis.core.enums import AuditAction, AuditOutcome
from aegis.db.base import ControlBase
from aegis.db.types import StrEnumType

JSONType = JSON().with_variant(JSONB(), "postgresql")
_TS = DateTime(timezone=True)

__all__ = ["AuditEvent"]


class AuditEvent(ControlBase):
    """One thing that happened, and who caused it."""

    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(_TS, server_default=func.now(), nullable=False)

    #: Who acted.  A person's subject from SSO, or ``service:<name>``.
    subject: Mapped[str] = mapped_column(String(320), nullable=False)
    #: How they were authenticated: oidc, service, cli.
    issuer: Mapped[str | None] = mapped_column(String(64))

    action: Mapped[AuditAction] = mapped_column(StrEnumType(AuditAction, 32), nullable=False)
    outcome: Mapped[AuditOutcome] = mapped_column(StrEnumType(AuditOutcome, 16), nullable=False)

    #: Which tenant the action was aimed at.  Null for platform operations,
    #: and *populated even when denied* - a refused cross-tenant read must
    #: record which tenant was targeted.
    tenant_slug: Mapped[str | None] = mapped_column(String(40))
    #: The permission checked, when the event came from an access check.
    permission: Mapped[str | None] = mapped_column(String(32))

    resource_type: Mapped[str | None] = mapped_column(String(32))
    resource_id: Mapped[str | None] = mapped_column(String(64))

    #: Why a denial happened, or what a run produced.
    reason: Mapped[str | None] = mapped_column(Text)
    #: Ties together the events of one API request or one scheduled run.
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    #: Network origin, when the event came through an interface.
    source_ip: Mapped[str | None] = mapped_column(String(64))

    detail: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_audit_event_occurred_at", "occurred_at"),
        Index("ix_audit_event_subject", "subject"),
        Index("ix_audit_event_tenant_slug", "tenant_slug"),
        Index("ix_audit_event_action", "action"),
        # Denied attempts are what gets reviewed; make finding them cheap.
        Index("ix_audit_event_outcome_occurred_at", "outcome", "occurred_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditEvent {self.action} {self.outcome} {self.subject}@{self.tenant_slug}>"
