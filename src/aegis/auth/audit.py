"""Writing the audit log (spec §11).

Two rules this module exists to keep:

* **A denial is recorded.** An access check that refuses writes an event
  before raising.  A log that only contains successful access answers the
  wrong question.
* **An audit write never swallows the thing it is auditing.** If the log
  cannot be written, that is itself logged loudly and the caller's work
  continues: losing a bulletin because the audit table was full would be a
  worse failure than losing one audit row.

* **Each event is committed as it is written.** An earlier version only
  flushed, and a denial was therefore rolled back by the very exception it
  was recording - the ``AccessDenied`` propagating out of the surrounding
  transaction took the audit row with it.  An audit event is an independent
  fact about something that already happened; it does not belong to the
  caller's transaction.  The trail must therefore be given a session of its
  own, which both call sites do.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from aegis.auth.rbac import AccessDenied, Permission, Principal
from aegis.core.enums import AuditAction, AuditOutcome
from aegis.db.models import AuditEvent
from aegis.db.tenancy import session_for_control

log = structlog.get_logger(__name__)

__all__ = ["AuditTrail", "audit_trail"]


class AuditTrail:
    """Append-only record of who did what (spec §11)."""

    def __init__(
        self,
        session: Session,
        *,
        correlation_id: str | None = None,
        source_ip: str | None = None,
    ) -> None:
        """
        Args:
            session: A session of the trail's own, on the control schema.
                Events are committed on it, so sharing it with a caller's
                work would commit that work too.
            correlation_id: Ties the events of one request together.
            source_ip: Network origin, for events from an interface.
        """
        self._session = session
        self.correlation_id = correlation_id
        self.source_ip = source_ip

    # -- writing -----------------------------------------------------------

    def record(
        self,
        *,
        principal: Principal,
        action: AuditAction,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        tenant_slug: str | None = None,
        permission: Permission | None = None,
        resource_type: str | None = None,
        resource_id: str | int | None = None,
        reason: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append one event.

        Never raises for a logging failure; see the module docstring.
        """
        event = AuditEvent(
            occurred_at=datetime.now(UTC),
            subject=principal.subject,
            issuer=principal.issuer,
            action=action,
            outcome=outcome,
            tenant_slug=tenant_slug,
            permission=str(permission) if permission else None,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            reason=reason,
            correlation_id=self.correlation_id,
            source_ip=self.source_ip,
            detail=detail or {},
        )
        try:
            self._session.add(event)
            # Committed, not merely flushed: a denial is recorded *because*
            # an exception is about to propagate, and that exception would
            # roll back a flush-only write before it ever reached disk.
            self._session.commit()
        except Exception as exc:
            log.error(
                "audit.write_failed",
                action=str(action),
                subject=principal.subject,
                error=str(exc),
            )
            self._session.rollback()
        return event

    def authorize(
        self,
        principal: Principal,
        permission: Permission,
        *,
        tenant_slug: str | None = None,
        resource_type: str | None = None,
        resource_id: str | int | None = None,
    ) -> None:
        """Check a permission and record the outcome (spec §11).

        This is the only authorisation entry point that writes to the audit
        log, and it is what interfaces call.  Raises:
            AccessDenied: if the principal may not do this - *after* the
                denial has been recorded.
        """
        try:
            principal.require(permission, tenant_slug=tenant_slug)
        except AccessDenied as denied:
            self.record(
                principal=principal,
                action=AuditAction.ACCESS,
                outcome=AuditOutcome.DENIED,
                tenant_slug=tenant_slug,
                permission=permission,
                resource_type=resource_type,
                resource_id=resource_id,
                reason=denied.reason,
            )
            log.warning(
                "auth.denied",
                subject=principal.subject,
                permission=str(permission),
                tenant=tenant_slug,
                reason=denied.reason,
            )
            raise

        self.record(
            principal=principal,
            action=AuditAction.ACCESS,
            outcome=AuditOutcome.ALLOWED,
            tenant_slug=tenant_slug,
            permission=permission,
            resource_type=resource_type,
            resource_id=resource_id,
        )

    # -- reading -----------------------------------------------------------

    def events_for_tenant(self, tenant_slug: str, *, limit: int = 100) -> list[AuditEvent]:
        """A tenant's own trail, newest first."""
        return list(
            self._session.scalars(
                select(AuditEvent)
                .where(AuditEvent.tenant_slug == tenant_slug)
                .order_by(AuditEvent.occurred_at.desc())
                .limit(limit)
            ).all()
        )

    def denials(self, *, limit: int = 100) -> list[AuditEvent]:
        """Every refused attempt, newest first - the platform review view."""
        return list(
            self._session.scalars(
                select(AuditEvent)
                .where(AuditEvent.outcome == AuditOutcome.DENIED)
                .order_by(AuditEvent.occurred_at.desc())
                .limit(limit)
            ).all()
        )


@contextmanager
def audit_trail(
    *,
    engine: Engine | None = None,
    correlation_id: str | None = None,
    source_ip: str | None = None,
) -> Iterator[AuditTrail]:
    """An audit trail on its own control-schema session.

    Separate from the session doing the work, so an audited action that
    rolls back still leaves its attempt on record.
    """
    with session_for_control(engine) as session:
        yield AuditTrail(session, correlation_id=correlation_id, source_ip=source_ip)
