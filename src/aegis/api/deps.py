"""Request-scoped dependencies for the API (spec §11, §12).

Every tenant-scoped endpoint goes through :func:`tenant_access`, which does
three things in one place so no endpoint can forget any of them:

1. verifies the SSO token and builds the principal (§11 SSO);
2. checks the permission against the tenant in the path (§11 RBAC,
   "per-tenant scoping enforced at the data-access layer");
3. writes the access to the audit log, allowed or denied (§11 audit).

An endpoint receives an already-scoped session.  There is no dependency
that yields an unscoped one, so an endpoint cannot read across tenants by
omitting a filter - it would have to construct its own session, which
review catches.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Annotated

import structlog
from fastapi import Depends, Header, HTTPException, Path, Request, status
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from aegis.auth.audit import AuditTrail
from aegis.auth.oidc import InvalidToken, TokenVerifier
from aegis.auth.rbac import AccessDenied, Permission, Principal
from aegis.db.models import Tenant
from aegis.db.tenancy import (
    TenantNotFound,
    get_tenant,
    session_for_control,
    tenant_session_scope,
)

log = structlog.get_logger(__name__)

__all__ = ["TenantContext", "current_principal", "tenant_access"]


@dataclass(slots=True)
class TenantContext:
    """What a tenant-scoped endpoint is handed."""

    principal: Principal
    tenant: Tenant
    session: Session
    audit: AuditTrail
    correlation_id: str


def _engine(request: Request) -> Engine | None:
    """The engine this app is bound to, or ``None`` for the configured one."""
    engine = getattr(request.app.state, "engine", None)
    return engine if isinstance(engine, Engine) else None


def _verifier(request: Request) -> TokenVerifier:
    verifier = getattr(request.app.state, "token_verifier", None)
    if not isinstance(verifier, TokenVerifier):  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="token verification is not configured",
        )
    return verifier


def current_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    """Authenticate the caller from its bearer token (spec §11).

    Raises:
        HTTPException: 401 when the token is absent, malformed or rejected.
            The reason is returned, because a caller debugging an expired
            token should not have to guess; nothing about *other* tenants
            is disclosed by it.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="a bearer token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    try:
        return _verifier(request).verify(token)
    except InvalidToken as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


def tenant_access(permission: Permission) -> Callable[..., Iterator[TenantContext]]:
    """Build a dependency that authorises ``permission`` on the path tenant.

    Usage::

        CaseAccess = Annotated[
            TenantContext, Depends(tenant_access(Permission.READ_CASE))
        ]

        @router.get("/tenants/{slug}/cases")
        def list_cases(ctx: CaseAccess) -> list[CaseOut]:
            ...
    """

    def dependency(
        request: Request,
        slug: Annotated[str, Path(min_length=2, max_length=40)],
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> Iterator[TenantContext]:
        correlation_id = _correlation_id(request)
        source_ip = request.client.host if request.client else None
        bind = _engine(request)

        with session_for_control(bind) as control:
            audit = AuditTrail(control, correlation_id=correlation_id, source_ip=source_ip)

            try:
                audit.authorize(
                    principal,
                    permission,
                    tenant_slug=slug,
                    resource_type="tenant",
                    resource_id=slug,
                )
            except AccessDenied as denied:
                # 404, not 403: confirming that a tenant exists to someone
                # with no role in it is itself a disclosure.
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="no such tenant",
                ) from denied

            try:
                tenant = get_tenant(control, slug)
            except TenantNotFound as missing:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="no such tenant",
                ) from missing

            with tenant_session_scope(tenant, bind) as session:
                yield TenantContext(
                    principal=principal,
                    tenant=tenant,
                    session=session,
                    audit=audit,
                    correlation_id=correlation_id,
                )

    return dependency


def platform_access(permission: Permission) -> Callable[..., Iterator[AuditTrail]]:
    """Authorise a platform operation, which is not scoped to a tenant."""

    def dependency(
        request: Request,
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> Iterator[AuditTrail]:
        with session_for_control(_engine(request)) as control:
            audit = AuditTrail(
                control,
                correlation_id=_correlation_id(request),
                source_ip=request.client.host if request.client else None,
            )
            try:
                audit.authorize(principal, permission)
            except AccessDenied as denied:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="not permitted",
                ) from denied
            yield audit

    return dependency


def _correlation_id(request: Request) -> str:
    """Tie every audit event of one request together."""
    supplied = request.headers.get("x-request-id")
    return (supplied or str(uuid.uuid4()))[:64]
