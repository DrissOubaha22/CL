"""Roles, permissions and the principal they belong to (spec §11).

Spec §11: "SSO + RBAC; per-tenant scoping enforced at the data-access
layer".  Two ideas, kept apart on purpose:

* **What a role may do** is a property of the role, and lives in
  :data:`ROLE_PERMISSIONS`.  One table, reviewable in one screen.
* **Which tenants a principal holds a role in** is a property of the
  principal.  A principal is an analyst *at Acme*, not an analyst in
  general.

A permission check therefore always takes both a permission and a tenant,
and there is no overload that omits the tenant.  The one exception is the
platform role, which is scoped to operations that are not tenant data at
all - running feeds, provisioning tenants - and which deliberately grants
*no* access to any tenant's assets, matches or bulletins.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

import structlog

log = structlog.get_logger(__name__)

__all__ = [
    "ROLE_PERMISSIONS",
    "AccessDenied",
    "Permission",
    "Principal",
    "Role",
]


class Permission(StrEnum):
    """One thing a principal may do."""

    # --- tenant data ------------------------------------------------------
    READ_INVENTORY = "read_inventory"
    WRITE_INVENTORY = "write_inventory"
    READ_CASE = "read_case"
    READ_BULLETIN = "read_bulletin"
    #: Release or reject a queued bulletin (spec §8.2 analyst review).
    REVIEW_BULLETIN = "review_bulletin"
    #: Run matching, verification or scoring for a tenant.
    RUN_ASSESSMENT = "run_assessment"
    #: Change a tenant's delivery destinations and automation policy.
    MANAGE_TENANT = "manage_tenant"
    #: Read the tenant's own audit trail.
    READ_AUDIT = "read_audit"

    # --- platform operations, not tenant data -----------------------------
    #: Run the shared intel feeds.
    RUN_INTEL = "run_intel"
    #: Create, provision and deactivate tenants.
    MANAGE_PLATFORM = "manage_platform"
    #: Read the cross-tenant audit log, including denied attempts.
    READ_PLATFORM_AUDIT = "read_platform_audit"


class Role(StrEnum):
    """A named bundle of permissions."""

    #: Read-only access to a tenant's findings.
    VIEWER = "viewer"
    #: A security analyst: reads everything, and releases bulletins.
    ANALYST = "analyst"
    #: Runs the tenant's pipeline and manages its settings.
    TENANT_ADMIN = "tenant_admin"
    #: Operates the platform. Deliberately holds no tenant-data permission:
    #: running the feeds does not require reading anyone's hostnames.
    PLATFORM_OPERATOR = "platform_operator"


#: What each role may do.  Tenant roles accumulate; the platform role is
#: disjoint from them.
ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(
        {
            Permission.READ_INVENTORY,
            Permission.READ_CASE,
            Permission.READ_BULLETIN,
        }
    ),
    Role.ANALYST: frozenset(
        {
            Permission.READ_INVENTORY,
            Permission.READ_CASE,
            Permission.READ_BULLETIN,
            Permission.REVIEW_BULLETIN,
            Permission.READ_AUDIT,
        }
    ),
    Role.TENANT_ADMIN: frozenset(
        {
            Permission.READ_INVENTORY,
            Permission.WRITE_INVENTORY,
            Permission.READ_CASE,
            Permission.READ_BULLETIN,
            Permission.REVIEW_BULLETIN,
            Permission.RUN_ASSESSMENT,
            Permission.MANAGE_TENANT,
            Permission.READ_AUDIT,
        }
    ),
    Role.PLATFORM_OPERATOR: frozenset(
        {
            Permission.RUN_INTEL,
            Permission.MANAGE_PLATFORM,
            Permission.READ_PLATFORM_AUDIT,
        }
    ),
}

#: Permissions that are not about any tenant's data.
PLATFORM_PERMISSIONS: frozenset[Permission] = ROLE_PERMISSIONS[Role.PLATFORM_OPERATOR]


class AccessDenied(PermissionError):
    """A principal attempted something its roles do not permit.

    Carries the tenant it was aimed at so the audit log can record the
    attempt - a denied cross-tenant read is exactly what §11's audit
    requirement exists to surface.
    """

    def __init__(
        self,
        *,
        subject: str,
        permission: Permission,
        tenant_slug: str | None = None,
        reason: str = "not permitted",
    ) -> None:
        target = f" on tenant {tenant_slug!r}" if tenant_slug else ""
        super().__init__(f"{subject!r} may not {permission}{target}: {reason}")
        self.subject = subject
        self.permission = permission
        self.tenant_slug = tenant_slug
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is acting, and what they hold where.

    ``tenant_roles`` maps a tenant slug to the roles the principal holds
    *in that tenant*.  A principal with no entry for a tenant has no access
    to it at all, which is the default and the only safe one.
    """

    subject: str
    #: Tenant slug -> roles held there.
    tenant_roles: Mapping[str, frozenset[Role]] = field(default_factory=dict)
    #: Roles that are not scoped to a tenant (platform operations).
    platform_roles: frozenset[Role] = field(default_factory=frozenset)
    #: Carried for the audit trail, never for authorisation.
    display_name: str | None = None
    #: How this principal was authenticated: "oidc", "service", "cli".
    issuer: str | None = None

    # -- queries -----------------------------------------------------------

    @property
    def tenants(self) -> frozenset[str]:
        """Every tenant this principal holds any role in."""
        return frozenset(slug for slug, roles in self.tenant_roles.items() if roles)

    def roles_in(self, tenant_slug: str) -> frozenset[Role]:
        return frozenset(self.tenant_roles.get(tenant_slug, frozenset()))

    def permissions_in(self, tenant_slug: str) -> frozenset[Permission]:
        """Everything this principal may do in one tenant."""
        granted: set[Permission] = set()
        for role in self.roles_in(tenant_slug):
            granted |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(granted)

    @property
    def platform_permissions(self) -> frozenset[Permission]:
        granted: set[Permission] = set()
        for role in self.platform_roles:
            granted |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(granted)

    def may(self, permission: Permission, *, tenant_slug: str | None = None) -> bool:
        """Is this permitted?  Never raises; see :meth:`require`."""
        if permission in PLATFORM_PERMISSIONS:
            # A platform permission is never granted by a tenant role, and
            # never applies to a tenant.
            return permission in self.platform_permissions
        if tenant_slug is None:
            return False
        return permission in self.permissions_in(tenant_slug)

    def require(self, permission: Permission, *, tenant_slug: str | None = None) -> None:
        """Assert a permission, raising :class:`AccessDenied` if absent."""
        if self.may(permission, tenant_slug=tenant_slug):
            return

        reason = "no role grants it"
        if (
            permission not in PLATFORM_PERMISSIONS
            and tenant_slug is not None
            and not self.roles_in(tenant_slug)
        ):
            reason = "principal holds no role in this tenant"

        raise AccessDenied(
            subject=self.subject,
            permission=permission,
            tenant_slug=tenant_slug,
            reason=reason,
        )


def principal_for_service(
    name: str, *, tenants: Iterable[str] = (), platform: bool = False
) -> Principal:
    """A principal for a background job or the CLI.

    Scheduled work still acts as *somebody*, so the audit trail names the
    job rather than a blank. A job that touches tenant data is given
    ``tenant_admin`` in exactly the tenants it was asked to process.
    """
    return Principal(
        subject=f"service:{name}",
        tenant_roles={slug: frozenset({Role.TENANT_ADMIN}) for slug in tenants},
        platform_roles=(frozenset({Role.PLATFORM_OPERATOR}) if platform else frozenset()),
        issuer="service",
    )
