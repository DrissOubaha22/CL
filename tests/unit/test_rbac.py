"""Roles, permissions and principals - spec §11."""

from __future__ import annotations

import pytest

from aegis.auth.rbac import (
    PLATFORM_PERMISSIONS,
    ROLE_PERMISSIONS,
    AccessDenied,
    Permission,
    Principal,
    Role,
    principal_for_service,
)


def analyst(*tenants: str) -> Principal:
    return Principal(
        subject="analyst@example.test",
        tenant_roles={slug: frozenset({Role.ANALYST}) for slug in tenants},
    )


class TestTenantScoping:
    def test_a_role_is_held_in_a_tenant_not_in_general(self) -> None:
        """The property §11 exists to enforce."""
        principal = analyst("acme")

        assert principal.may(Permission.READ_CASE, tenant_slug="acme")
        assert not principal.may(Permission.READ_CASE, tenant_slug="globex")

    def test_a_permission_without_a_tenant_is_refused(self) -> None:
        """There is no 'read cases everywhere'."""
        assert not analyst("acme").may(Permission.READ_CASE)

    def test_roles_in_one_tenant_do_not_reach_another(self) -> None:
        principal = Principal(
            subject="u",
            tenant_roles={
                "acme": frozenset({Role.TENANT_ADMIN}),
                "globex": frozenset({Role.VIEWER}),
            },
        )
        assert principal.may(Permission.WRITE_INVENTORY, tenant_slug="acme")
        assert not principal.may(Permission.WRITE_INVENTORY, tenant_slug="globex")

    def test_tenants_lists_only_tenants_with_roles(self) -> None:
        principal = Principal(
            subject="u",
            tenant_roles={"acme": frozenset({Role.VIEWER}), "ghost": frozenset()},
        )
        assert principal.tenants == frozenset({"acme"})


class TestRoleContents:
    def test_a_viewer_cannot_release_a_bulletin(self) -> None:
        viewer = Principal(subject="v", tenant_roles={"acme": frozenset({Role.VIEWER})})
        assert viewer.may(Permission.READ_BULLETIN, tenant_slug="acme")
        assert not viewer.may(Permission.REVIEW_BULLETIN, tenant_slug="acme")

    def test_an_analyst_can(self) -> None:
        assert analyst("acme").may(Permission.REVIEW_BULLETIN, tenant_slug="acme")

    def test_an_analyst_cannot_change_the_inventory(self) -> None:
        assert not analyst("acme").may(Permission.WRITE_INVENTORY, tenant_slug="acme")

    def test_roles_accumulate(self) -> None:
        principal = Principal(
            subject="u",
            tenant_roles={"acme": frozenset({Role.VIEWER, Role.ANALYST})},
        )
        assert principal.may(Permission.REVIEW_BULLETIN, tenant_slug="acme")

    def test_every_role_grants_something(self) -> None:
        for role in Role:
            assert ROLE_PERMISSIONS[role], f"{role} grants nothing"


class TestPlatformRole:
    def test_a_platform_operator_may_run_the_feeds(self) -> None:
        ops = Principal(subject="ops", platform_roles=frozenset({Role.PLATFORM_OPERATOR}))
        assert ops.may(Permission.RUN_INTEL)

    def test_a_platform_operator_holds_no_tenant_data_permission(self) -> None:
        """Running the shared feeds does not require anyone's hostnames."""
        ops = Principal(subject="ops", platform_roles=frozenset({Role.PLATFORM_OPERATOR}))
        for permission in (
            Permission.READ_CASE,
            Permission.READ_INVENTORY,
            Permission.READ_BULLETIN,
        ):
            assert not ops.may(permission, tenant_slug="acme")

    def test_a_tenant_role_never_grants_a_platform_permission(self) -> None:
        admin = Principal(subject="a", tenant_roles={"acme": frozenset({Role.TENANT_ADMIN})})
        assert not admin.may(Permission.RUN_INTEL)
        assert not admin.may(Permission.MANAGE_PLATFORM)

    def test_a_platform_permission_ignores_a_supplied_tenant(self) -> None:
        admin = Principal(subject="a", tenant_roles={"acme": frozenset({Role.TENANT_ADMIN})})
        assert not admin.may(Permission.RUN_INTEL, tenant_slug="acme")

    def test_the_two_permission_sets_are_disjoint(self) -> None:
        tenant_permissions: set[Permission] = set()
        for role in (Role.VIEWER, Role.ANALYST, Role.TENANT_ADMIN):
            tenant_permissions |= ROLE_PERMISSIONS[role]
        assert not tenant_permissions & PLATFORM_PERMISSIONS


class TestRequire:
    def test_require_passes_silently_when_permitted(self) -> None:
        analyst("acme").require(Permission.READ_CASE, tenant_slug="acme")

    def test_require_names_the_tenant_it_was_aimed_at(self) -> None:
        """The audit log needs to record which tenant was targeted."""
        with pytest.raises(AccessDenied) as err:
            analyst("acme").require(Permission.READ_CASE, tenant_slug="globex")

        assert err.value.tenant_slug == "globex"
        assert err.value.permission is Permission.READ_CASE
        assert err.value.subject == "analyst@example.test"

    def test_the_reason_distinguishes_no_role_from_wrong_role(self) -> None:
        no_role = analyst("acme")
        with pytest.raises(AccessDenied) as absent:
            no_role.require(Permission.READ_CASE, tenant_slug="globex")
        assert "no role in this tenant" in absent.value.reason

        wrong_role = Principal(subject="v", tenant_roles={"acme": frozenset({Role.VIEWER})})
        with pytest.raises(AccessDenied) as insufficient:
            wrong_role.require(Permission.REVIEW_BULLETIN, tenant_slug="acme")
        assert "no role grants it" in insufficient.value.reason


class TestServicePrincipal:
    def test_a_job_is_named_in_the_audit_trail(self) -> None:
        """Scheduled work still acts as somebody."""
        job = principal_for_service("delivery", tenants=["acme"])
        assert job.subject == "service:delivery"
        assert job.issuer == "service"

    def test_a_job_is_scoped_to_the_tenants_it_was_given(self) -> None:
        job = principal_for_service("matching", tenants=["acme"])
        assert job.may(Permission.RUN_ASSESSMENT, tenant_slug="acme")
        assert not job.may(Permission.RUN_ASSESSMENT, tenant_slug="globex")

    def test_a_platform_job_holds_no_tenant_access(self) -> None:
        job = principal_for_service("intel", platform=True)
        assert job.may(Permission.RUN_INTEL)
        assert not job.may(Permission.READ_CASE, tenant_slug="acme")
