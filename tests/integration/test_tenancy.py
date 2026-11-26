"""Schema-per-tenant isolation - spec §1, §11.

The isolation claim is the one that has to be *tested*, not reasoned about:
these assert that a tenant-scoped query cannot see another tenant's rows, and
that an unscoped query cannot run at all.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from aegis.core.enums import AutomationPolicy
from aegis.db.models import Asset, Tenant
from aegis.db.models.control import InvalidTenantSlug, schema_name_for, validate_slug
from aegis.db.tenancy import (
    TenantNotFound,
    active_tenants,
    create_tenant,
    drop_tenant_schema,
    get_tenant,
    tenant_session_scope,
)
from tests.conftest import requires_db, session_for

pytestmark = [pytest.mark.integration, requires_db]


def _add_asset(session: Session, hostname: str, product: str) -> None:
    session.add(
        Asset(
            hostname=hostname,
            product_name=product,
            version="1.0.0",
            source="test",
        )
    )
    session.commit()


class TestSlugValidation:
    @pytest.mark.parametrize(
        "slug", ["", "1acme", "ACME-Corp", "acme-corp", "a", "x" * 50, "drop; --"]
    )
    def test_rejects_anything_that_is_not_a_bare_identifier(self, slug: str) -> None:
        """The slug is concatenated into a schema name, so it is locked down."""
        with pytest.raises(InvalidTenantSlug):
            validate_slug(slug)

    def test_normalises_case_and_whitespace(self) -> None:
        assert validate_slug("  Acme_Corp  ") == "acme_corp"

    def test_schema_name_carries_the_prefix(self) -> None:
        assert schema_name_for("acme") == "tenant_acme"


class TestIsolation:
    def test_each_tenant_sees_only_its_own_rows(
        self, two_tenants: tuple[Tenant, Tenant], engine: Engine
    ) -> None:
        acme, globex = two_tenants

        acme_session = session_for(acme, engine)
        globex_session = session_for(globex, engine)
        try:
            _add_asset(acme_session, "vpn.acme.test", "FortiOS")
            _add_asset(globex_session, "mail.globex.test", "Exchange")

            assert [a.hostname for a in acme_session.scalars(select(Asset))] == ["vpn.acme.test"]
            assert [a.hostname for a in globex_session.scalars(select(Asset))] == [
                "mail.globex.test"
            ]
        finally:
            acme_session.close()
            globex_session.close()

    def test_an_unscoped_query_cannot_run(self, tenant: Tenant, engine: Engine) -> None:
        """Isolation does not depend on remembering to filter.

        Without a schema_translate_map the placeholder schema is used
        literally, and no such schema exists.
        """
        unscoped = sessionmaker(bind=engine)()
        try:
            with pytest.raises(ProgrammingError, match="does not exist"):
                unscoped.scalars(select(Asset)).all()
        finally:
            unscoped.rollback()
            unscoped.close()

    def test_identical_identities_coexist_across_tenants(
        self, two_tenants: tuple[Tenant, Tenant], engine: Engine
    ) -> None:
        """Two clients may run the same host name; neither constrains the other."""
        acme, globex = two_tenants
        for tenant in (acme, globex):
            session = session_for(tenant, engine)
            try:
                _add_asset(session, "vpn.internal", "FortiOS")
            finally:
                session.close()

        for tenant in (acme, globex):
            session = session_for(tenant, engine)
            try:
                assert session.scalars(select(Asset)).one().hostname == "vpn.internal"
            finally:
                session.close()

    def test_dropping_one_tenant_leaves_the_other_intact(
        self, two_tenants: tuple[Tenant, Tenant], engine: Engine
    ) -> None:
        acme, globex = two_tenants
        session = session_for(globex, engine)
        try:
            _add_asset(session, "mail.globex.test", "Exchange")
        finally:
            session.close()

        drop_tenant_schema(acme, engine=engine)

        session = session_for(globex, engine)
        try:
            assert session.scalars(select(Asset)).one().hostname == "mail.globex.test"
        finally:
            session.close()

        with engine.connect() as connection:
            remaining = connection.execute(
                text("SELECT 1 FROM information_schema.schemata WHERE schema_name = :s"),
                {"s": acme.schema_name},
            ).first()
        assert remaining is None


class TestRegistry:
    def test_create_tenant_provisions_and_stamps(
        self, control_session: Session, engine: Engine
    ) -> None:
        tenant = create_tenant(
            control_session,
            slug="newco",
            name="NewCo Ltd",
            automation_policy=AutomationPolicy.AUTO_ISSUE_VERIFIED,
            engine=engine,
        )
        control_session.commit()
        try:
            assert tenant.schema_name == "tenant_newco"
            assert tenant.provisioned_at is not None
            assert tenant.automation_policy is AutomationPolicy.AUTO_ISSUE_VERIFIED

            # The schema is real and usable.
            with tenant_session_scope(tenant, engine) as session:
                _add_asset(session, "host.newco.test", "nginx")
            with tenant_session_scope(tenant, engine) as session:
                assert session.scalars(select(Asset)).one().product_name == "nginx"
        finally:
            drop_tenant_schema(tenant, engine=engine)

    def test_duplicate_slug_is_refused(
        self, tenant: Tenant, control_session: Session, engine: Engine
    ) -> None:
        with pytest.raises(ValueError, match="already exists"):
            create_tenant(control_session, slug="acme", name="Impostor", engine=engine)

    def test_get_tenant_rejects_an_unknown_slug(self, control_session: Session) -> None:
        with pytest.raises(TenantNotFound):
            get_tenant(control_session, "nobody")

    def test_deactivated_tenants_are_excluded(
        self, tenant: Tenant, control_session: Session
    ) -> None:
        """Scheduled jobs must not process a deactivated tenant."""
        tenant.active = False
        control_session.commit()

        assert active_tenants(control_session) == []
        with pytest.raises(TenantNotFound, match="not active"):
            get_tenant(control_session, "acme")
        # It is still findable when explicitly asked for.
        assert get_tenant(control_session, "acme", require_active=False) is tenant
