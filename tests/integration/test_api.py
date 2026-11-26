"""The tenant API and the isolation it enforces - spec §11, §12.

§11 asks for "automated cross-tenant access tests in CI".  ``TestCrossTenant``
is that: a principal holding a role in one tenant is driven at another
tenant's endpoints and must see nothing, and the attempt must appear in the
audit log.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from aegis.api.app import create_app
from aegis.auth.oidc import InvalidToken, TokenVerifier
from aegis.auth.rbac import Principal, Role
from aegis.config import Settings
from aegis.core.enums import (
    AuditAction,
    AuditOutcome,
    BulletinStatus,
    Criticality,
    FeedSource,
    Tier,
)
from aegis.db.models import AuditEvent, Bulletin, Tenant
from aegis.intel.schemas import CpeRange, FeedContribution, SourceRef
from aegis.intel.store import apply_contributions
from aegis.inventory.schemas import DiscoveryEvidence, InventoryItem, InventorySource
from aegis.inventory.store import import_inventory
from aegis.matching.engine import reset_context_cache, run_matching
from aegis.scoring.engine import score_matches
from tests.conftest import requires_db, session_for

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
CVE = "CVE-2024-21762"


class StubVerifier(TokenVerifier):
    """Maps an opaque token straight to a principal, no identity provider.

    The token format is tested against a real signature in
    ``tests/unit/test_oidc_and_secrets.py``; what these tests need is the
    principal, not another round of JWT parsing.
    """

    def __init__(self, principals: dict[str, Principal]) -> None:
        self._principals = principals

    @property
    def configured(self) -> bool:
        return True

    def verify(self, token: str) -> Principal:
        try:
            return self._principals[token]
        except KeyError as exc:
            raise InvalidToken("unknown token") from exc


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    reset_context_cache()


@pytest.fixture
def principals() -> dict[str, Principal]:
    return {
        "acme-analyst": Principal(
            subject="analyst@acme.test",
            tenant_roles={"acme": frozenset({Role.ANALYST})},
            issuer="oidc",
        ),
        "acme-viewer": Principal(
            subject="viewer@acme.test",
            tenant_roles={"acme": frozenset({Role.VIEWER})},
            issuer="oidc",
        ),
        "globex-analyst": Principal(
            subject="analyst@globex.test",
            tenant_roles={"globex": frozenset({Role.ANALYST})},
            issuer="oidc",
        ),
        "ops": Principal(
            subject="ops@example.test",
            platform_roles=frozenset({Role.PLATFORM_OPERATOR}),
            issuer="oidc",
        ),
        "nobody": Principal(subject="nobody@example.test", issuer="oidc"),
    }


@pytest.fixture
def app(principals: dict[str, Principal], engine: Engine) -> FastAPI:
    # Bound to the test engine: without it the API would open sessions on
    # the configured DSN, which is a different database.
    return create_app(
        settings=Settings(oidc_issuer="https://idp.test"),
        token_verifier=StubVerifier(principals),
        engine=engine,
    )


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _seed_intel(session: Session) -> None:
    apply_contributions(
        session,
        [
            FeedContribution(
                cve_id=CVE,
                source=FeedSource.CISA_KEV,
                retrieved_at=NOW,
                sources=[SourceRef(url="https://kev.test/x")],
                on_kev=True,
                ransomware=True,
            ),
            FeedContribution(
                cve_id=CVE,
                source=FeedSource.NVD,
                retrieved_at=NOW,
                sources=[SourceRef(url="https://nvd.test/x")],
                cvss=9.8,
                patch_available=True,
                affected_cpes=[
                    CpeRange(
                        cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                        version_start_including="7.4.0",
                        version_end_excluding="7.4.3",
                    )
                ],
            ),
        ],
    )
    session.commit()


def _populate(tenant_db: Session, hostname: str) -> None:
    import_inventory(
        tenant_db,
        [
            InventoryItem(
                hostname=hostname,
                product="FortiOS",
                version="7.4.1",
                port=443,
                evidence=DiscoveryEvidence.ANSWERED_PUBLICLY,
                source=InventorySource.ASM,
                criticality=Criticality.HIGH,
            )
        ],
        observed_at=NOW,
    )
    tenant_db.commit()
    run_matching(tenant_db, now=NOW)
    tenant_db.commit()
    score_matches(tenant_db, now=NOW)
    tenant_db.commit()

    match = tenant_db.scalars(select(Bulletin.match_id)).first()
    if match is None:
        from aegis.db.models import Match

        match_row = tenant_db.scalars(select(Match)).one()
        tenant_db.add(
            Bulletin(
                match_id=match_row.match_id,
                cve_id=CVE,
                tier=Tier.MEDIUM,
                body=f"Bulletin for {hostname}",
                draft_body="Public draft.",
                status=BulletinStatus.QUEUED,
            )
        )
        tenant_db.commit()


@pytest.fixture
def populated(
    session: Session, two_tenants: tuple[Tenant, Tenant], engine: Engine
) -> tuple[Tenant, Tenant]:
    _seed_intel(session)
    for tenant in two_tenants:
        tenant_db = session_for(tenant, engine)
        try:
            _populate(tenant_db, f"vpn.{tenant.slug}.example.com")
        finally:
            tenant_db.close()
    return two_tenants


class TestAuthentication:
    def test_health_needs_no_token(self, client: TestClient) -> None:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_a_missing_token_is_401(self, client: TestClient) -> None:
        response = client.get("/tenants/acme/cases")
        assert response.status_code == 401
        assert response.headers["WWW-Authenticate"] == "Bearer"

    def test_a_non_bearer_header_is_401(self, client: TestClient) -> None:
        response = client.get("/tenants/acme/cases", headers={"Authorization": "Basic abc"})
        assert response.status_code == 401

    def test_an_unknown_token_is_401(self, client: TestClient) -> None:
        response = client.get("/tenants/acme/cases", headers=auth("forged"))
        assert response.status_code == 401

    def test_the_api_refuses_to_start_without_sso(self) -> None:
        """An API that cannot authenticate must not serve."""
        with pytest.raises(RuntimeError, match="without SSO"):
            create_app(settings=Settings())


class TestCrossTenant:
    """Spec §11: automated cross-tenant access tests."""

    def test_a_principal_cannot_read_another_tenants_cases(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        own = client.get("/tenants/acme/cases", headers=auth("acme-analyst"))
        assert own.status_code == 200
        assert own.json()["count"] >= 1

        other = client.get("/tenants/globex/cases", headers=auth("acme-analyst"))
        assert other.status_code == 404
        assert "globex" not in other.text

    @pytest.mark.parametrize(
        "path",
        [
            "/tenants/globex",
            "/tenants/globex/assets",
            "/tenants/globex/cases",
            "/tenants/globex/bulletins",
            "/tenants/globex/audit",
        ],
    )
    def test_every_tenant_endpoint_refuses(
        self, populated: tuple[Tenant, Tenant], client: TestClient, path: str
    ) -> None:
        response = client.get(path, headers=auth("acme-analyst"))
        assert response.status_code == 404

    def test_the_refusal_does_not_disclose_that_the_tenant_exists(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        """404, not 403: a 403 confirms the tenant is real."""
        real = client.get("/tenants/globex/cases", headers=auth("acme-analyst"))
        invented = client.get("/tenants/nosuchco/cases", headers=auth("acme-analyst"))

        assert real.status_code == invented.status_code == 404
        assert real.json() == invented.json()

    def test_a_principal_with_no_roles_sees_nothing(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        for slug in ("acme", "globex"):
            response = client.get(f"/tenants/{slug}/cases", headers=auth("nobody"))
            assert response.status_code == 404

    def test_a_platform_operator_cannot_read_tenant_data(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        """Operating the platform does not mean reading anyone's hostnames."""
        response = client.get("/tenants/acme/cases", headers=auth("ops"))
        assert response.status_code == 404

    def test_each_tenant_sees_only_its_own_hosts(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        acme = client.get("/tenants/acme/assets", headers=auth("acme-analyst"))
        globex = client.get("/tenants/globex/assets", headers=auth("globex-analyst"))

        acme_hosts = [item["hostname"] for item in acme.json()["items"]]
        globex_hosts = [item["hostname"] for item in globex.json()["items"]]

        assert acme_hosts == ["vpn.acme.example.com"]
        assert globex_hosts == ["vpn.globex.example.com"]

    def test_the_denied_attempt_is_audited(
        self,
        populated: tuple[Tenant, Tenant],
        client: TestClient,
        control_session: Session,
    ) -> None:
        """Spec §11: the audit log exists so this is noticed, not just blocked."""
        client.get("/tenants/globex/cases", headers=auth("acme-analyst"))

        denial = control_session.scalars(
            select(AuditEvent)
            .where(AuditEvent.outcome == AuditOutcome.DENIED)
            .order_by(AuditEvent.occurred_at.desc())
        ).first()

        assert denial is not None
        assert denial.subject == "analyst@acme.test"
        assert denial.tenant_slug == "globex"
        assert denial.action is AuditAction.ACCESS
        assert denial.reason


class TestPermissions:
    def test_a_viewer_cannot_review_a_bulletin(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        listing = client.get("/tenants/acme/bulletins", headers=auth("acme-viewer"))
        assert listing.status_code == 200
        bulletin_id = listing.json()["items"][0]["bulletin_id"]

        response = client.post(
            f"/tenants/acme/bulletins/{bulletin_id}/review",
            headers=auth("acme-viewer"),
            json={"approve": True},
        )
        assert response.status_code == 404

    def test_an_analyst_can_release_a_bulletin(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        listing = client.get("/tenants/acme/bulletins", headers=auth("acme-analyst"))
        bulletin_id = listing.json()["items"][0]["bulletin_id"]

        response = client.post(
            f"/tenants/acme/bulletins/{bulletin_id}/review",
            headers=auth("acme-analyst"),
            json={"approve": True, "note": "confirmed with the platform team"},
        )

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "issued"
        assert body["analyst"] == "analyst@acme.test"
        assert body["issued_at"] is not None

    def test_a_bulletin_cannot_be_reviewed_twice(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        """Re-deciding one already issued rewrites history the log recorded."""
        listing = client.get("/tenants/acme/bulletins", headers=auth("acme-analyst"))
        bulletin_id = listing.json()["items"][0]["bulletin_id"]

        client.post(
            f"/tenants/acme/bulletins/{bulletin_id}/review",
            headers=auth("acme-analyst"),
            json={"approve": True},
        )
        second = client.post(
            f"/tenants/acme/bulletins/{bulletin_id}/review",
            headers=auth("acme-analyst"),
            json={"approve": False},
        )
        assert second.status_code == 409

    def test_only_a_platform_operator_reads_the_denial_log(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        assert client.get("/audit/denials", headers=auth("acme-analyst")).status_code == 403
        assert client.get("/audit/denials", headers=auth("ops")).status_code == 200


class TestResponses:
    def test_a_case_explains_its_tier(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        case = client.get("/tenants/acme/cases", headers=auth("acme-analyst")).json()["items"][0]

        assert case["cve_id"] == CVE
        assert case["tier_before_gate"] == "critical"
        assert case["tier"] == "medium"
        assert case["cap_reasons"]
        assert case["remediation_window"]

    def test_a_bulletin_detail_separates_the_model_draft(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        """Spec §8.1 audit evidence."""
        listing = client.get("/tenants/acme/bulletins", headers=auth("acme-analyst")).json()
        bulletin_id = listing["items"][0]["bulletin_id"]

        detail = client.get(
            f"/tenants/acme/bulletins/{bulletin_id}",
            headers=auth("acme-analyst"),
        ).json()

        assert "body" in detail
        assert "draft_body" in detail

    def test_listings_paginate(self, populated: tuple[Tenant, Tenant], client: TestClient) -> None:
        response = client.get("/tenants/acme/assets?limit=1", headers=auth("acme-analyst")).json()
        assert len(response["items"]) <= 1
        assert "next_offset" in response

    def test_a_missing_bulletin_is_404(
        self, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        response = client.get("/tenants/acme/bulletins/999999", headers=auth("acme-analyst"))
        assert response.status_code == 404


class TestAuditTrail:
    def test_every_access_is_recorded(
        self,
        populated: tuple[Tenant, Tenant],
        client: TestClient,
        control_session: Session,
    ) -> None:
        client.get("/tenants/acme/cases", headers=auth("acme-analyst"))

        events = control_session.scalars(
            select(AuditEvent).where(
                AuditEvent.subject == "analyst@acme.test",
                AuditEvent.outcome == AuditOutcome.ALLOWED,
            )
        ).all()
        assert events
        assert all(event.tenant_slug == "acme" for event in events)

    def test_a_review_is_recorded_as_such(
        self,
        populated: tuple[Tenant, Tenant],
        client: TestClient,
        control_session: Session,
    ) -> None:
        listing = client.get("/tenants/acme/bulletins", headers=auth("acme-analyst")).json()
        bulletin_id = listing["items"][0]["bulletin_id"]
        client.post(
            f"/tenants/acme/bulletins/{bulletin_id}/review",
            headers=auth("acme-analyst"),
            json={"approve": True},
        )

        reviewed = control_session.scalars(
            select(AuditEvent).where(AuditEvent.action == AuditAction.BULLETIN_REVIEWED)
        ).all()
        assert len(reviewed) == 1
        assert reviewed[0].resource_id == str(bulletin_id)

    def test_one_request_shares_a_correlation_id(
        self,
        populated: tuple[Tenant, Tenant],
        client: TestClient,
        control_session: Session,
    ) -> None:
        client.get(
            "/tenants/acme/cases",
            headers={**auth("acme-analyst"), "X-Request-Id": "req-123"},
        )
        events = control_session.scalars(
            select(AuditEvent).where(AuditEvent.correlation_id == "req-123")
        ).all()
        assert events

    def test_the_audit_log_cannot_be_rewritten(
        self, engine: Engine, populated: tuple[Tenant, Tenant], client: TestClient
    ) -> None:
        """Spec §11: append-only, enforced by the database.

        A log the application merely promises not to rewrite is a log that
        anyone with application access can rewrite.
        """
        from sqlalchemy import text

        client.get("/tenants/acme/cases", headers=auth("acme-analyst"))

        with engine.connect() as connection:
            with pytest.raises(Exception, match="append-only"):
                connection.exec_driver_sql("UPDATE control.audit_event SET subject = 'attacker'")
            connection.rollback()

            with pytest.raises(Exception, match="append-only"):
                connection.exec_driver_sql("DELETE FROM control.audit_event")
            connection.rollback()

            surviving = connection.execute(
                text("SELECT count(*) FROM control.audit_event")
            ).scalar_one()
            assert surviving > 0


class TestOpenApi:
    def test_the_schema_is_generated(self, app: FastAPI) -> None:
        schema: dict[str, Any] = app.openapi()
        assert "/tenants/{slug}/cases" in schema["paths"]
        assert "/audit/denials" in schema["paths"]

    def test_every_tenant_path_is_scoped_by_slug(self, app: FastAPI) -> None:
        """No tenant endpoint can exist without a tenant in its path."""
        schema: dict[str, Any] = app.openapi()
        for path in schema["paths"]:
            if path.startswith("/tenants"):
                assert "{slug}" in path
