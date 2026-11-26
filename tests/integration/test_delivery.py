"""Delivering bulletins to webhooks - spec §12."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
import respx
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.auth.secrets import SecretStore
from aegis.config import Settings
from aegis.core.enums import (
    BulletinStatus,
    DeliveryChannel,
    DeliveryStatus,
    Tier,
)
from aegis.db.models import Bulletin, Delivery, DeliveryDestination, Match
from aegis.delivery.formatters import format_payload
from aegis.delivery.sender import send_bulletins
from tests.conftest import requires_db

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
SLACK_URL = "https://hooks.slack.test/services/T/B/x"
TEAMS_URL = "https://outlook.office.test/webhook/abc"


class StubSecrets:
    """A secret store that knows the webhook URLs under test."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def get(self, name: str) -> str:
        from aegis.auth.secrets import SecretNotFound

        try:
            return self._values[name]
        except KeyError as exc:
            raise SecretNotFound(name, "stub") from exc

    def get_optional(self, name: str) -> str | None:
        return self._values.get(name)

    def describe(self, name: str) -> Any:  # pragma: no cover - unused
        raise NotImplementedError

    def names(self) -> list[str]:
        return sorted(self._values)


@pytest.fixture
def secrets() -> SecretStore:
    return StubSecrets({"slack_soc": SLACK_URL, "teams_soc": TEAMS_URL})


@pytest.fixture
def settings() -> Settings:
    return Settings(delivery_enabled=True, delivery_max_retries=2)


def _destination(
    channel: DeliveryChannel = DeliveryChannel.SLACK,
    *,
    label: str = "SOC",
    secret: str = "slack_soc",
    min_tier: Tier | None = None,
    include_reviewed: bool = True,
    active: bool = True,
    destination_id: int = 1,
) -> DeliveryDestination:
    destination = DeliveryDestination(
        tenant_id=1,
        channel=channel,
        label=label,
        webhook_secret_name=secret,
        min_tier=min_tier,
        include_reviewed=include_reviewed,
        active=active,
    )
    destination.id = destination_id
    return destination


def _bulletin(
    tenant_session: Session,
    *,
    tier: Tier = Tier.CRITICAL,
    status: BulletinStatus = BulletinStatus.AUTO_ISSUED,
    auto_issued: bool = True,
    hostname: str = "vpn.example.com",
) -> Bulletin:
    """A bulletin with the asset and match it needs to render."""
    from aegis.db.models import Asset

    asset = Asset(
        hostname=hostname,
        product_name="FortiOS",
        version="7.4.1",
        source="asm",
    )
    tenant_session.add(asset)
    tenant_session.flush()

    match = Match(
        asset_id=asset.asset_id,
        cve_id="CVE-2024-21762",
        matched_cpe="cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*",
        matched_range=">=7.4.0 <7.4.3",
    )
    tenant_session.add(match)
    tenant_session.flush()

    bulletin = Bulletin(
        match_id=match.match_id,
        cve_id="CVE-2024-21762",
        tier=tier,
        body="Upgrade to 7.4.3.",
        draft_body="Upgrade to 7.4.3.",
        status=status,
        auto_issued=auto_issued,
    )
    tenant_session.add(bulletin)
    tenant_session.commit()
    return bulletin


class TestSending:
    @respx.mock
    def test_an_issued_bulletin_reaches_the_webhook(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [_destination()],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )
        tenant_session.commit()

        assert result.sent == 1
        assert route.called
        attempt = tenant_session.scalars(select(Delivery)).one()
        assert attempt.status is DeliveryStatus.DELIVERED
        assert attempt.status_code == 200

    @respx.mock
    def test_a_queued_bulletin_is_not_sent(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        """A draft awaiting a human is not an alert."""
        _bulletin(
            tenant_session,
            status=BulletinStatus.QUEUED,
            auto_issued=False,
        )
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [_destination()],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )

        assert result.considered == 0
        assert not route.called

    @respx.mock
    def test_delivery_is_idempotent(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        """A bulletin already delivered is not sent again."""
        _bulletin(tenant_session)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        destination = _destination()

        send_bulletins(tenant_session, [destination], secrets=secrets, settings=settings, now=NOW)
        tenant_session.commit()
        second = send_bulletins(
            tenant_session, [destination], secrets=secrets, settings=settings, now=NOW
        )
        tenant_session.commit()

        assert route.call_count == 1
        assert second.sent == 0
        assert second.skipped == 1

    @respx.mock
    def test_a_failure_is_recorded_and_retried_next_run(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session)
        respx.post(SLACK_URL).mock(return_value=httpx.Response(500))
        destination = _destination()

        first = send_bulletins(
            tenant_session, [destination], secrets=secrets, settings=settings, now=NOW
        )
        tenant_session.commit()
        assert first.failed == 1

        respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        second = send_bulletins(
            tenant_session, [destination], secrets=secrets, settings=settings, now=NOW
        )
        tenant_session.commit()

        assert second.sent == 1
        attempts = tenant_session.scalars(select(Delivery)).all()
        assert len(attempts) == 2, "both attempts are on record"
        assert {a.status for a in attempts} == {
            DeliveryStatus.FAILED,
            DeliveryStatus.DELIVERED,
        }

    @respx.mock
    def test_a_missing_secret_is_reported_not_retried(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        """Retrying will not conjure a vault entry."""
        _bulletin(tenant_session)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [_destination(secret="absent")],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )
        tenant_session.commit()

        assert result.misconfigured == ["SOC"]
        assert result.failed == 0
        assert not route.called

    @respx.mock
    def test_delivery_can_be_turned_off(
        self, tenant_session: Session, secrets: SecretStore
    ) -> None:
        _bulletin(tenant_session)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [_destination()],
            secrets=secrets,
            settings=Settings(delivery_enabled=False),
            now=NOW,
        )

        assert result.considered == 0
        assert not route.called


class TestDestinationFilters:
    @respx.mock
    def test_min_tier_filters_out_lower_tiers(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session, tier=Tier.MEDIUM)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [_destination(min_tier=Tier.HIGH)],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )

        assert result.skipped == 1
        assert not route.called

    @respx.mock
    def test_min_tier_admits_the_tier_itself(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session, tier=Tier.HIGH)
        respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [_destination(min_tier=Tier.HIGH)],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )
        assert result.sent == 1

    @respx.mock
    def test_a_destination_can_decline_analyst_released_bulletins(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session, status=BulletinStatus.ISSUED, auto_issued=False)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [_destination(include_reviewed=False)],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )

        assert result.skipped == 1
        assert not route.called

    @respx.mock
    def test_an_inactive_destination_is_ignored(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        send_bulletins(
            tenant_session,
            [_destination(active=False)],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )
        assert not route.called

    @respx.mock
    def test_several_destinations_each_receive_it(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session)
        slack = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        teams = respx.post(TEAMS_URL).mock(return_value=httpx.Response(200))

        result = send_bulletins(
            tenant_session,
            [
                _destination(destination_id=1),
                _destination(
                    DeliveryChannel.TEAMS,
                    label="Teams SOC",
                    secret="teams_soc",
                    destination_id=2,
                ),
            ],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )

        assert result.sent == 2
        assert slack.called and teams.called


class TestPayloads:
    @respx.mock
    def test_slack_receives_slack_shaped_json(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session)
        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))

        send_bulletins(
            tenant_session,
            [_destination()],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )

        import json

        payload = json.loads(route.calls[0].request.content)
        assert "attachments" in payload
        assert "CRITICAL" in payload["text"]
        assert "vpn.example.com" in payload["text"]

    @respx.mock
    def test_teams_receives_a_message_card(
        self, tenant_session: Session, secrets: SecretStore, settings: Settings
    ) -> None:
        _bulletin(tenant_session)
        route = respx.post(TEAMS_URL).mock(return_value=httpx.Response(200))

        send_bulletins(
            tenant_session,
            [_destination(DeliveryChannel.TEAMS, label="Teams", secret="teams_soc")],
            secrets=secrets,
            settings=settings,
            now=NOW,
        )

        import json

        payload = json.loads(route.calls[0].request.content)
        assert payload["@type"] == "MessageCard"
        assert "sections" in payload

    def test_an_unknown_channel_is_refused(self) -> None:
        with pytest.raises(ValueError, match="no formatter"):
            format_payload(
                channel="carrier_pigeon",  # type: ignore[arg-type]
                cve_id="CVE-1",
                tier=Tier.LOW,
                hostname="h",
                product="p",
                body="b",
                auto_issued=True,
            )


class TestRunner:
    """Per-tenant orchestration (``aegis.delivery.runner``)."""

    @pytest.fixture
    def tenants_with_destinations(self, two_tenants, control_session: Session, engine):
        """Both tenants get a Slack destination and one issued bulletin."""
        from tests.conftest import session_for

        for tenant in two_tenants:
            control_session.add(
                DeliveryDestination(
                    tenant_id=tenant.tenant_id,
                    channel=DeliveryChannel.SLACK,
                    label=f"SOC {tenant.slug}",
                    webhook_secret_name="slack_soc",
                )
            )
            tenant_db = session_for(tenant, engine)
            try:
                _bulletin(tenant_db, hostname=f"vpn.{tenant.slug}.example.com")
            finally:
                tenant_db.close()
        control_session.commit()
        return two_tenants

    @respx.mock
    def test_every_tenant_is_delivered_for(
        self, tenants_with_destinations, secrets: SecretStore, settings, engine
    ) -> None:
        from aegis.delivery.runner import deliver_all_tenants

        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        results = deliver_all_tenants(secrets=secrets, settings=settings, engine=engine)

        assert {item.slug for item in results} == {"acme", "globex"}
        assert all(item.ok for item in results)
        assert route.call_count == 2

    @respx.mock
    def test_each_tenants_own_hosts_are_sent(
        self, tenants_with_destinations, secrets: SecretStore, settings, engine
    ) -> None:
        """A tenant's alert must not carry another tenant's host."""
        import json

        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        from aegis.delivery.runner import deliver_all_tenants

        deliver_all_tenants(secrets=secrets, settings=settings, engine=engine)

        sent = [json.loads(call.request.content)["text"] for call in route.calls]
        assert any("vpn.acme.example.com" in text for text in sent)
        assert any("vpn.globex.example.com" in text for text in sent)
        for text in sent:
            assert not ("vpn.acme.example.com" in text and "vpn.globex.example.com" in text)

    @respx.mock
    def test_a_tenant_without_destinations_is_a_no_op(
        self, two_tenants, secrets: SecretStore, settings, engine
    ) -> None:
        from aegis.delivery.runner import deliver_all_tenants

        route = respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        results = deliver_all_tenants(secrets=secrets, settings=settings, engine=engine)

        assert all(item.result.considered == 0 for item in results)
        assert not route.called

    @respx.mock
    def test_a_single_tenant_can_be_targeted(
        self, tenants_with_destinations, secrets: SecretStore, settings, engine
    ) -> None:
        from aegis.delivery.runner import deliver_for_tenant

        respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        item = deliver_for_tenant("acme", secrets=secrets, settings=settings, engine=engine)
        assert item.ok
        assert item.result.sent == 1

    @respx.mock
    def test_the_delivery_is_audited(
        self,
        tenants_with_destinations,
        secrets: SecretStore,
        settings,
        engine,
        control_session: Session,
    ) -> None:
        """Spec §11: bulletin issuance is in the audit log."""
        from aegis.core.enums import AuditAction
        from aegis.db.models import AuditEvent
        from aegis.delivery.runner import deliver_for_tenant

        respx.post(SLACK_URL).mock(return_value=httpx.Response(200))
        deliver_for_tenant("acme", secrets=secrets, settings=settings, engine=engine)

        events = control_session.scalars(
            select(AuditEvent).where(AuditEvent.action == AuditAction.BULLETIN_DELIVERED)
        ).all()
        assert len(events) == 1
        assert events[0].tenant_slug == "acme"
        assert events[0].detail["sent"] == 1
