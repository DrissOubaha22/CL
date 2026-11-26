"""Bulletin generation end to end - spec §8, and the §14 phase-4 criterion.

"Privacy-safe auto/review bulletin pipeline." Two properties are asserted
here and nowhere else: that bulletins are routed correctly per §8.2, and
that the model is given no client data no matter how many tenants, hosts or
CVEs pass through.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from aegis.ai.privacy import PublicPayload
from aegis.bulletins.engine import generate_bulletins
from aegis.config import Settings
from aegis.core.enums import (
    AutomationPolicy,
    BulletinStatus,
    Criticality,
    FeedSource,
    ReviewReason,
    Tier,
)
from aegis.db.models import Bulletin, Match, Tenant
from aegis.intel.schemas import CpeRange, FeedContribution, SourceRef
from aegis.intel.store import apply_contributions
from aegis.inventory.schemas import DiscoveryEvidence, InventoryItem, InventorySource
from aegis.inventory.store import import_inventory
from aegis.matching.engine import reset_context_cache, run_matching
from aegis.scoring.engine import score_matches
from aegis.verification.engine import verify_matches
from aegis.verification.probes import ProbeObservation
from aegis.verification.scope import ProbeTarget
from tests.conftest import requires_db, session_for

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
CVE = "CVE-2024-21762"


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    reset_context_cache()


class RecordingLlm:
    """A stand-in model that records every payload it is handed."""

    def __init__(self) -> None:
        self.payloads: list[str] = []
        self.calls = 0

    def draft(self, *, system: str, payload: PublicPayload, instructions: str) -> str:
        self.calls += 1
        self.payloads.append(payload.text)
        self.payloads.append(system)
        self.payloads.append(instructions)
        return (
            "A stack-based buffer overflow in the SSL VPN lets an "
            "unauthenticated attacker run code. Upgrade to 7.4.3 or later."
        )

    def extract(self, **kwargs: Any) -> Any:  # pragma: no cover - unused
        raise NotImplementedError

    @property
    def everything_seen(self) -> str:
        return "\n".join(self.payloads)


def _seed_intel(session: Session, **overrides: object) -> None:
    kev_fields: dict[str, object] = {"on_kev": True, "ransomware": True}
    kev_fields.update(overrides)
    apply_contributions(
        session,
        [
            FeedContribution(
                cve_id=CVE,
                source=FeedSource.CISA_KEV,
                retrieved_at=NOW,
                sources=[SourceRef(url="https://kev.test/x")],
                **kev_fields,  # type: ignore[arg-type]
            ),
            FeedContribution(
                cve_id=CVE,
                source=FeedSource.NVD,
                retrieved_at=NOW,
                sources=[SourceRef(url="https://nvd.test/x")],
                cvss=9.8,
                patch_available=True,
                description="A stack-based buffer overflow in the SSL VPN.",
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


def _answering() -> ProbeObservation:
    observation = ProbeObservation(target="stub", reachable=True, latency_ms=20)
    observation.server_header = observation.banner = "FortiOS/7.4.1"
    observation.observed_product = "fortios"
    observation.observed_version = "7.4.1"
    return observation


class AlwaysAnswering:
    def probe(self, target: ProbeTarget) -> ProbeObservation:
        from dataclasses import replace

        return replace(_answering(), target=str(target))


def _prepare_tenant(
    tenant_session: Session,
    hosts: list[tuple[str, Criticality]],
    *,
    verify: bool = True,
) -> None:
    """Inventory, match, verify and score, so bulletins have something to say."""
    import_inventory(
        tenant_session,
        [
            InventoryItem(
                hostname=hostname,
                product="FortiOS",
                version="7.4.1",
                port=443,
                evidence=DiscoveryEvidence.ANSWERED_PUBLICLY,
                source=InventorySource.ASM,
                criticality=criticality,
            )
            for hostname, criticality in hosts
        ],
        observed_at=NOW,
    )
    tenant_session.commit()
    run_matching(tenant_session, now=NOW)
    tenant_session.commit()

    if verify:
        verify_matches(
            tenant_session,
            prober=AlwaysAnswering(),
            settings=Settings(verification_enabled=True, verification_per_host_delay_seconds=0.0),
            now=NOW,
            force=True,
        )
        tenant_session.commit()

    score_matches(tenant_session, now=NOW)
    tenant_session.commit()


class TestPrivacy:
    """The §8.1 property, asserted against what the model actually received."""

    def test_no_tenant_data_reaches_the_model(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_intel(session)
        _prepare_tenant(
            tenant_session,
            [
                ("vpn.acme.example.com", Criticality.HIGH),
                ("mail.acme.example.com", Criticality.LOW),
            ],
        )

        llm = RecordingLlm()
        generate_bulletins(
            tenant_session,
            llm=llm,
            model_name="claude-opus-5-5",
            automation_policy=AutomationPolicy.AUTO_ISSUE_VERIFIED,
            now=NOW,
        )
        tenant_session.commit()

        seen = llm.everything_seen
        for forbidden in (
            "vpn.acme.example.com",
            "mail.acme.example.com",
            "acme",
            "Acme",
        ):
            assert forbidden not in seen, f"{forbidden!r} reached the model"

    def test_the_public_facts_do_reach_the_model(
        self, session: Session, tenant_session: Session
    ) -> None:
        """The boundary must not be achieved by sending nothing useful."""
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.HIGH)])

        llm = RecordingLlm()
        generate_bulletins(tenant_session, llm=llm, now=NOW)
        tenant_session.commit()

        seen = llm.everything_seen
        assert CVE in seen
        assert "9.8" in seen
        assert "fortios" in seen.lower()

    def test_the_rendered_bulletin_does_carry_the_tenant_details(
        self, session: Session, tenant_session: Session
    ) -> None:
        """Merged afterwards, inside the boundary (spec §8.1)."""
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.HIGH)])

        generate_bulletins(tenant_session, llm=RecordingLlm(), now=NOW)
        tenant_session.commit()

        bulletin = tenant_session.scalars(select(Bulletin)).one()
        assert "vpn.example.com" in bulletin.body
        assert "vpn.example.com" not in (bulletin.draft_body or "")

    def test_one_draft_is_shared_across_hosts(
        self, session: Session, tenant_session: Session
    ) -> None:
        """The public half does not depend on which host it is."""
        _seed_intel(session)
        _prepare_tenant(
            tenant_session,
            [(f"host{index}.example.com", Criticality.LOW) for index in range(4)],
        )

        llm = RecordingLlm()
        result = generate_bulletins(tenant_session, llm=llm, now=NOW)
        tenant_session.commit()

        assert result.created == 4
        assert llm.calls == 1


class TestRoutingInPractice:
    def test_an_exploited_patched_verified_case_is_auto_issued(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        result = generate_bulletins(
            tenant_session,
            llm=RecordingLlm(),
            automation_policy=AutomationPolicy.AUTO_ISSUE_VERIFIED,
            now=NOW,
        )
        tenant_session.commit()

        assert result.auto_issued == 1
        bulletin = tenant_session.scalars(select(Bulletin)).one()
        assert bulletin.status is BulletinStatus.AUTO_ISSUED
        assert bulletin.auto_issued is True
        assert bulletin.issued_at == NOW

    def test_a_crown_jewel_critical_waits_for_a_human(
        self, session: Session, tenant_session: Session
    ) -> None:
        """Spec §8.2 row 3 overrides row 1."""
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("crown.example.com", Criticality.HIGH)])

        generate_bulletins(
            tenant_session,
            llm=RecordingLlm(),
            automation_policy=AutomationPolicy.AUTO_ISSUE_VERIFIED,
            now=NOW,
        )
        tenant_session.commit()

        bulletin = tenant_session.scalars(select(Bulletin)).one()
        assert bulletin.tier is Tier.CRITICAL
        assert bulletin.status is BulletinStatus.QUEUED
        assert str(ReviewReason.CROWN_JEWEL) in bulletin.review_reasons
        assert bulletin.detail["mandatory_review"] is True

    def test_unverified_exposure_queues_the_bulletin(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)], verify=False)

        generate_bulletins(
            tenant_session,
            llm=RecordingLlm(),
            automation_policy=AutomationPolicy.AUTO_ISSUE_VERIFIED,
            now=NOW,
        )
        tenant_session.commit()

        bulletin = tenant_session.scalars(select(Bulletin)).one()
        assert bulletin.status is BulletinStatus.QUEUED
        assert str(ReviewReason.EXPOSURE_UNVERIFIED) in bulletin.review_reasons

    def test_no_patch_queues_the_bulletin(self, session: Session, tenant_session: Session) -> None:
        apply_contributions(
            session,
            [
                FeedContribution(
                    cve_id=CVE,
                    source=FeedSource.CISA_KEV,
                    retrieved_at=NOW,
                    sources=[SourceRef(url="https://kev.test/x")],
                    on_kev=True,
                ),
                FeedContribution(
                    cve_id=CVE,
                    source=FeedSource.NVD,
                    retrieved_at=NOW,
                    sources=[SourceRef(url="https://nvd.test/x")],
                    cvss=9.8,
                    patch_available=False,
                    affected_cpes=[
                        CpeRange(
                            cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                            version_end_excluding="7.4.3",
                        )
                    ],
                ),
            ],
        )
        session.commit()
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        generate_bulletins(
            tenant_session,
            llm=RecordingLlm(),
            automation_policy=AutomationPolicy.AUTO_ISSUE_VERIFIED,
            now=NOW,
        )
        tenant_session.commit()

        bulletin = tenant_session.scalars(select(Bulletin)).one()
        assert str(ReviewReason.NO_PATCH) in bulletin.review_reasons

    def test_tenant_policy_queues_everything(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        generate_bulletins(
            tenant_session,
            llm=RecordingLlm(),
            automation_policy=AutomationPolicy.REVIEW_ALL,
            now=NOW,
        )
        tenant_session.commit()

        bulletin = tenant_session.scalars(select(Bulletin)).one()
        assert bulletin.status is BulletinStatus.QUEUED
        assert str(ReviewReason.TENANT_POLICY) in bulletin.review_reasons


class TestLifecycle:
    def test_regenerating_is_skipped_by_default(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        generate_bulletins(tenant_session, llm=RecordingLlm(), now=NOW)
        tenant_session.commit()
        second = generate_bulletins(tenant_session, llm=RecordingLlm(), now=NOW)
        tenant_session.commit()

        assert second.created == 0
        assert second.skipped_existing == 1
        assert len(tenant_session.scalars(select(Bulletin)).all()) == 1

    def test_regenerate_replaces_in_place(self, session: Session, tenant_session: Session) -> None:
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        generate_bulletins(tenant_session, llm=RecordingLlm(), now=NOW)
        tenant_session.commit()
        result = generate_bulletins(tenant_session, llm=RecordingLlm(), now=NOW, regenerate=True)
        tenant_session.commit()

        assert result.created == 1
        assert len(tenant_session.scalars(select(Bulletin)).all()) == 1

    def test_resolved_matches_get_no_bulletin(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        match = tenant_session.scalars(select(Match)).one()
        match.resolved_at = NOW
        tenant_session.commit()

        result = generate_bulletins(tenant_session, llm=RecordingLlm(), now=NOW)
        assert result.created == 0

    def test_the_drafting_model_is_recorded(
        self, session: Session, tenant_session: Session
    ) -> None:
        """Audit: which bulletins a model wrote, and which it did not."""
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        generate_bulletins(
            tenant_session, llm=RecordingLlm(), model_name="claude-opus-5-5", now=NOW
        )
        tenant_session.commit()
        assert tenant_session.scalars(select(Bulletin)).one().drafted_by == "claude-opus-5-5"

    def test_without_a_model_bulletins_are_still_issued(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_intel(session)
        _prepare_tenant(tenant_session, [("vpn.example.com", Criticality.LOW)])

        result = generate_bulletins(tenant_session, llm=None, now=NOW)
        tenant_session.commit()

        assert result.created == 1
        assert result.drafts_fallback == 1
        bulletin = tenant_session.scalars(select(Bulletin)).one()
        assert bulletin.drafted_by is None
        assert bulletin.body


class TestPerTenant:
    def test_bulletins_do_not_leak_between_tenants(
        self,
        session: Session,
        two_tenants: tuple[Tenant, Tenant],
        engine: Engine,
    ) -> None:
        _seed_intel(session)
        acme, globex = two_tenants
        llm = RecordingLlm()

        for tenant in (acme, globex):
            tenant_db = session_for(tenant, engine)
            try:
                _prepare_tenant(
                    tenant_db,
                    [(f"vpn.{tenant.slug}.example.com", Criticality.LOW)],
                )
                generate_bulletins(tenant_db, llm=llm, now=NOW)
                tenant_db.commit()
            finally:
                tenant_db.close()

        for tenant in (acme, globex):
            tenant_db = session_for(tenant, engine)
            try:
                bulletins = tenant_db.scalars(select(Bulletin)).all()
                assert len(bulletins) == 1
                assert f"vpn.{tenant.slug}.example.com" in bulletins[0].body
            finally:
                tenant_db.close()

        # And the shared model saw neither tenant's hosts.
        seen = llm.everything_seen
        assert "vpn.acme.example.com" not in seen
        assert "vpn.globex.example.com" not in seen


class TestRunner:
    """Per-tenant orchestration (``aegis.bulletins.runner``)."""

    @pytest.fixture
    def populated(self, session: Session, two_tenants: tuple[Tenant, Tenant], engine: Engine):
        _seed_intel(session)
        for tenant in two_tenants:
            tenant_db = session_for(tenant, engine)
            try:
                _prepare_tenant(
                    tenant_db,
                    [(f"vpn.{tenant.slug}.example.com", Criticality.LOW)],
                )
            finally:
                tenant_db.close()
        return two_tenants

    def test_generates_for_every_active_tenant(self, populated, engine: Engine) -> None:
        from aegis.bulletins.runner import generate_all_tenants

        results = generate_all_tenants(llm=RecordingLlm(), engine=engine)

        assert {item.slug for item in results} == {"acme", "globex"}
        assert all(item.ok for item in results)
        assert all(item.result.created == 1 for item in results)

    def test_the_tenants_own_policy_is_honoured(
        self, populated, control_session: Session, engine: Engine
    ) -> None:
        """Spec §8.2: "under tenant policy" - each tenant decides."""
        from aegis.bulletins.runner import generate_all_tenants

        acme, globex = populated
        acme.automation_policy = AutomationPolicy.AUTO_ISSUE_VERIFIED
        globex.automation_policy = AutomationPolicy.REVIEW_ALL
        control_session.commit()

        results = {
            item.slug: item for item in generate_all_tenants(llm=RecordingLlm(), engine=engine)
        }

        assert results["acme"].result.auto_issued == 1
        assert results["globex"].result.auto_issued == 0
        assert results["globex"].result.queued == 1

    def test_one_broken_tenant_does_not_stop_the_others(self, populated, engine: Engine) -> None:
        from aegis.bulletins.runner import generate_all_tenants
        from aegis.db.tenancy import drop_tenant_schema

        acme, _ = populated
        drop_tenant_schema(acme, engine=engine)

        results = {
            item.slug: item for item in generate_all_tenants(llm=RecordingLlm(), engine=engine)
        }

        assert not results["acme"].ok
        assert results["globex"].ok

    def test_a_single_tenant_can_be_targeted(self, populated, engine: Engine) -> None:
        from aegis.bulletins.runner import generate_for_tenant

        item = generate_for_tenant("acme", llm=RecordingLlm(), engine=engine)
        assert item.ok
        assert item.result.created == 1
