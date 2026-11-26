"""Exposure verification against a live database - spec §6.

The prober is a stub throughout: these test what Aegis *concludes* from an
observation, not the socket code.  §6.2's two rules are what is being
asserted - never escalate on assumption, and log every check.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.config import Settings
from aegis.core.enums import (
    Criticality,
    ExposureClass,
    FeedSource,
    MatchFlag,
    VerificationOutcome,
)
from aegis.db.models import Asset, Match, Verification
from aegis.intel.schemas import CpeRange, FeedContribution, SourceRef
from aegis.intel.store import apply_contributions
from aegis.inventory.schemas import DiscoveryEvidence, InventoryItem, InventorySource
from aegis.inventory.store import import_inventory
from aegis.matching.engine import reset_context_cache, run_matching
from aegis.verification.engine import verify_matches
from aegis.verification.probes import ProbeObservation
from aegis.verification.scope import ProbeTarget
from tests.conftest import requires_db

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
CVE = "CVE-2024-21762"
HOST = "vpn.example.com"


class StubProber:
    """Returns a scripted observation and records what it was asked to probe."""

    def __init__(self, observation: ProbeObservation | None = None) -> None:
        self.observation = observation or ProbeObservation(target="stub")
        self.targets: list[ProbeTarget] = []

    def probe(self, target: ProbeTarget) -> ProbeObservation:
        self.targets.append(target)
        # ProbeObservation uses slots, so copy it through dataclasses.
        return replace(self.observation, target=str(target))


def reachable(**overrides: object) -> ProbeObservation:
    observation = ProbeObservation(
        target="stub", reachable=True, latency_ms=25, server_header="FortiOS/7.4.1"
    )
    observation.observed_product = "fortios"
    observation.observed_version = "7.4.1"
    observation.banner = observation.server_header
    for key, value in overrides.items():
        setattr(observation, key, value)
    return observation


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    reset_context_cache()


@pytest.fixture
def settings() -> Settings:
    return Settings(
        verification_enabled=True,
        verification_per_host_delay_seconds=0.0,
        verification_ttl_hours=24,
    )


@pytest.fixture
def advisory(session: Session) -> None:
    """FortiOS 7.4.0 <= v < 7.4.3, KEV-listed, ransomware-linked."""
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


def _seed_match(
    tenant_session: Session,
    *,
    hostname: str = HOST,
    version: str = "7.4.1",
    evidence: DiscoveryEvidence = DiscoveryEvidence.ANSWERED_PUBLICLY,
    port: int | None = 443,
) -> Match:
    import_inventory(
        tenant_session,
        [
            InventoryItem(
                hostname=hostname,
                product="FortiOS",
                version=version,
                port=port,
                evidence=evidence,
                source=InventorySource.ASM,
                criticality=Criticality.HIGH,
            )
        ],
        observed_at=NOW,
    )
    tenant_session.commit()
    run_matching(tenant_session, now=NOW)
    tenant_session.commit()
    return tenant_session.scalars(select(Match)).one()


class TestOutcomes:
    def test_a_live_vulnerable_version_is_confirmed(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        match = _seed_match(tenant_session)
        prober = StubProber(reachable())

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert result.confirmed == 1
        check = tenant_session.scalars(select(Verification)).one()
        assert check.outcome is VerificationOutcome.CONFIRMED
        assert check.reachable is True
        assert check.version_confirmed is True
        assert check.observed_version == "7.4.1"

        tenant_session.refresh(match)
        assert match.asset.exposure_verified_at == NOW
        assert str(MatchFlag.UNVERIFIED) not in match.flags

    def test_a_patched_live_version_cuts_the_false_positive(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """The stale-record case §6.1 exists for: inventory says 7.4.1, the
        live service runs 7.4.9."""
        match = _seed_match(tenant_session)
        prober = StubProber(
            reachable(
                server_header="FortiOS/7.4.9",
                observed_version="7.4.9",
                banner="FortiOS/7.4.9",
            )
        )

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert result.version_mismatch == 1
        assert result.false_positives_cut == 1
        tenant_session.refresh(match)
        assert match.resolved_at == NOW, "a contradicted match stops being open"

    def test_an_unreachable_service_is_not_escalated(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """Spec §6.1: behind NAT, filtering, or simply not there."""
        match = _seed_match(tenant_session)
        prober = StubProber(ProbeObservation(target="stub", error="connection timed out"))

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert result.unreachable == 1
        tenant_session.refresh(match)
        assert match.asset.exposure_verified_at is None
        assert str(MatchFlag.UNVERIFIED) in match.flags
        assert match.resolved_at is None, "unreachable is not the same as fixed"

    def test_a_fronted_origin_is_recorded_as_fronted(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """Spec §6.1: a WAF-protected origin is not directly exploitable."""
        _seed_match(tenant_session)
        prober = StubProber(
            reachable(waf_detected=True, waf_vendor="cloudflare", observed_version=None)
        )

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert result.fronted == 1
        check = tenant_session.scalars(select(Verification)).one()
        assert check.outcome is VerificationOutcome.FRONTED
        assert check.waf_detected is True
        assert check.waf_vendor == "cloudflare"

    def test_a_silent_banner_confirms_reachability_only(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """Many appliances suppress the version; that contradicts nothing."""
        _seed_match(tenant_session)
        prober = StubProber(
            reachable(server_header="FortiGate", observed_version=None, observed_product=None)
        )

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert result.confirmed == 1
        assert result.version_mismatch == 0

    def test_a_banner_for_another_product_proves_nothing(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """A proxy or a different service answering is not evidence."""
        _seed_match(tenant_session)
        prober = StubProber(
            reachable(
                server_header="nginx/1.24.0",
                observed_product="nginx",
                observed_version="1.24.0",
            )
        )

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert result.version_mismatch == 0, "a foreign banner is not a mismatch"
        check = tenant_session.scalars(select(Verification)).one()
        assert check.evidence.get("product_mismatch") is not None

    def test_an_out_of_scope_target_is_inconclusive(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """Spec §6.2: a check that could not run leaves the tier alone."""
        match = _seed_match(tenant_session)
        observation = ProbeObservation(target="stub", error="out of scope")
        observation.detail["out_of_scope"] = True
        prober = StubProber(observation)

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert result.inconclusive == 1
        assert result.false_positives_cut == 0
        tenant_session.refresh(match)
        assert match.asset.exposure_verified_at is None
        assert match.resolved_at is None


class TestScopeInPractice:
    def test_only_the_host_and_port_the_match_names_is_probed(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """Spec §6.2: no scanning, no enumeration."""
        _seed_match(tenant_session, port=8443)
        prober = StubProber(reachable())

        verify_matches(tenant_session, prober=prober, settings=settings, now=NOW, force=True)

        assert len(prober.targets) == 1
        assert prober.targets[0].host == HOST
        assert prober.targets[0].port == 8443

    def test_internal_assets_are_not_probed(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        _seed_match(tenant_session, evidence=DiscoveryEvidence.SEEN_INTERNALLY)
        prober = StubProber(reachable())

        result = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert prober.targets == []
        assert result.skipped == 1
        check = tenant_session.scalars(select(Verification)).one()
        assert check.outcome is VerificationOutcome.NOT_APPLICABLE

    def test_client_side_assets_are_not_probed(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """Spec §6.3: the risk basis is weaponised content, not reachability."""
        _seed_match(tenant_session, evidence=DiscoveryEvidence.INSTALLED_ON_ENDPOINT)
        prober = StubProber(reachable())

        verify_matches(tenant_session, prober=prober, settings=settings, now=NOW, force=True)
        tenant_session.commit()

        assert prober.targets == []
        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.exposure_class is ExposureClass.CLIENT_SIDE

    def test_verification_can_be_turned_off_entirely(
        self, advisory: None, tenant_session: Session
    ) -> None:
        """A deployment that must not emit traffic claims nothing."""
        match = _seed_match(tenant_session)
        prober = StubProber(reachable())

        result = verify_matches(
            tenant_session,
            prober=prober,
            settings=Settings(verification_enabled=False),
            now=NOW,
            force=True,
        )
        tenant_session.commit()

        assert prober.targets == []
        assert result.skipped == result.considered
        tenant_session.refresh(match)
        assert str(MatchFlag.UNVERIFIED) in match.flags


class TestAuditTrail:
    def test_every_check_is_logged_including_the_useless_ones(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        """Spec §6.2: each check is logged against the match for audit."""
        _seed_match(tenant_session)

        for observation in (
            reachable(),
            ProbeObservation(target="stub", error="timed out"),
            reachable(waf_detected=True, waf_vendor="akamai"),
        ):
            verify_matches(
                tenant_session,
                prober=StubProber(observation),
                settings=settings,
                now=NOW,
                force=True,
            )
            tenant_session.commit()

        count = tenant_session.scalar(select(func.count()).select_from(Verification)) or 0
        assert count == 3

    def test_the_target_probed_is_recorded(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        _seed_match(tenant_session)
        verify_matches(
            tenant_session,
            prober=StubProber(reachable()),
            settings=settings,
            now=NOW,
            force=True,
        )
        tenant_session.commit()

        check = tenant_session.scalars(select(Verification)).one()
        assert (check.target_host, check.target_port) == (HOST, 443)
        assert check.latency_ms == 25


class TestFreshness:
    def test_a_recent_check_is_not_repeated(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        _seed_match(tenant_session)
        prober = StubProber(reachable())

        verify_matches(tenant_session, prober=prober, settings=settings, now=NOW, force=True)
        tenant_session.commit()

        result = verify_matches(
            tenant_session,
            prober=prober,
            settings=settings,
            now=NOW + timedelta(hours=1),
        )
        tenant_session.commit()

        assert result.skipped == 1
        assert len(prober.targets) == 1

    def test_a_stale_check_is_repeated(
        self, advisory: None, tenant_session: Session, settings: Settings
    ) -> None:
        _seed_match(tenant_session)
        prober = StubProber(reachable())

        verify_matches(tenant_session, prober=prober, settings=settings, now=NOW, force=True)
        tenant_session.commit()

        verify_matches(
            tenant_session,
            prober=prober,
            settings=settings,
            now=NOW + timedelta(hours=48),
        )
        tenant_session.commit()

        assert len(prober.targets) == 2
