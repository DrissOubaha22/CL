"""Scoring against a live database, and the full phase-3 cycle - spec §7, §14.

Phase 3 is done when the specification's §14 criterion holds: "verified,
tiered cases; false positives cut".  ``TestFullCycle`` is that criterion.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.config import Settings
from aegis.core.enums import (
    Criticality,
    FeedSource,
    MatchFlag,
    RunStatus,
    Tier,
)
from aegis.db.models import Match, Score, ScoreRun
from aegis.intel.schemas import CpeRange, FeedContribution, SourceRef
from aegis.intel.store import apply_contributions
from aegis.inventory.schemas import DiscoveryEvidence, InventoryItem, InventorySource
from aegis.inventory.store import import_inventory
from aegis.matching.engine import reset_context_cache, run_matching
from aegis.scoring.engine import score_matches
from aegis.verification.engine import verify_matches
from aegis.verification.probes import ProbeObservation
from aegis.verification.scope import ProbeTarget
from tests.conftest import requires_db

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
CVE = "CVE-2024-21762"


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    reset_context_cache()


@pytest.fixture
def settings() -> Settings:
    return Settings(verification_enabled=True, verification_per_host_delay_seconds=0.0)


class ScriptedProber:
    """Answers per hostname, so one pass can cover several real situations."""

    def __init__(self, script: dict[str, ProbeObservation]) -> None:
        self.script = script
        self.targets: list[ProbeTarget] = []

    def probe(self, target: ProbeTarget) -> ProbeObservation:
        self.targets.append(target)
        observation = self.script.get(
            target.host, ProbeObservation(target="unknown", error="no answer")
        )
        return replace(observation, target=str(target))


def _answering(version: str | None = "7.4.1", **overrides: object) -> ProbeObservation:
    observation = ProbeObservation(target="stub", reachable=True, latency_ms=20)
    if version:
        observation.server_header = f"FortiOS/{version}"
        observation.banner = observation.server_header
        observation.observed_product = "fortios"
        observation.observed_version = version
    for key, value in overrides.items():
        setattr(observation, key, value)
    return observation


def _seed_advisory(session: Session, **intel: object) -> None:
    apply_contributions(
        session,
        [
            FeedContribution(
                cve_id=CVE,
                source=FeedSource.CISA_KEV,
                retrieved_at=NOW,
                sources=[SourceRef(url="https://kev.test/x")],
                on_kev=True,
                **intel,  # type: ignore[arg-type]
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


def _seed_host(
    tenant_session: Session,
    hostname: str,
    *,
    criticality: Criticality = Criticality.UNKNOWN,
    evidence: DiscoveryEvidence = DiscoveryEvidence.ANSWERED_PUBLICLY,
    version: str = "7.4.1",
) -> None:
    import_inventory(
        tenant_session,
        [
            InventoryItem(
                hostname=hostname,
                product="FortiOS",
                version=version,
                port=443,
                evidence=evidence,
                source=InventorySource.ASM,
                criticality=criticality,
            )
        ],
        observed_at=NOW,
    )
    tenant_session.commit()


class TestScoring:
    def test_an_unverified_match_cannot_exceed_medium(
        self, session: Session, tenant_session: Session
    ) -> None:
        """Spec §5.3's verification gate, end to end."""
        _seed_advisory(session, ransomware=True)
        _seed_host(tenant_session, "vpn.example.com", criticality=Criticality.HIGH)
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        score = tenant_session.scalars(select(Score)).one()
        assert score.tier is Tier.MEDIUM
        assert score.tier_before_gate is Tier.CRITICAL
        assert score.auto_escalatable is False

    def test_a_verified_match_reaches_critical(
        self, session: Session, tenant_session: Session, settings: Settings
    ) -> None:
        _seed_advisory(session, ransomware=True)
        _seed_host(tenant_session, "vpn.example.com", criticality=Criticality.HIGH)
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        verify_matches(
            tenant_session,
            prober=ScriptedProber({"vpn.example.com": _answering()}),
            settings=settings,
            now=NOW,
            force=True,
        )
        tenant_session.commit()
        score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        score = tenant_session.scalars(select(Score)).one()
        assert score.tier is Tier.CRITICAL
        assert score.auto_escalatable is True
        assert score.due_at is None, "CRITICAL is out-of-band, not scheduled"

    def test_the_due_date_follows_the_tier(
        self, session: Session, tenant_session: Session, settings: Settings
    ) -> None:
        _seed_advisory(session)
        _seed_host(tenant_session, "vpn.example.com")
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        verify_matches(
            tenant_session,
            prober=ScriptedProber({"vpn.example.com": _answering()}),
            settings=settings,
            now=NOW,
            force=True,
        )
        tenant_session.commit()
        score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        score = tenant_session.scalars(select(Score)).one()
        assert score.tier is Tier.HIGH
        assert score.due_at == NOW + timedelta(hours=72)

    def test_rescoring_updates_rather_than_duplicating(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_advisory(session)
        _seed_host(tenant_session, "vpn.example.com")
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        score_matches(tenant_session, now=NOW)
        tenant_session.commit()
        result = score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        assert result.tier_changed == 0
        assert len(tenant_session.scalars(select(Score)).all()) == 1

    def test_a_tier_change_is_counted(
        self, session: Session, tenant_session: Session, settings: Settings
    ) -> None:
        """Verification is what moves a case off Medium."""
        _seed_advisory(session, ransomware=True)
        _seed_host(tenant_session, "vpn.example.com", criticality=Criticality.HIGH)
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        verify_matches(
            tenant_session,
            prober=ScriptedProber({"vpn.example.com": _answering()}),
            settings=settings,
            now=NOW,
            force=True,
        )
        tenant_session.commit()
        result = score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        assert result.tier_changed == 1
        assert tenant_session.scalars(select(Score)).one().tier is Tier.CRITICAL

    def test_resolved_matches_are_not_scored(
        self, session: Session, tenant_session: Session
    ) -> None:
        _seed_advisory(session)
        _seed_host(tenant_session, "vpn.example.com")
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        match = tenant_session.scalars(select(Match)).one()
        match.resolved_at = NOW
        tenant_session.commit()

        result = score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        assert result.scored == 0

    def test_a_match_with_no_intel_record_is_skipped_not_defaulted(
        self, tenant_session: Session
    ) -> None:
        """Every §7.1 input comes from the intel record; without it there is
        nothing to score, and scoring on defaults would invent a tier."""
        _seed_host(tenant_session, "vpn.example.com")
        asset_id = tenant_session.scalars(select(Match.asset_id)).first()
        assert asset_id is None  # no advisory, so no match

        tenant_session.add(
            Match(
                asset_id=1,
                cve_id="CVE-2099-99999",
                matched_cpe="cpe:2.3:o:fortinet:fortios:7.4.1:*:*:*:*:*:*:*",
            )
        )
        tenant_session.commit()

        result = score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        assert result.scored == 0
        assert result.skipped_no_intel == 1

    def test_the_run_is_journalled(self, session: Session, tenant_session: Session) -> None:
        _seed_advisory(session)
        _seed_host(tenant_session, "vpn.example.com")
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        run = tenant_session.scalars(select(ScoreRun)).one()
        assert run.status is RunStatus.SUCCESS
        assert run.matches_scored == 1
        assert run.finished_at is not None

    def test_factors_explain_the_tier(self, session: Session, tenant_session: Session) -> None:
        _seed_advisory(session, ransomware=True)
        _seed_host(tenant_session, "vpn.example.com", criticality=Criticality.HIGH)
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()
        score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        factors = tenant_session.scalars(select(Score)).one().factors
        assert factors["on_kev"] is True
        assert factors["ransomware"] is True
        assert factors["exposure_verified"] is False
        assert str(MatchFlag.UNVERIFIED) in factors["gating_flags"]
        assert factors["cap_reasons"]


class TestFullCycle:
    """Spec §14 phase 3: verified, tiered cases; false positives cut."""

    def test_four_hosts_four_outcomes(
        self, session: Session, tenant_session: Session, settings: Settings
    ) -> None:
        _seed_advisory(session, ransomware=True)

        for hostname, criticality in (
            ("vulnerable.example.com", Criticality.HIGH),
            ("patched.example.com", Criticality.HIGH),
            ("filtered.example.com", Criticality.HIGH),
            ("fronted.example.com", Criticality.HIGH),
        ):
            _seed_host(tenant_session, hostname, criticality=criticality)

        run_matching(tenant_session, now=NOW)
        tenant_session.commit()
        assert len(tenant_session.scalars(select(Match)).all()) == 4

        prober = ScriptedProber(
            {
                # Live banner agrees with the advisory.
                "vulnerable.example.com": _answering("7.4.1"),
                # Live banner is outside the affected range: stale record.
                "patched.example.com": _answering("7.4.9"),
                # Nothing answers: not reachable from the internet.
                "filtered.example.com": ProbeObservation(
                    target="stub", error="connection timed out"
                ),
                # A proxy answered, not the origin.
                "fronted.example.com": _answering(None, waf_detected=True, waf_vendor="cloudflare"),
            }
        )

        verification = verify_matches(
            tenant_session, prober=prober, settings=settings, now=NOW, force=True
        )
        tenant_session.commit()

        assert verification.probed == 4
        assert verification.confirmed == 1
        assert verification.version_mismatch == 1
        assert verification.unreachable == 1
        assert verification.fronted == 1
        assert verification.false_positives_cut == 2

        scoring = score_matches(tenant_session, now=NOW)
        tenant_session.commit()

        # The patched host is no longer an open finding.
        assert scoring.scored == 3

        tiers = {
            score.match.asset.hostname: score for score in tenant_session.scalars(select(Score))
        }
        assert tiers["vulnerable.example.com"].tier is Tier.CRITICAL
        assert tiers["vulnerable.example.com"].auto_escalatable is True

        assert tiers["fronted.example.com"].tier is Tier.HIGH
        assert tiers["fronted.example.com"].tier_before_gate is Tier.CRITICAL
        assert tiers["fronted.example.com"].auto_escalatable is False

        assert tiers["filtered.example.com"].tier is Tier.MEDIUM
        assert tiers["filtered.example.com"].auto_escalatable is False

        assert "patched.example.com" not in tiers


class TestRunner:
    """Per-tenant orchestration (``aegis.scoring.runner``)."""

    @pytest.fixture
    def populated(
        self,
        session: Session,
        two_tenants,
        engine,
    ):
        from tests.conftest import session_for

        _seed_advisory(session, ransomware=True)
        for tenant in two_tenants:
            tenant_db = session_for(tenant, engine)
            try:
                _seed_host(
                    tenant_db,
                    f"vpn.{tenant.slug}.example.com",
                    criticality=Criticality.HIGH,
                )
                run_matching(tenant_db, now=NOW)
                tenant_db.commit()
            finally:
                tenant_db.close()
        return two_tenants

    def test_assesses_every_active_tenant(self, populated, engine, settings: Settings) -> None:
        from aegis.scoring.runner import assess_all_tenants

        prober = ScriptedProber(
            {
                "vpn.acme.example.com": _answering("7.4.1"),
                "vpn.globex.example.com": _answering("7.4.1"),
            }
        )
        results = assess_all_tenants(prober=prober, settings=settings, engine=engine, force=True)

        assert {result.slug for result in results} == {"acme", "globex"}
        assert all(result.ok for result in results)
        assert all(result.scoring.by_tier == {"critical": 1} for result in results)

    def test_verification_can_be_skipped_to_rescore_only(
        self, populated, engine, settings: Settings
    ) -> None:
        """A configuration change needs a re-score, not fresh traffic."""
        from aegis.scoring.runner import assess_tenant

        prober = ScriptedProber({})
        result = assess_tenant(
            "acme", verify=False, prober=prober, settings=settings, engine=engine
        )

        assert prober.targets == []
        assert result.scoring.scored == 1
        assert result.verification.probed == 0

    def test_one_broken_tenant_does_not_stop_the_others(
        self, populated, control_session: Session, engine, settings: Settings
    ) -> None:
        from aegis.db.tenancy import drop_tenant_schema
        from aegis.scoring.runner import assess_all_tenants

        acme, _ = populated
        drop_tenant_schema(acme, engine=engine)

        results = {
            result.slug: result
            for result in assess_all_tenants(
                prober=ScriptedProber({"vpn.globex.example.com": _answering("7.4.1")}),
                settings=settings,
                engine=engine,
                force=True,
            )
        }

        assert not results["acme"].ok
        assert results["acme"].status is RunStatus.FAILED
        assert results["globex"].ok

    def test_scores_do_not_leak_between_tenants(
        self, populated, engine, settings: Settings
    ) -> None:
        from aegis.scoring.runner import assess_all_tenants
        from tests.conftest import session_for

        assess_all_tenants(
            prober=ScriptedProber(
                {
                    "vpn.acme.example.com": _answering("7.4.1"),
                    "vpn.globex.example.com": ProbeObservation(
                        target="stub", error="connection timed out"
                    ),
                }
            ),
            settings=settings,
            engine=engine,
            force=True,
        )

        for tenant, expected in zip(populated, (Tier.CRITICAL, Tier.MEDIUM), strict=True):
            tenant_db = session_for(tenant, engine)
            try:
                score = tenant_db.scalars(select(Score)).one()
                assert score.tier is expected
            finally:
                tenant_db.close()
