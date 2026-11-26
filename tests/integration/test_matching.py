"""The matching engine end to end - spec §5, and the phase-2 criterion of §14.

"Matches produced per tenant, pre-plugin": intel the client already had, in
software the client already ran, matched before any scanner ships a detection
plugin for it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from aegis.core.enums import (
    Criticality,
    FeedSource,
    MatchConfidence,
    MatchFlag,
    RunStatus,
)
from aegis.db.models import Match, MatchRun, Tenant
from aegis.intel.schemas import CpeRange, FeedContribution, SourceRef
from aegis.intel.store import apply_contributions
from aegis.inventory.schemas import DiscoveryEvidence, InventoryItem, InventorySource
from aegis.inventory.store import import_inventory
from aegis.matching.engine import reset_context_cache, run_matching
from tests.conftest import requires_db, session_for

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
FORTIOS_CVE = "CVE-2024-21762"
LOG4J_CVE = "CVE-2021-44228"


@pytest.fixture(autouse=True)
def _clear_context_cache() -> None:
    reset_context_cache()


def _intel(cve_id: str, source: FeedSource, **fields: object) -> FeedContribution:
    return FeedContribution(
        cve_id=cve_id,
        source=source,
        retrieved_at=NOW,
        sources=[SourceRef(url=f"https://{source}.test/{cve_id}")],
        **fields,  # type: ignore[arg-type]
    )


@pytest.fixture
def advisories(session: Session) -> None:
    """A KEV-listed appliance CVE and a distro-packaged library CVE."""
    apply_contributions(
        session,
        [
            _intel(FORTIOS_CVE, FeedSource.CISA_KEV, on_kev=True, ransomware=True),
            _intel(
                FORTIOS_CVE,
                FeedSource.NVD,
                cvss=9.8,
                affected_cpes=[
                    CpeRange(
                        cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                        version_start_including="7.4.0",
                        version_end_excluding="7.4.3",
                    )
                ],
            ),
            _intel(
                LOG4J_CVE,
                FeedSource.NVD,
                cvss=10.0,
                affected_cpes=[
                    CpeRange(
                        cpe="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                        version_start_including="2.0",
                        version_end_excluding="2.15.0",
                    )
                ],
            ),
        ],
    )
    session.commit()


def _item(**overrides: object) -> InventoryItem:
    fields: dict[str, object] = {
        "hostname": "vpn.acme.test",
        "product": "FortiOS",
        "version": "7.4.1",
        "evidence": DiscoveryEvidence.ANSWERED_PUBLICLY,
        "source": InventorySource.ASM,
        "criticality": Criticality.HIGH,
    }
    fields.update(overrides)
    return InventoryItem(**fields)  # type: ignore[arg-type]


def _load(session: Session, *items: InventoryItem, at: datetime = NOW) -> None:
    import_inventory(session, list(items), observed_at=at)
    session.commit()


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


class TestMatching:
    def test_a_vulnerable_version_matches(self, advisories: None, tenant_session: Session) -> None:
        _load(tenant_session, _item(version="7.4.1"))

        outcome = run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert outcome.ok
        assert outcome.matches_new == 1
        match = tenant_session.scalars(select(Match)).one()
        assert match.cve_id == FORTIOS_CVE
        assert match.matched_range == ">=7.4.0 <7.4.3"
        assert match.matched_version == "7.4.1"

    def test_a_version_outside_the_range_does_not_match(
        self, advisories: None, tenant_session: Session
    ) -> None:
        """The boundary case string comparison gets wrong."""
        _load(tenant_session, _item(version="7.4.3"), _item(hostname="b", version="7.4.10"))

        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert _count(tenant_session, Match) == 0

    def test_a_different_product_does_not_match(
        self, advisories: None, tenant_session: Session
    ) -> None:
        _load(tenant_session, _item(product="FortiMail", version="7.4.1"))

        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert _count(tenant_session, Match) == 0

    def test_internet_facing_appliance_match_is_high_confidence(
        self, advisories: None, tenant_session: Session
    ) -> None:
        _load(tenant_session, _item())
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        match = tenant_session.scalars(select(Match)).one()
        assert match.confidence is MatchConfidence.HIGH

    def test_every_match_starts_unverified(self, advisories: None, tenant_session: Session) -> None:
        """Spec §5.3 verification gate."""
        _load(tenant_session, _item())
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        match = tenant_session.scalars(select(Match)).one()
        assert str(MatchFlag.UNVERIFIED) in match.flags

    def test_distro_package_match_is_flagged_and_low(
        self, advisories: None, tenant_session: Session
    ) -> None:
        """Spec §5.3 backport awareness."""
        _load(
            tenant_session,
            _item(
                hostname="app1.acme.test",
                product="log4j",
                version="2.14.1",
                from_distro_package=True,
                evidence=DiscoveryEvidence.SEEN_INTERNALLY,
            ),
        )
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        match = tenant_session.scalars(select(Match)).one()
        assert match.cve_id == LOG4J_CVE
        assert match.confidence is MatchConfidence.LOW
        assert str(MatchFlag.BACKPORT) in match.flags

    def test_internal_exposure_caps_confidence(
        self, advisories: None, tenant_session: Session
    ) -> None:
        _load(
            tenant_session,
            _item(hostname="lab.acme.test", evidence=DiscoveryEvidence.SEEN_INTERNALLY),
        )
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert tenant_session.scalars(select(Match)).one().confidence is MatchConfidence.MEDIUM

    def test_retired_assets_are_not_matched(
        self, advisories: None, tenant_session: Session
    ) -> None:
        from aegis.db.models import Asset

        _load(tenant_session, _item())
        asset = tenant_session.scalars(select(Asset)).one()
        asset.retired_at = NOW
        tenant_session.commit()

        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert _count(tenant_session, Match) == 0

    def test_an_asset_without_a_version_is_flagged_not_guessed(
        self, advisories: None, tenant_session: Session
    ) -> None:
        """Spec §5.2: an unorderable version downgrades, it does not decide."""
        _load(tenant_session, _item(version=None))

        outcome = run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        match = tenant_session.scalars(select(Match)).one()
        assert match.confidence is MatchConfidence.LOW
        assert str(MatchFlag.UNPARSEABLE_VERSION) in match.flags
        assert outcome.skipped_unparseable == 1

    def test_non_vulnerable_advisory_nodes_do_not_produce_matches(
        self, session: Session, tenant_session: Session
    ) -> None:
        """A ``vulnerable: false`` cpeMatch is platform context, not a target."""
        apply_contributions(
            session,
            [
                _intel(
                    "CVE-2026-500001",
                    FeedSource.NVD,
                    cvss=7.0,
                    affected_cpes=[
                        CpeRange(
                            cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                            vulnerable=False,
                        )
                    ],
                )
            ],
        )
        session.commit()

        _load(tenant_session, _item())
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert _count(tenant_session, Match) == 0

    def test_context_nodes_flag_config_dependence(
        self, session: Session, tenant_session: Session
    ) -> None:
        """Spec §5.3: an advisory describing a combination is config-dependent."""
        apply_contributions(
            session,
            [
                _intel(
                    "CVE-2026-500002",
                    FeedSource.NVD,
                    cvss=8.0,
                    affected_cpes=[
                        CpeRange(
                            cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                            version_end_excluding="7.5.0",
                        ),
                        CpeRange(
                            cpe="cpe:2.3:h:fortinet:fortigate_600e:-:*:*:*:*:*:*:*",
                            vulnerable=False,
                        ),
                    ],
                )
            ],
        )
        session.commit()

        _load(tenant_session, _item())
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        match = tenant_session.scalars(select(Match).where(Match.cve_id == "CVE-2026-500002")).one()
        assert str(MatchFlag.CONFIG_DEPENDENT) in match.flags
        assert match.confidence is MatchConfidence.MEDIUM


class TestLifecycle:
    def test_re_running_produces_no_new_matches(
        self, advisories: None, tenant_session: Session
    ) -> None:
        _load(tenant_session, _item())
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        second = run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert second.matches_new == 0
        assert second.matches_open == 1
        assert _count(tenant_session, Match) == 1

    def test_patching_an_asset_resolves_its_match(
        self, advisories: None, tenant_session: Session
    ) -> None:
        """The whole point of the cycle: a fixed host stops being a finding."""
        _load(tenant_session, _item(version="7.4.1"))
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()
        assert tenant_session.scalars(select(Match)).one().is_open

        _load(tenant_session, _item(version="7.4.7"))
        outcome = run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        assert outcome.matches_resolved == 1
        assert outcome.matches_open == 0
        match = tenant_session.scalars(select(Match)).one()
        assert not match.is_open
        assert match.resolved_at is not None

    def test_a_regression_reopens_the_match(
        self, advisories: None, tenant_session: Session
    ) -> None:
        _load(tenant_session, _item(version="7.4.1"))
        run_matching(tenant_session, now=NOW)
        _load(tenant_session, _item(version="7.4.7"))
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        _load(tenant_session, _item(version="7.4.1"))
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        match = tenant_session.scalars(select(Match)).one()
        assert match.is_open

    def test_the_run_is_journalled(self, advisories: None, tenant_session: Session) -> None:
        _load(tenant_session, _item())
        run_matching(tenant_session, now=NOW)
        tenant_session.commit()

        run = tenant_session.scalars(select(MatchRun)).one()
        assert run.status is RunStatus.SUCCESS
        assert run.assets_considered == 1
        assert run.matches_new == 1
        assert run.finished_at is not None

    def test_new_cve_ids_are_reported_for_the_delta(
        self, advisories: None, tenant_session: Session
    ) -> None:
        """Spec §10 step 6: what has just become a finding."""
        _load(tenant_session, _item())
        outcome = run_matching(tenant_session, now=NOW)
        tenant_session.commit()
        assert outcome.new_cve_ids == [FORTIOS_CVE]

    def test_restricting_to_cve_ids_skips_the_rest(
        self, advisories: None, tenant_session: Session
    ) -> None:
        """New intel re-matches only the CVEs that changed."""
        _load(
            tenant_session,
            _item(),
            _item(
                hostname="app1.acme.test",
                product="log4j",
                version="2.14.1",
                evidence=DiscoveryEvidence.SEEN_INTERNALLY,
            ),
        )

        run_matching(tenant_session, cve_ids=[LOG4J_CVE], now=NOW)
        tenant_session.commit()

        cve_ids = {m.cve_id for m in tenant_session.scalars(select(Match))}
        assert cve_ids == {LOG4J_CVE}


class TestPerTenant:
    def test_matches_do_not_leak_between_tenants(
        self,
        session: Session,
        two_tenants: tuple[Tenant, Tenant],
        engine: Engine,
    ) -> None:
        """Both tenants run the same vulnerable product; neither sees the other."""
        apply_contributions(
            session,
            [
                _intel(FORTIOS_CVE, FeedSource.CISA_KEV, on_kev=True),
                _intel(
                    FORTIOS_CVE,
                    FeedSource.NVD,
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

        acme, globex = two_tenants
        acme_session = session_for(acme, engine)
        globex_session = session_for(globex, engine)
        try:
            _load(acme_session, _item(hostname="vpn.acme.test"))
            _load(globex_session, _item(hostname="vpn.globex.test"))

            run_matching(acme_session, now=NOW)
            acme_session.commit()
            run_matching(globex_session, now=NOW)
            globex_session.commit()

            acme_hosts = [m.asset.hostname for m in acme_session.scalars(select(Match))]
            globex_hosts = [m.asset.hostname for m in globex_session.scalars(select(Match))]
            assert acme_hosts == ["vpn.acme.test"]
            assert globex_hosts == ["vpn.globex.test"]
        finally:
            acme_session.close()
            globex_session.close()

    def test_the_shared_intel_store_is_read_by_both(
        self,
        session: Session,
        two_tenants: tuple[Tenant, Tenant],
        engine: Engine,
    ) -> None:
        """Intel is collected once per CVE and shared (spec §2)."""
        apply_contributions(
            session,
            [
                _intel(
                    FORTIOS_CVE,
                    FeedSource.NVD,
                    cvss=9.8,
                    affected_cpes=[
                        CpeRange(
                            cpe="cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                            version_end_excluding="7.4.3",
                        )
                    ],
                )
            ],
        )
        session.commit()

        for tenant in two_tenants:
            tenant_db = session_for(tenant, engine)
            try:
                _load(tenant_db, _item(hostname=f"vpn.{tenant.slug}.test"))
                outcome = run_matching(tenant_db, now=NOW)
                tenant_db.commit()
                assert outcome.matches_new == 1
            finally:
                tenant_db.close()


class TestRunner:
    """Per-tenant orchestration (``aegis.matching.runner``)."""

    @pytest.fixture
    def populated(
        self,
        session: Session,
        two_tenants: tuple[Tenant, Tenant],
        engine: Engine,
    ) -> tuple[Tenant, Tenant]:
        apply_contributions(
            session,
            [
                _intel(FORTIOS_CVE, FeedSource.CISA_KEV, on_kev=True),
                _intel(
                    FORTIOS_CVE,
                    FeedSource.NVD,
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

        for tenant in two_tenants:
            tenant_db = session_for(tenant, engine)
            try:
                _load(tenant_db, _item(hostname=f"vpn.{tenant.slug}.test"))
            finally:
                tenant_db.close()
        return two_tenants

    def test_matches_every_active_tenant(
        self, populated: tuple[Tenant, Tenant], engine: Engine
    ) -> None:
        from aegis.matching.runner import match_all_tenants

        results = match_all_tenants(engine=engine)

        assert {result.slug for result in results} == {"acme", "globex"}
        assert all(result.ok for result in results)
        assert all(result.outcome.matches_new == 1 for result in results)

    def test_can_be_restricted_to_some_tenants(
        self, populated: tuple[Tenant, Tenant], engine: Engine
    ) -> None:
        from aegis.matching.runner import match_all_tenants

        results = match_all_tenants(slugs=["acme"], engine=engine)
        assert [result.slug for result in results] == ["acme"]

    def test_deactivated_tenants_are_skipped(
        self,
        populated: tuple[Tenant, Tenant],
        control_session: Session,
        engine: Engine,
    ) -> None:
        from aegis.matching.runner import match_all_tenants

        acme, _ = populated
        acme.active = False
        control_session.commit()

        results = match_all_tenants(engine=engine)
        assert [result.slug for result in results] == ["globex"]

    def test_one_broken_tenant_does_not_stop_the_others(
        self,
        populated: tuple[Tenant, Tenant],
        control_session: Session,
        engine: Engine,
    ) -> None:
        """Isolated schemas mean a failure is contained to that tenant."""
        from aegis.db.tenancy import drop_tenant_schema
        from aegis.matching.runner import match_all_tenants

        acme, _ = populated
        drop_tenant_schema(acme, engine=engine)

        results = {result.slug: result for result in match_all_tenants(engine=engine)}

        assert not results["acme"].ok
        assert results["acme"].outcome.status is RunStatus.FAILED
        assert results["globex"].ok
        assert results["globex"].outcome.matches_new == 1

    def test_match_tenant_accepts_a_slug(
        self, populated: tuple[Tenant, Tenant], engine: Engine
    ) -> None:
        from aegis.matching.runner import match_tenant as run_for_tenant

        result = run_for_tenant("acme", engine=engine)
        assert result.ok
        assert result.outcome.matches_new == 1
