"""Inventory ingestion against a live database - spec §3.2, §3.3."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.core.enums import (
    Criticality,
    ExposureClass,
    MatchConfidence,
    ProductClass,
)
from aegis.db.models import Asset, AssetCpe
from aegis.inventory.schemas import DiscoveryEvidence, InventoryItem, InventorySource
from aegis.inventory.store import import_inventory, retire_unseen
from tests.conftest import requires_db

pytestmark = [pytest.mark.integration, requires_db]

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def appliance(**overrides: object) -> InventoryItem:
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


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


class TestImport:
    def test_creates_an_asset_with_derived_attributes(self, tenant_session: Session) -> None:
        result = import_inventory(tenant_session, [appliance()], observed_at=NOW)
        tenant_session.commit()

        assert (result.created, result.rejected) == (1, 0)
        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.product_class is ProductClass.APPLIANCE
        assert asset.exposure_class is ExposureClass.INTERNET
        assert asset.criticality is Criticality.HIGH
        assert asset.match_confidence is MatchConfidence.HIGH
        assert asset.version_is_clean is True
        assert asset.first_seen_at == NOW

    def test_resolves_the_product_to_cpe_rows(self, tenant_session: Session) -> None:
        import_inventory(tenant_session, [appliance()], observed_at=NOW)
        tenant_session.commit()

        cpe = tenant_session.scalars(select(AssetCpe)).one()
        assert cpe.vendor == "fortinet"
        assert cpe.product == "fortios"
        assert cpe.part == "o"

    def test_one_product_may_yield_several_cpe_rows(self, tenant_session: Session) -> None:
        """Spec §3.2: one or more CPE strings per discovered product."""
        import_inventory(
            tenant_session,
            [appliance(product="Apache HTTP Server", version="2.4.58")],
            observed_at=NOW,
        )
        tenant_session.commit()
        assert _count(tenant_session, AssetCpe) == 2

    def test_reimport_updates_rather_than_duplicating(self, tenant_session: Session) -> None:
        import_inventory(tenant_session, [appliance()], observed_at=NOW)
        tenant_session.commit()

        later = NOW + timedelta(days=1)
        result = import_inventory(tenant_session, [appliance()], observed_at=later)
        tenant_session.commit()

        assert (result.created, result.updated) == (0, 1)
        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.first_seen_at == NOW
        assert asset.last_seen_at == later

    def test_a_patched_host_updates_in_place(self, tenant_session: Session) -> None:
        """Asset identity is (host, product, port): a version bump is an update.

        If the version were part of the identity, patching would leave the
        vulnerable row behind and its matches open forever.
        """
        import_inventory(tenant_session, [appliance(version="7.4.1")], observed_at=NOW)
        tenant_session.commit()

        import_inventory(tenant_session, [appliance(version="7.4.7")], observed_at=NOW)
        tenant_session.commit()

        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.version == "7.4.7"
        assert _count(tenant_session, Asset) == 1

    def test_same_host_different_products_are_separate_assets(
        self, tenant_session: Session
    ) -> None:
        import_inventory(
            tenant_session,
            [
                appliance(hostname="srv1", product="nginx", version="1.24.0"),
                appliance(hostname="srv1", product="OpenSSH", version="9.3"),
            ],
            observed_at=NOW,
        )
        tenant_session.commit()
        assert _count(tenant_session, Asset) == 2

    def test_distro_package_is_classified_and_capped(self, tenant_session: Session) -> None:
        import_inventory(
            tenant_session,
            [
                appliance(
                    hostname="db1",
                    product="openssl",
                    version="3.0.2",
                    from_distro_package=True,
                    evidence=DiscoveryEvidence.SEEN_INTERNALLY,
                )
            ],
            observed_at=NOW,
        )
        tenant_session.commit()

        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.product_class is ProductClass.OS_PACKAGE
        assert asset.match_confidence is MatchConfidence.LOW

    def test_unorderable_version_is_kept_but_marked(self, tenant_session: Session) -> None:
        """Spec §5.2: keep it, flag it; do not drop the asset."""
        import_inventory(tenant_session, [appliance(version="latest")], observed_at=NOW)
        tenant_session.commit()

        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.version == "latest"
        assert asset.version_is_clean is False
        assert asset.match_confidence is MatchConfidence.LOW

    def test_a_guessed_identity_cannot_reach_high_confidence(self, tenant_session: Session) -> None:
        import_inventory(
            tenant_session,
            [appliance(product="Totally Unknown Widget", version="1.0")],
            observed_at=NOW,
        )
        tenant_session.commit()

        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.match_confidence.rank < MatchConfidence.HIGH.rank

    def test_empty_import_is_a_no_op(self, tenant_session: Session) -> None:
        result = import_inventory(tenant_session, [], observed_at=NOW)
        assert (result.seen, result.created) == (0, 0)

    def test_cpe_rows_are_replaced_not_accumulated(self, tenant_session: Session) -> None:
        """Re-resolution swaps the CPE set; stale spellings must not linger.

        The version is part of the CPE string, so a patched asset re-resolves
        to different CPEs - and the old ones have to go, or the matcher would
        keep joining against a version the host no longer runs.
        """
        import_inventory(
            tenant_session,
            [appliance(product="nginx", version="1.24.0", port=443)],
            observed_at=NOW,
        )
        tenant_session.commit()
        before = {row.cpe for row in tenant_session.scalars(select(AssetCpe))}
        assert all(":1.24.0:" in cpe for cpe in before)

        import_inventory(
            tenant_session,
            [appliance(product="nginx", version="1.26.0", port=443)],
            observed_at=NOW,
        )
        tenant_session.commit()

        after = {row.cpe for row in tenant_session.scalars(select(AssetCpe))}
        assert all(":1.26.0:" in cpe for cpe in after)
        assert len(after) == len(before), "the same product resolves to as many CPEs"
        assert after.isdisjoint(before)

    def test_repeated_imports_on_one_session_keep_cpes_correct(
        self, tenant_session: Session
    ) -> None:
        """Regression: a cached relationship must not stall the CPE sync.

        Sessions use ``expire_on_commit=False``, so ``asset.cpes`` loaded
        before a commit stays stale.  Trusting it made a re-import a no-op,
        leaving the asset advertising a version it no longer ran - and when
        that stale version was the *patched* one, the matcher joined on it
        and missed a real vulnerability.
        """
        for version in ("7.4.1", "7.4.7", "7.4.1"):
            import_inventory(tenant_session, [appliance(version=version)], observed_at=NOW)
            tenant_session.commit()

            cpes = {row.cpe for row in tenant_session.scalars(select(AssetCpe))}
            assert cpes == {f"cpe:2.3:o:fortinet:fortios:{version}:*:*:*:*:*:*:*"}, (
                f"CPE set is stale after importing {version}"
            )

    def test_supplied_cpes_add_to_rather_than_replace_known_spellings(
        self, tenant_session: Session
    ) -> None:
        """A scanner naming one spelling does not invalidate the others.

        NVD lists nginx under both ``nginx:nginx`` and ``f5:nginx``; keeping
        both is what stops a naming mismatch hiding a vulnerable asset.
        """
        import_inventory(
            tenant_session,
            [
                appliance(
                    product="nginx",
                    version="1.24.0",
                    cpes=["cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"],
                )
            ],
            observed_at=NOW,
        )
        tenant_session.commit()

        vendors = {row.vendor for row in tenant_session.scalars(select(AssetCpe))}
        assert vendors == {"nginx", "f5"}


class TestRetirement:
    def test_assets_a_pass_stopped_reporting_are_retired(self, tenant_session: Session) -> None:
        import_inventory(
            tenant_session,
            [appliance(hostname="gone.acme.test"), appliance()],
            observed_at=NOW,
        )
        tenant_session.commit()

        later = NOW + timedelta(hours=1)
        import_inventory(tenant_session, [appliance()], observed_at=later)
        tenant_session.commit()

        retired = retire_unseen(tenant_session, source="asm", before=later)
        tenant_session.commit()

        assert retired == 1
        gone = tenant_session.scalars(select(Asset).where(Asset.hostname == "gone.acme.test")).one()
        assert gone.retired_at is not None
        assert not gone.is_active

    def test_retirement_is_scoped_by_source(self, tenant_session: Session) -> None:
        """A scanner import must not retire what only ASM can see."""
        import_inventory(
            tenant_session,
            [
                appliance(hostname="asm-only.acme.test", source=InventorySource.ASM),
                appliance(
                    hostname="scanner-only.acme.test",
                    source=InventorySource.SCANNER,
                    evidence=DiscoveryEvidence.SEEN_INTERNALLY,
                ),
            ],
            observed_at=NOW,
        )
        tenant_session.commit()

        retired = retire_unseen(tenant_session, source="scanner", before=NOW + timedelta(hours=1))
        tenant_session.commit()

        assert retired == 1
        asm_asset = tenant_session.scalars(
            select(Asset).where(Asset.hostname == "asm-only.acme.test")
        ).one()
        assert asm_asset.retired_at is None

    def test_rediscovery_unretires(self, tenant_session: Session) -> None:
        import_inventory(tenant_session, [appliance()], observed_at=NOW)
        tenant_session.commit()
        retire_unseen(tenant_session, source="asm", before=NOW + timedelta(hours=1))
        tenant_session.commit()

        import_inventory(tenant_session, [appliance()], observed_at=NOW + timedelta(days=1))
        tenant_session.commit()

        asset = tenant_session.scalars(select(Asset)).one()
        assert asset.retired_at is None
