"""Merging and exploitation derivation - spec §7.1, §7.2."""

from __future__ import annotations

from datetime import date

import pytest

from aegis.core.enums import ExploitStatus, FeedSource
from aegis.intel.derive import (
    FIELD_OWNERS,
    derive_exploit_status,
    merge_contributions,
)


class TestDeriveExploitStatus:
    def test_kev_listing_is_active(self) -> None:
        assert derive_exploit_status(on_kev=True, vendor_confirmed=False) is ExploitStatus.ACTIVE

    def test_vendor_confirmation_is_active_before_cisa_lists_it(self) -> None:
        """Spec §7.2: a PSIRT advisory is treated as KEV-equivalent."""
        assert derive_exploit_status(on_kev=False, vendor_confirmed=True) is ExploitStatus.ACTIVE

    def test_third_party_in_the_wild_report_is_active(self) -> None:
        assert (
            derive_exploit_status(on_kev=False, vendor_confirmed=False, exploited_in_wild=True)
            is ExploitStatus.ACTIVE
        )

    def test_public_exploit_alone_is_only_poc(self) -> None:
        assert (
            derive_exploit_status(on_kev=False, vendor_confirmed=False, public_exploit=True)
            is ExploitStatus.POC
        )

    def test_no_evidence_is_none(self) -> None:
        assert derive_exploit_status(on_kev=False, vendor_confirmed=False) is ExploitStatus.NONE

    def test_in_the_wild_outranks_public_exploit(self) -> None:
        assert (
            derive_exploit_status(on_kev=True, vendor_confirmed=False, public_exploit=True)
            is ExploitStatus.ACTIVE
        )


class TestMergeContributions:
    def test_merges_across_sources(self) -> None:
        merged = merge_contributions(
            "CVE-2026-104286",
            [
                (
                    FeedSource.CISA_KEV,
                    {
                        "on_kev": True,
                        "ransomware": True,
                        "kev_due": "2026-12-01",
                        "kev_date_added": "2026-11-10",
                    },
                ),
                (FeedSource.FIRST_EPSS, {"epss": 0.94, "epss_percentile": 0.99}),
                (FeedSource.NVD, {"cvss": 9.8, "cwe": ["CWE-78"]}),
            ],
        )
        assert merged.exploit_status is ExploitStatus.ACTIVE
        assert merged.on_kev is True
        assert merged.ransomware is True
        assert merged.kev_due == date(2026, 12, 1)
        assert merged.kev_date_added == date(2026, 11, 10)
        assert merged.epss == pytest.approx(0.94)
        assert merged.cvss == pytest.approx(9.8)
        assert merged.cwe == ["CWE-78"]

    def test_a_source_cannot_write_a_field_it_does_not_own(self) -> None:
        """A feed drifting outside its remit must not overwrite better data."""
        merged = merge_contributions(
            "CVE-2026-1",
            [
                (FeedSource.FIRST_EPSS, {"epss": 0.94}),
                (FeedSource.NVD, {"epss": 0.01, "on_kev": True}),
            ],
        )
        assert merged.epss == pytest.approx(0.94)
        assert merged.on_kev is False
        assert merged.exploit_status is ExploitStatus.NONE

    def test_public_exploit_is_additive_across_sources(self) -> None:
        """One source proving exploit code exists is not cancelled by silence."""
        merged = merge_contributions(
            "CVE-2026-2",
            [
                (FeedSource.EXPLOIT_DB, {"public_exploit": True}),
                (FeedSource.NUCLEI, {"public_exploit": False}),
            ],
        )
        assert merged.public_exploit is True
        assert merged.exploit_status is ExploitStatus.POC

    def test_precedence_within_a_shared_field(self) -> None:
        """patch_available: a vendor advisory outranks an NVD reference tag."""
        merged = merge_contributions(
            "CVE-2026-3",
            [
                (FeedSource.NVD, {"patch_available": False}),
                (FeedSource.PSIRT, {"patch_available": True}),
            ],
        )
        assert merged.patch_available is True

    def test_empty_contributions_derive_an_empty_record(self) -> None:
        merged = merge_contributions("CVE-2026-4", [])
        assert merged.exploit_status is ExploitStatus.NONE
        assert merged.cvss is None
        assert merged.cwe == []

    def test_every_owned_field_exists_on_the_derived_record(self) -> None:
        """Guards against a field being owned but silently never merged."""
        merged = merge_contributions("CVE-2026-5", [])
        for name in FIELD_OWNERS:
            assert hasattr(merged, name), f"{name} is owned but not derived"
