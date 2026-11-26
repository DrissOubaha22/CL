"""Feed contribution validation - spec §4.1, §4.2."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegis.core.enums import FeedSource
from aegis.intel.schemas import CpeRange, FeedContribution, SourceRef, normalise_cve_id

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def _contribution(**fields: object) -> FeedContribution:
    base: dict[str, object] = {
        "cve_id": "CVE-2026-104286",
        "source": FeedSource.CISA_KEV,
        "retrieved_at": NOW,
        "sources": [SourceRef(url="https://example.test/advisory")],
    }
    base.update(fields)
    return FeedContribution(**base)  # type: ignore[arg-type]


class TestCveId:
    def test_upper_cases_and_trims(self) -> None:
        assert normalise_cve_id("  cve-2026-104286 ") == "CVE-2026-104286"

    @pytest.mark.parametrize("value", ["CVE-2026-1", "NOTACVE", "CVE-26-1234", "", "CVE-2026"])
    def test_rejects_malformed_ids(self, value: str) -> None:
        """Spec §4.2: CVE ids are never invented, so a bad id is a rejection."""
        with pytest.raises(ValueError, match="malformed CVE id"):
            normalise_cve_id(value)


class TestFeedContribution:
    def test_requires_provenance(self) -> None:
        """Spec §4.2: unsourced claims are discarded."""
        with pytest.raises(ValidationError, match="no source URL"):
            FeedContribution(
                cve_id="CVE-2026-104286",
                source=FeedSource.NVD,
                retrieved_at=NOW,
            )

    def test_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            _contribution(not_a_field=True)

    @pytest.mark.parametrize(("field", "value"), [("epss", 1.5), ("cvss", 11.0)])
    def test_rejects_out_of_range_scores(self, field: str, value: float) -> None:
        with pytest.raises(ValidationError):
            _contribution(**{field: value})

    def test_drops_non_cwe_placeholders(self) -> None:
        """NVD emits NVD-CWE-noinfo for unmapped entries."""
        contribution = _contribution(cwe=["CWE-78", "NVD-CWE-noinfo", "cwe-78"])
        assert contribution.cwe == ["CWE-78"]

    def test_owned_payload_excludes_unasserted_fields(self) -> None:
        payload = _contribution(on_kev=True).owned_payload()
        assert payload == {"on_kev": True}

    def test_digest_ignores_retrieval_time(self) -> None:
        """Re-polling unchanged data must be a no-op (spec §4.1 poll + diff)."""
        first = _contribution(on_kev=True)
        later = _contribution(on_kev=True, retrieved_at=datetime(2026, 12, 1, tzinfo=UTC))
        assert first.digest() == later.digest()

    def test_digest_changes_with_the_facts(self) -> None:
        assert (
            _contribution(on_kev=True).digest()
            != _contribution(on_kev=True, ransomware=True).digest()
        )

    def test_digest_is_order_independent(self) -> None:
        a = _contribution(
            sources=[
                SourceRef(url="https://a.test"),
                SourceRef(url="https://b.test"),
            ]
        )
        b = _contribution(
            sources=[
                SourceRef(url="https://b.test"),
                SourceRef(url="https://a.test"),
            ]
        )
        assert a.digest() == b.digest()


class TestCpeRange:
    def test_canonicalises_the_cpe(self) -> None:
        entry = CpeRange(cpe="CPE:2.3:O:Fortinet:FortiOS:*:*:*:*:*:*:*:*")
        assert entry.cpe == "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"

    def test_rejects_a_malformed_cpe(self) -> None:
        with pytest.raises(ValidationError):
            CpeRange(cpe="fortios 7.4.2")

    def test_rejects_two_lower_bounds(self) -> None:
        with pytest.raises(ValidationError, match="two lower bounds"):
            CpeRange(
                cpe="cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                version_start_including="1.0",
                version_start_excluding="1.0",
            )

    def test_rejects_exact_version_combined_with_bounds(self) -> None:
        with pytest.raises(ValidationError, match="cannot be combined"):
            CpeRange(
                cpe="cpe:2.3:a:v:p:*:*:*:*:*:*:*:*",
                version_exact="1.0",
                version_end_excluding="2.0",
            )

    def test_detects_an_unbounded_range(self) -> None:
        assert CpeRange(cpe="cpe:2.3:a:v:p:*:*:*:*:*:*:*:*").is_unbounded
        assert not CpeRange(
            cpe="cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", version_end_excluding="2.0"
        ).is_unbounded
