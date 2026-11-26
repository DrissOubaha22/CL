"""Store write path against a live PostgreSQL - spec §4.1, §9, §10 step 10."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.core.enums import ExploitStatus, FeedSource
from aegis.db.models import AffectedCpe, IntelContribution, IntelRecord, IntelSource
from aegis.intel.schemas import CpeRange, SourceRef
from aegis.intel.store import apply_contributions, rebuild_records, retract_source
from tests.conftest import make_contribution, requires_db

pytestmark = [pytest.mark.integration, requires_db]

CVE = "CVE-2026-104286"


def _count(session: Session, model: type) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


class TestApplyContributions:
    def test_creates_a_record_and_derives_exploit_status(self, session: Session) -> None:
        result = apply_contributions(
            session, [make_contribution(CVE, FeedSource.CISA_KEV, on_kev=True)]
        )
        session.commit()

        assert (result.seen, result.changed, result.rejected) == (1, 1, 0)
        record = session.get(IntelRecord, CVE)
        assert record is not None
        assert record.on_kev is True
        assert record.exploit_status is ExploitStatus.ACTIVE
        assert record.as_of is not None

    def test_stores_provenance_for_every_claim(self, session: Session) -> None:
        apply_contributions(
            session,
            [
                make_contribution(
                    CVE,
                    FeedSource.CISA_KEV,
                    on_kev=True,
                    sources=[
                        SourceRef(
                            url="https://cisa.test/kev",
                            field="on_kev",
                            quote="exploited in the wild",
                        )
                    ],
                )
            ],
        )
        session.commit()

        source = session.scalars(select(IntelSource)).one()
        assert source.cve_id == CVE
        assert source.quote == "exploited in the wild"
        assert source.retrieved_at is not None

    def test_reapplying_identical_facts_changes_nothing(self, session: Session) -> None:
        """Spec §4.1 poll + diff: an unchanged feed must be a no-op."""
        contribution = make_contribution(CVE, FeedSource.CISA_KEV, on_kev=True)
        apply_contributions(session, [contribution])
        session.commit()
        before = session.get(IntelRecord, CVE).as_of  # type: ignore[union-attr]

        again = make_contribution(
            CVE,
            FeedSource.CISA_KEV,
            on_kev=True,
            retrieved_at=datetime(2026, 12, 25, tzinfo=UTC),
        )
        result = apply_contributions(session, [again])
        session.commit()

        assert result.changed == 0
        session.refresh(session.get(IntelRecord, CVE))  # type: ignore[arg-type]
        assert session.get(IntelRecord, CVE).as_of == before  # type: ignore[union-attr]
        # The retrieval timestamp is still refreshed, so staleness is visible.
        contribution_row = session.scalars(select(IntelContribution)).one()
        assert contribution_row.retrieved_at.date() == datetime(2026, 12, 25).date()

    def test_changed_facts_update_the_record(self, session: Session) -> None:
        apply_contributions(session, [make_contribution(CVE, on_kev=True)])
        session.commit()

        apply_contributions(session, [make_contribution(CVE, on_kev=True, ransomware=True)])
        session.commit()

        record = session.get(IntelRecord, CVE)
        assert record is not None and record.ransomware is True
        assert _count(session, IntelContribution) == 1, "one row per source per CVE"

    def test_merges_sources_without_clobbering(self, session: Session) -> None:
        apply_contributions(
            session,
            [
                make_contribution(CVE, FeedSource.CISA_KEV, on_kev=True),
                make_contribution(CVE, FeedSource.FIRST_EPSS, epss=0.94),
                make_contribution(CVE, FeedSource.NVD, cvss=9.8, cwe=["CWE-78"]),
            ],
        )
        session.commit()

        record = session.get(IntelRecord, CVE)
        assert record is not None
        assert record.on_kev is True
        assert record.epss == pytest.approx(0.94)
        assert record.cvss == pytest.approx(9.8)
        assert record.cwe == ["CWE-78"]
        assert record.exploit_status is ExploitStatus.ACTIVE
        assert _count(session, IntelContribution) == 3

    def test_affected_cpes_are_denormalised_for_the_matcher(self, session: Session) -> None:
        apply_contributions(
            session,
            [
                make_contribution(
                    CVE,
                    FeedSource.NVD,
                    affected_cpes=[
                        CpeRange(
                            cpe="cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*",
                            version_start_including="7.4.0",
                            version_end_excluding="7.4.8",
                        ),
                        CpeRange(cpe="cpe:2.3:a:fortinet:fortimail:7.6.2:*:*:*:*:*:*:*"),
                    ],
                )
            ],
        )
        session.commit()

        rows = session.scalars(select(AffectedCpe).order_by(AffectedCpe.id)).all()
        assert len(rows) == 2
        assert rows[0].vendor == "fortinet" and rows[0].product == "fortimail"
        assert rows[0].version_start_including == "7.4.0"
        # A bound-free CPE carrying a version collapses to version_exact.
        assert rows[1].version_exact == "7.6.2"

    def test_a_feed_without_cpes_does_not_clear_another_feeds_cpes(self, session: Session) -> None:
        """EPSS carries no product data; it must not wipe NVD's ranges."""
        apply_contributions(
            session,
            [
                make_contribution(
                    CVE,
                    FeedSource.NVD,
                    affected_cpes=[CpeRange(cpe="cpe:2.3:a:fortinet:fortimail:*:*:*:*:*:*:*:*")],
                )
            ],
        )
        session.commit()

        apply_contributions(session, [make_contribution(CVE, FeedSource.FIRST_EPSS, epss=0.5)])
        session.commit()

        assert _count(session, AffectedCpe) == 1

    def test_re_running_a_feed_replaces_only_its_own_cpes(self, session: Session) -> None:
        def nvd_with(cpe: str):
            return make_contribution(CVE, FeedSource.NVD, affected_cpes=[CpeRange(cpe=cpe)])

        apply_contributions(session, [nvd_with("cpe:2.3:a:fortinet:fortimail:7.4.0:*:*:*:*:*:*:*")])
        session.commit()
        apply_contributions(session, [nvd_with("cpe:2.3:a:fortinet:fortimail:7.4.1:*:*:*:*:*:*:*")])
        session.commit()

        rows = session.scalars(select(AffectedCpe)).all()
        assert len(rows) == 1
        assert rows[0].version_exact == "7.4.1"

    def test_empty_batch_is_a_no_op(self, session: Session) -> None:
        result = apply_contributions(session, [])
        assert (result.seen, result.changed) == (0, 0)
        assert _count(session, IntelRecord) == 0


class TestRetraction:
    def test_dropping_a_source_clears_the_facts_it_alone_asserted(self, session: Session) -> None:
        """A CISA KEV delisting must not leave an unsourced claim behind."""
        apply_contributions(
            session,
            [
                make_contribution(CVE, FeedSource.CISA_KEV, on_kev=True),
                make_contribution(CVE, FeedSource.NVD, cvss=9.8),
            ],
        )
        session.commit()
        assert session.get(IntelRecord, CVE).on_kev is True  # type: ignore[union-attr]

        retract_source(session, FeedSource.CISA_KEV, [CVE])
        session.commit()

        record = session.get(IntelRecord, CVE)
        assert record is not None
        assert record.on_kev is False
        assert record.exploit_status is ExploitStatus.NONE
        # Facts from the other source survive.
        assert record.cvss == pytest.approx(9.8)
        assert _count(session, IntelContribution) == 1

    def test_retraction_removes_that_sources_provenance(self, session: Session) -> None:
        apply_contributions(session, [make_contribution(CVE, FeedSource.CISA_KEV, on_kev=True)])
        session.commit()
        retract_source(session, FeedSource.CISA_KEV, [CVE])
        session.commit()
        assert _count(session, IntelSource) == 0


class TestRebuild:
    def test_rebuild_is_deterministic(self, session: Session) -> None:
        """Spec §10 step 10: refresh must not drift the record."""
        apply_contributions(
            session,
            [
                make_contribution(CVE, FeedSource.CISA_KEV, on_kev=True),
                make_contribution(CVE, FeedSource.FIRST_EPSS, epss=0.94),
            ],
        )
        session.commit()
        first = session.get(IntelRecord, CVE)
        snapshot = (first.exploit_status, first.on_kev, first.epss)  # type: ignore[union-attr]

        rebuild_records(session, [CVE])
        session.commit()

        again = session.get(IntelRecord, CVE)
        assert (again.exploit_status, again.on_kev, again.epss) == snapshot  # type: ignore[union-attr]

    def test_rebuilding_an_unknown_cve_is_harmless(self, session: Session) -> None:
        assert rebuild_records(session, ["CVE-2026-999999"]) == 0
