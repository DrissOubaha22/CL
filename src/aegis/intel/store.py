"""Writing contributions into the shared intel store (spec §4.1, §9).

The write path is deliberately narrow:

1. A pipeline hands over validated :class:`FeedContribution` objects.
2. :func:`apply_contributions` stores each as an ``intel_contribution`` row,
   replacing that source's provenance and affected-CPE rows.
3. Every touched CVE is re-derived into its ``intel_record``.

Unchanged contributions are detected by content digest and skipped, which is
what makes the scheduled poll of spec §4.1 cheap and the whole path
idempotent.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from aegis.core.cpe import InvalidCpe, parse_cpe
from aegis.core.enums import FeedSource
from aegis.db.models import (
    AffectedCpe,
    IntelContribution,
    IntelRecord,
    IntelSource,
)
from aegis.intel.derive import merge_contributions
from aegis.intel.schemas import CpeRange, FeedContribution

log = structlog.get_logger(__name__)

__all__ = ["UpsertResult", "apply_contributions", "rebuild_records"]


@dataclass(slots=True)
class UpsertResult:
    """Outcome of applying a batch of contributions."""

    seen: int = 0
    changed: int = 0
    rejected: int = 0
    rebuilt: int = 0
    rejections: list[tuple[str, str]] = field(default_factory=list)

    def reject(self, cve_id: str, reason: str) -> None:
        self.rejected += 1
        self.rejections.append((cve_id, reason))


def apply_contributions(
    session: Session,
    contributions: Iterable[FeedContribution],
    *,
    rebuild: bool = True,
) -> UpsertResult:
    """Persist ``contributions`` and re-derive the records they touch.

    Args:
        session: An open session; the caller owns the transaction.
        contributions: Validated contributions, which may span many CVEs but
            typically come from a single source.
        rebuild: Re-derive the affected ``intel_record`` rows before
            returning.  Only set ``False`` when the caller will call
            :func:`rebuild_records` itself after further writes.

    Returns:
        Counts of rows seen, changed and rejected.
    """
    batch = list(contributions)
    result = UpsertResult(seen=len(batch))
    if not batch:
        return result

    cve_ids = {item.cve_id for item in batch}
    existing_records = _load_records(session, cve_ids)
    existing_contributions = _load_contributions(session, cve_ids)

    changed_cve_ids: set[str] = set()

    for contribution in batch:
        cve_id = contribution.cve_id
        digest = contribution.digest()
        key = (cve_id, contribution.source)
        previous = existing_contributions.get(key)

        if previous is not None and previous.payload_digest == digest:
            # Same facts as last poll: refresh only the retrieval timestamp.
            previous.retrieved_at = contribution.retrieved_at
            continue

        record = existing_records.get(cve_id)
        if record is None:
            record = IntelRecord(cve_id=cve_id)
            session.add(record)
            existing_records[cve_id] = record
            # Make the parent row visible to the FK checks below.
            session.flush()

        if previous is None:
            previous = IntelContribution(
                cve_id=cve_id,
                source=contribution.source,
                payload=contribution.owned_payload(),
                payload_digest=digest,
                retrieved_at=contribution.retrieved_at,
            )
            session.add(previous)
            existing_contributions[key] = previous
        else:
            previous.payload = contribution.owned_payload()
            previous.payload_digest = digest
            previous.retrieved_at = contribution.retrieved_at

        _replace_sources(session, contribution)
        _replace_affected_cpes(session, contribution, result)

        changed_cve_ids.add(cve_id)

    result.changed = len(changed_cve_ids)
    session.flush()

    if rebuild and changed_cve_ids:
        result.rebuilt = rebuild_records(session, changed_cve_ids)

    log.info(
        "intel.contributions_applied",
        seen=result.seen,
        changed=result.changed,
        rejected=result.rejected,
    )
    return result


def rebuild_records(session: Session, cve_ids: Iterable[str]) -> int:
    """Re-derive ``intel_record`` from the stored contributions.

    Returns:
        The number of records rewritten.
    """
    ids = sorted(set(cve_ids))
    if not ids:
        return 0

    records = _load_records(session, ids)
    contributions = _load_contributions(session, ids)

    by_cve: dict[str, list[tuple[FeedSource, dict[str, Any]]]] = {cve_id: [] for cve_id in ids}
    for (cve_id, source), contribution in contributions.items():
        by_cve.setdefault(cve_id, []).append((source, contribution.payload or {}))

    now = datetime.now(UTC)
    rewritten = 0
    for cve_id in ids:
        record = records.get(cve_id)
        if record is None:
            # Nothing to derive onto: the CVE has no contributions left.
            continue
        derived = merge_contributions(cve_id, by_cve.get(cve_id, []))
        record.exploit_status = derived.exploit_status
        record.on_kev = derived.on_kev
        record.vendor_confirmed = derived.vendor_confirmed
        record.public_exploit = derived.public_exploit
        record.ransomware = derived.ransomware
        record.kev_due = derived.kev_due
        record.kev_date_added = derived.kev_date_added
        record.epss = derived.epss
        record.epss_percentile = derived.epss_percentile
        record.cvss = derived.cvss
        record.cvss_vector = derived.cvss_vector
        record.cwe = derived.cwe
        record.patch_available = derived.patch_available
        record.config_dependent = derived.config_dependent
        record.title = derived.title
        record.description = derived.description
        record.published_at = derived.published_at
        record.last_modified_at = derived.last_modified_at
        record.as_of = now
        rewritten += 1

    session.flush()
    return rewritten


def retract_source(session: Session, source: FeedSource, cve_ids: Iterable[str]) -> int:
    """Drop ``source``'s contributions for ``cve_ids`` and re-derive.

    Used when a feed stops asserting a CVE it previously listed - a CISA KEV
    removal, for instance.  Because the record is derived, the fact
    disappears instead of persisting unsourced.
    """
    ids = sorted(set(cve_ids))
    if not ids:
        return 0

    for model in (IntelContribution, IntelSource, AffectedCpe):
        session.execute(delete(model).where(model.source == source, model.cve_id.in_(ids)))
    session.flush()
    rebuild_records(session, ids)
    log.info("intel.source_retracted", source=str(source), count=len(ids))
    return len(ids)


# --------------------------------------------------------------------------
# internals
# --------------------------------------------------------------------------


def _load_records(session: Session, cve_ids: Iterable[str]) -> dict[str, IntelRecord]:
    ids = list(cve_ids)
    if not ids:
        return {}
    rows = session.scalars(select(IntelRecord).where(IntelRecord.cve_id.in_(ids))).all()
    return {row.cve_id: row for row in rows}


def _load_contributions(
    session: Session, cve_ids: Iterable[str]
) -> dict[tuple[str, FeedSource], IntelContribution]:
    ids = list(cve_ids)
    if not ids:
        return {}
    rows = session.scalars(select(IntelContribution).where(IntelContribution.cve_id.in_(ids))).all()
    return {(row.cve_id, FeedSource(row.source)): row for row in rows}


def _replace_sources(session: Session, contribution: FeedContribution) -> None:
    """Swap this source's citations for the ones just retrieved."""
    session.execute(
        delete(IntelSource).where(
            IntelSource.cve_id == contribution.cve_id,
            IntelSource.source == contribution.source,
        )
    )
    seen: set[tuple[str | None, str]] = set()
    for ref in contribution.sources:
        key = (ref.field, ref.url)
        if key in seen:
            continue
        seen.add(key)
        session.add(
            IntelSource(
                cve_id=contribution.cve_id,
                source=contribution.source,
                field=ref.field,
                url=ref.url,
                quote=ref.quote,
                retrieved_at=contribution.retrieved_at,
            )
        )


def _replace_affected_cpes(
    session: Session, contribution: FeedContribution, result: UpsertResult
) -> None:
    """Swap this source's affected-product rows for the ones just retrieved.

    Scoping the delete by source means a feed that carries no CPE data (EPSS,
    for one) never clears the ranges another feed published.
    """
    if not contribution.affected_cpes:
        return

    session.execute(
        delete(AffectedCpe).where(
            AffectedCpe.cve_id == contribution.cve_id,
            AffectedCpe.source == contribution.source,
        )
    )
    for row in _affected_rows(contribution, result):
        session.add(row)


def _affected_rows(contribution: FeedContribution, result: UpsertResult) -> Sequence[AffectedCpe]:
    rows: list[AffectedCpe] = []
    seen: set[tuple[Any, ...]] = set()

    for entry in contribution.affected_cpes:
        try:
            parsed = parse_cpe(entry.cpe)
        except InvalidCpe as exc:
            # Validation already ran in the schema; reaching here means a
            # stored string we can no longer parse. Drop it rather than
            # poison the matcher.
            result.reject(contribution.cve_id, f"unparseable CPE: {exc}")
            continue

        version_exact = _exact_version(entry, parsed.version)
        key = (
            parsed.without_version().to_string(),
            version_exact,
            entry.version_start_including,
            entry.version_start_excluding,
            entry.version_end_including,
            entry.version_end_excluding,
        )
        if key in seen:
            continue
        seen.add(key)

        rows.append(
            AffectedCpe(
                cve_id=contribution.cve_id,
                source=contribution.source,
                cpe=parsed.to_string(),
                part=parsed.part,
                vendor=parsed.vendor,
                product=parsed.product,
                target_sw=None if parsed.target_sw == "*" else parsed.target_sw,
                version_exact=version_exact,
                version_start_including=entry.version_start_including,
                version_start_excluding=entry.version_start_excluding,
                version_end_including=entry.version_end_including,
                version_end_excluding=entry.version_end_excluding,
                vulnerable=entry.vulnerable,
            )
        )
    return rows


def _exact_version(entry: CpeRange, cpe_version: str) -> str | None:
    """Resolve the single-version form of an affected entry.

    NVD states an exact version either as a bound-free ``cpeMatch`` whose CPE
    carries the version, or explicitly; both collapse to ``version_exact``.
    """
    if entry.version_exact:
        return entry.version_exact
    if entry.is_unbounded and cpe_version not in ("*", "-"):
        return cpe_version
    return None
