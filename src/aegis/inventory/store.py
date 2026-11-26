"""Writing inventory into a tenant's store (spec §3.2, §3.3).

Takes validated :class:`~aegis.inventory.schemas.InventoryItem` objects and
upserts assets into the tenant schema the session is bound to.  Along the
way each asset acquires the three attributes the matcher needs:

* ``product_class`` - what kind of software it is (spec §3.3).
* ``exposure_class`` - derived from discovery evidence (spec §3.2).
* ``match_confidence`` - how far a match on it can be trusted (spec §5.3).

Re-importing the same inventory is idempotent; it refreshes ``last_seen_at``
and nothing else.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.core.classification import classify_product, match_confidence
from aegis.core.cpe import parse_cpe
from aegis.core.enums import MatchConfidence
from aegis.core.versions import UnparseableVersion, parse_version
from aegis.db.models import Asset, AssetCpe
from aegis.inventory.normalise import resolve_product
from aegis.inventory.schemas import InventoryBatch, InventoryItem

log = structlog.get_logger(__name__)

__all__ = ["ImportResult", "import_inventory", "retire_unseen"]


@dataclass(slots=True)
class ImportResult:
    """Outcome of an inventory import."""

    seen: int = 0
    created: int = 0
    updated: int = 0
    retired: int = 0
    rejected: int = 0
    rejections: list[tuple[str, str]] = field(default_factory=list)

    def reject(self, what: str, reason: str) -> None:
        self.rejected += 1
        self.rejections.append((what, reason))


def import_inventory(
    session: Session,
    batch: InventoryBatch | Iterable[InventoryItem],
    *,
    observed_at: datetime | None = None,
) -> ImportResult:
    """Upsert a batch of discovered products into the tenant's inventory.

    Args:
        session: A tenant-scoped session (see
            :func:`aegis.db.tenancy.tenant_session_scope`).  The schema the
            session is bound to *is* the tenant.
        batch: The import, or a bare iterable of items.
        observed_at: Discovery time, defaulting to now.  Stored as
            ``last_seen_at`` so staleness is measurable.

    Returns:
        Counts of assets created, updated and rejected.
    """
    items = list(batch.items) if isinstance(batch, InventoryBatch) else list(batch)
    when = observed_at or datetime.now(UTC)
    result = ImportResult(seen=len(items))
    if not items:
        return result

    existing = _load_existing(session, items)

    for item in items:
        try:
            _upsert_item(session, item, when, existing, result)
        except Exception as exc:
            log.warning(
                "inventory.item_rejected",
                hostname=item.hostname,
                product=item.product,
                error=str(exc),
            )
            result.reject(f"{item.hostname}/{item.product}", str(exc))

    session.flush()
    log.info(
        "inventory.imported",
        seen=result.seen,
        created=result.created,
        updated=result.updated,
        rejected=result.rejected,
    )
    return result


def _asset_key(item: InventoryItem) -> tuple[str, str, int | None]:
    """Asset identity: a host's product on a port, independent of version."""
    return (item.hostname, item.product, item.port)


def _load_existing(
    session: Session, items: list[InventoryItem]
) -> dict[tuple[str, str, int | None], Asset]:
    """Pre-load the assets this batch might touch, keyed by identity."""
    hostnames = {item.hostname for item in items}
    rows = session.scalars(select(Asset).where(Asset.hostname.in_(hostnames))).all()
    return {(row.hostname, row.product_name, row.port): row for row in rows}


def _upsert_item(
    session: Session,
    item: InventoryItem,
    when: datetime,
    existing: dict[tuple[str, str, int | None], Asset],
    result: ImportResult,
) -> None:
    resolved = resolve_product(
        product=item.product,
        vendor=item.vendor,
        version=item.version,
        supplied_cpes=item.cpes,
    )
    if not resolved.cpes:
        raise ValueError("product did not resolve to any CPE")

    version_is_clean = _version_is_orderable(item.version)
    primary = resolved.cpes[0]

    product_class = classify_product(
        part=primary.part,
        vendor=primary.vendor,
        product=primary.product,
        from_distro_package=item.from_distro_package,
    )
    confidence = match_confidence(
        product_class=product_class,
        exposure=item.exposure_class,
        version_is_clean=version_is_clean,
    )
    # A guessed CPE identity is not a reliable match target, whatever the
    # product class suggests (spec §3.3 requires clean identification).
    if not resolved.is_authoritative:
        confidence = min(confidence, MatchConfidence.MEDIUM, key=lambda c: c.rank)

    key = _asset_key(item)
    asset = existing.get(key)

    if asset is None:
        asset = Asset(
            hostname=item.hostname,
            address=item.address,
            port=item.port,
            product_name=item.product,
            version=item.version,
            version_is_clean=version_is_clean,
            product_class=product_class,
            exposure_class=item.exposure_class,
            criticality=item.criticality,
            match_confidence=confidence,
            source=str(item.source),
            from_distro_package=item.from_distro_package,
            first_seen_at=when,
            last_seen_at=when,
            evidence=_evidence_of(item),
        )
        session.add(asset)
        session.flush()
        existing[key] = asset
        result.created += 1
    else:
        asset.address = item.address or asset.address
        # The version is what changes when a host is patched; updating it in
        # place is what lets the matcher resolve the old finding.
        asset.version = item.version
        asset.version_is_clean = version_is_clean
        asset.product_class = product_class
        asset.exposure_class = item.exposure_class
        asset.criticality = item.criticality
        asset.match_confidence = confidence
        asset.source = str(item.source)
        asset.from_distro_package = item.from_distro_package
        asset.last_seen_at = when
        # Rediscovery un-retires: the asset is back.
        asset.retired_at = None
        asset.evidence = _evidence_of(item)
        result.updated += 1

    _sync_cpes(session, asset, [cpe.to_string() for cpe in resolved.cpes])


def _sync_cpes(session: Session, asset: Asset, cpe_strings: list[str]) -> None:
    """Make the asset's CPE rows exactly ``cpe_strings``.

    The rows are queried rather than read off ``asset.cpes``: sessions here
    are created with ``expire_on_commit=False``, so a relationship loaded
    before an earlier commit stays cached and stale.  Trusting it would make
    a re-import a no-op and leave the asset advertising a version it no
    longer runs - which, if that stale version is the patched one, hides a
    real vulnerability.
    """
    current = {
        row.cpe: row
        for row in session.scalars(
            select(AssetCpe).where(AssetCpe.asset_id == asset.asset_id)
        ).all()
    }
    wanted = set(cpe_strings)

    for cpe_string in cpe_strings:
        if cpe_string in current:
            continue
        parsed = parse_cpe(cpe_string)
        session.add(
            AssetCpe(
                asset_id=asset.asset_id,
                cpe=cpe_string,
                part=parsed.part,
                vendor=parsed.vendor,
                product=parsed.product,
                target_sw=None if parsed.target_sw == "*" else parsed.target_sw,
            )
        )

    for cpe_string, row in current.items():
        if cpe_string not in wanted:
            session.delete(row)

    # Flush so the next asset in the batch - and the next import - sees the
    # rows as they now stand, not as the session last cached them.
    session.flush()


def retire_unseen(
    session: Session,
    *,
    source: str,
    before: datetime,
) -> int:
    """Retire assets from ``source`` that this discovery pass did not report.

    Retiring rather than deleting keeps the history a match may reference,
    and excludes the asset from future matching.  Scoped by source so a
    scanner import cannot retire what only ASM can see.
    """
    stale = session.scalars(
        select(Asset).where(
            Asset.source == source,
            Asset.last_seen_at < before,
            Asset.retired_at.is_(None),
        )
    ).all()
    for asset in stale:
        asset.retired_at = datetime.now(UTC)
    session.flush()
    if stale:
        log.info("inventory.retired", source=source, count=len(stale))
    return len(stale)


def _version_is_orderable(version: str | None) -> bool:
    """Can this version take part in a range comparison (spec §5.2)?"""
    if not version:
        return False
    try:
        parse_version(version)
    except UnparseableVersion:
        return False
    return True


def _evidence_of(item: InventoryItem) -> dict[str, object]:
    return {
        "discovery_evidence": str(item.evidence),
        "source": str(item.source),
        **({"raw": item.raw} if item.raw else {}),
    }
