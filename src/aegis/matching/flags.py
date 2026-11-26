"""False-positive controls (spec §5.3).

Spec §5.3 lists four controls.  Two are decided before matching, by the
inventory, and two at match time, here:

================== ===================================================
Appliance-first    inventory: :func:`aegis.core.classification.match_confidence`
Backport awareness here: :data:`~aegis.core.enums.MatchFlag.BACKPORT`
Config dependence  here: :data:`~aegis.core.enums.MatchFlag.CONFIG_DEPENDENT`
Verification gate  here: :data:`~aegis.core.enums.MatchFlag.UNVERIFIED`
================== ===================================================

The flags do not suppress a match.  A suppressed match is a match nobody can
review; a flagged one is visible, explained, and barred from auto-escalation
by the scoring engine in phase 3.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from aegis.core.enums import MatchConfidence, MatchFlag, ProductClass

__all__ = ["MatchVerdict", "evaluate_match"]


@dataclass(frozen=True, slots=True)
class MatchVerdict:
    """The caveats and final confidence attached to one match."""

    confidence: MatchConfidence
    flags: tuple[MatchFlag, ...]

    @property
    def flag_values(self) -> list[str]:
        return [str(flag) for flag in self.flags]

    @property
    def auto_escalatable(self) -> bool:
        """May the scoring engine raise this without a human (spec §5.3)?

        False whenever a caveat means the match might not be real.  Phase 3
        reads this; phase 2 only records it.
        """
        blocking = {
            MatchFlag.BACKPORT,
            MatchFlag.CONFIG_DEPENDENT,
            MatchFlag.UNVERIFIED,
            MatchFlag.UNPARSEABLE_VERSION,
        }
        return not blocking.intersection(self.flags)


def evaluate_match(
    *,
    asset_confidence: MatchConfidence,
    product_class: ProductClass,
    from_distro_package: bool,
    version_is_clean: bool,
    exposure_verified_at: datetime | None,
    intel_config_dependent: bool,
    advisory_has_context_nodes: bool,
    range_is_unbounded: bool,
) -> MatchVerdict:
    """Decide the flags and final confidence for a candidate match.

    Args:
        asset_confidence: Confidence the inventory assigned to the asset.
        product_class: What kind of software the asset is.
        from_distro_package: The entry came from a package manager.
        version_is_clean: The asset version could be ordered (spec §5.2).
        exposure_verified_at: When an active check last confirmed exposure,
            or ``None``.
        intel_config_dependent: The advisory says a feature or setting is
            required.
        advisory_has_context_nodes: The advisory's configuration names
            products that are *not* themselves vulnerable, i.e. it describes
            a platform combination rather than a single product.
        range_is_unbounded: The advisory names the product with no version
            bound at all.

    Returns:
        The verdict stored on the match.
    """
    flags: list[MatchFlag] = []
    confidence = asset_confidence

    # Verification gate (spec §5.3): a match is a *candidate* until an active
    # check confirms the service is really reachable and really that version.
    if exposure_verified_at is None:
        flags.append(MatchFlag.UNVERIFIED)

    # Backport awareness (spec §5.3): distros patch without bumping the
    # version string, so an upstream-version comparison may be wrong.
    if from_distro_package or product_class is ProductClass.OS_PACKAGE:
        flags.append(MatchFlag.BACKPORT)
        confidence = MatchConfidence.LOW

    # Configuration dependence (spec §5.3).
    if intel_config_dependent or advisory_has_context_nodes:
        flags.append(MatchFlag.CONFIG_DEPENDENT)
        confidence = _cap(confidence, MatchConfidence.MEDIUM)

    if not version_is_clean:
        flags.append(MatchFlag.UNPARSEABLE_VERSION)
        confidence = MatchConfidence.LOW

    # An advisory naming every version of a product is usually an incomplete
    # record rather than a genuine "all versions affected".
    if range_is_unbounded:
        flags.append(MatchFlag.UNBOUNDED_RANGE)
        confidence = _cap(confidence, MatchConfidence.MEDIUM)

    return MatchVerdict(confidence=confidence, flags=tuple(flags))


def _cap(value: MatchConfidence, ceiling: MatchConfidence) -> MatchConfidence:
    return value if value.rank <= ceiling.rank else ceiling
