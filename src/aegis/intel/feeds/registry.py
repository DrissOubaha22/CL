"""Lookup of the pipelines available to the scheduler and the CLI."""

from __future__ import annotations

from collections.abc import Mapping

from aegis.core.enums import FeedSource
from aegis.intel.feeds.base import FeedPipeline
from aegis.intel.feeds.epss import EpssPipeline
from aegis.intel.feeds.kev import KevPipeline
from aegis.intel.feeds.nvd import NvdPipeline
from aegis.intel.feeds.psirt import PsirtPipeline

__all__ = ["PIPELINES", "SYNC_ORDER", "get_pipeline"]

PIPELINES: Mapping[FeedSource, type[FeedPipeline]] = {
    FeedSource.CISA_KEV: KevPipeline,
    FeedSource.NVD: NvdPipeline,
    FeedSource.FIRST_EPSS: EpssPipeline,
    FeedSource.PSIRT: PsirtPipeline,
}

#: Order a full refresh runs in: sources that *introduce* CVEs first, then
#: sources that annotate CVEs already in the store.
SYNC_ORDER: tuple[FeedSource, ...] = (
    FeedSource.CISA_KEV,
    FeedSource.NVD,
    # PSIRT reads advisories NVD already published URLs for, so it runs
    # after NVD and before the annotating feeds.
    FeedSource.PSIRT,
    FeedSource.FIRST_EPSS,
)


def get_pipeline(source: FeedSource) -> type[FeedPipeline]:
    """Return the pipeline class for ``source``.

    Raises:
        KeyError: if no pipeline is implemented for that source yet.
    """
    try:
        return PIPELINES[source]
    except KeyError as exc:
        implemented = ", ".join(sorted(str(key) for key in PIPELINES))
        raise KeyError(f"no pipeline for {source}; implemented: {implemented}") from exc
