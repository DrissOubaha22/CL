"""Vocabulary shared by the intel store, the pipelines and (later) scoring."""

from __future__ import annotations

from enum import StrEnum


class ExploitStatus(StrEnum):
    """Exploitation maturity for a CVE (spec §7.1).

    Derived, never written directly by a feed: see
    :func:`aegis.intel.derive.derive_exploit_status`.
    """

    NONE = "none"
    POC = "poc"
    ACTIVE = "active"

    @property
    def rank(self) -> int:
        return _EXPLOIT_RANK[self]


_EXPLOIT_RANK: dict[ExploitStatus, int] = {
    ExploitStatus.NONE: 0,
    ExploitStatus.POC: 1,
    ExploitStatus.ACTIVE: 2,
}


class FeedSource(StrEnum):
    """Structured intel sources consumed by deterministic ETL (spec §4.1).

    ``PSIRT`` is the one non-deterministic origin; it is reserved here so the
    provenance tables accept phase-4 LLM extraction output without a
    migration, but no pipeline in this phase produces it.
    """

    CISA_KEV = "cisa_kev"
    FIRST_EPSS = "first_epss"
    NVD = "nvd"
    VULNCHECK_KEV = "vulncheck_kev"
    EXPLOIT_DB = "exploit_db"
    METASPLOIT = "metasploit"
    NUCLEI = "nuclei"
    PSIRT = "psirt"


#: Sources that assert *active* exploitation in the wild.
ACTIVE_EXPLOITATION_SOURCES = frozenset({FeedSource.CISA_KEV, FeedSource.VULNCHECK_KEV})

#: Sources that only prove exploit code exists publicly.
PUBLIC_EXPLOIT_SOURCES = frozenset(
    {FeedSource.EXPLOIT_DB, FeedSource.METASPLOIT, FeedSource.NUCLEI}
)


class Confidence(StrEnum):
    """Confidence attached to an extracted claim (spec §4.2)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RunStatus(StrEnum):
    """Outcome of a scheduled pipeline run."""

    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
