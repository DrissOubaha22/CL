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


class ExposureClass(StrEnum):
    """How an asset can be reached by an attacker (spec §6.3, §7.1).

    This is *evidence*, not a self-declared field: discovery sets it from what
    it actually observed (spec §3.2).  ``INTERNET`` additionally requires
    confirmation by exposure verification before it drives a Critical/High
    tier (spec §5.3, §6).
    """

    INTERNET = "internet"
    INTERNAL = "internal"
    #: Browsers, mail clients, office apps. Never "internet-facing": the risk
    #: basis is weaponised content reaching a user (spec §6.3).
    CLIENT_SIDE = "client_side"
    UNKNOWN = "unknown"


class Criticality(StrEnum):
    """Business criticality of an asset, tagged at onboarding (spec §3.2)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class MatchConfidence(StrEnum):
    """How much the match itself can be trusted (spec §3.3, §5.3).

    Separate from severity: a Critical CVE matched against a backported
    distro package is a low-confidence match, and §5.3 forbids auto-escalating
    it.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK: dict[MatchConfidence, int] = {
    MatchConfidence.LOW: 0,
    MatchConfidence.MEDIUM: 1,
    MatchConfidence.HIGH: 2,
}


class MatchFlag(StrEnum):
    """Caveats carried by a match (spec §9 ``match.flags``, §5.3)."""

    #: Linux distro package: the distro backports fixes without changing the
    #: version string, so an upstream-version match may be already patched.
    BACKPORT = "backport"
    #: The advisory states the vulnerability needs a feature or configuration.
    CONFIG_DEPENDENT = "config"
    #: Exposure has not been confirmed by an active check yet (spec §6).
    UNVERIFIED = "unverified"
    #: The asset or advisory version could not be ordered (spec §5.2).
    UNPARSEABLE_VERSION = "unparseable_version"
    #: The advisory names every version of the product, with no bound.
    UNBOUNDED_RANGE = "unbounded_range"


class ProductClass(StrEnum):
    """What kind of software an asset is (spec §3.3).

    Matching precision differs sharply by class, so the class drives both
    confidence and the false-positive flags.
    """

    #: Network appliance / security gateway with a clean version banner.
    APPLIANCE = "appliance"
    #: Server-side software addressable over the network (web, app, mail).
    SERVER_SOFTWARE = "server_software"
    #: Distribution-packaged software on a general-purpose host.
    OS_PACKAGE = "os_package"
    #: Browsers, mail clients, office suites (spec §6.3).
    CLIENT_SIDE = "client_side"
    OTHER = "other"


class AutomationPolicy(StrEnum):
    """How far a tenant lets Aegis act without a human (spec §8.2).

    Consumed by bulletin routing in phase 4; stored on the tenant from
    onboarding so the policy exists before the pipeline that honours it.
    """

    #: Auto-issue where the case is unambiguous: exploited, patch available
    #: and exposure verified.  Everything else is queued.
    AUTO_ISSUE_VERIFIED = "auto_issue_verified"
    #: Every bulletin waits for an analyst.
    REVIEW_ALL = "review_all"
