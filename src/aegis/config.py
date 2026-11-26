"""Runtime configuration.

All settings are read from the environment (prefix ``AEGIS_``) or a ``.env``
file.  Feed credentials are expected to come from the secret vault at
deployment time (spec §11) and are therefore never given defaults here.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: str = "development"
    log_level: str = "INFO"
    log_json: bool = False

    # --- Data store (spec §13: PostgreSQL, shared intel schema) -------------
    database_dsn: str = "postgresql+psycopg://aegis:aegis@localhost:5432/aegis"
    intel_schema: str = "intel"
    control_schema: str = "control"
    #: Prefix for per-tenant schemas, e.g. "tenant_acme" (spec §11).
    tenant_schema_prefix: str = "tenant_"
    db_echo: bool = False
    db_pool_size: int = 5

    # --- Workers (spec §13: Celery/cron) ------------------------------------
    broker_url: str = "redis://localhost:6379/0"
    result_backend: str = "redis://localhost:6379/1"

    # --- Feed endpoints (spec §4.1) -----------------------------------------
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_url: str = "https://api.first.org/data/v1/epss"
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    vulncheck_url: str = "https://api.vulncheck.com/v3/index/vulncheck-kev"

    nvd_api_key: SecretStr | None = None
    vulncheck_api_token: SecretStr | None = None

    # --- HTTP client --------------------------------------------------------
    http_timeout_seconds: float = 30.0
    http_max_retries: int = 4
    user_agent: str = Field(
        default="aegis-intel-etl/0.1",
        description="Generic client identifier; never carries client identity.",
    )

    # NVD asks unauthenticated clients to stay under 5 requests / 30s and
    # authenticated ones under 50 / 30s.
    nvd_requests_per_window: int = 5
    nvd_window_seconds: float = 30.0
    nvd_page_size: int = 2000

    # --- Exposure verification (spec §6) ------------------------------------
    #: Active probing is the product's core check; a deployment that must not
    #: emit traffic turns it off and every match stays at its unverified tier.
    verification_enabled: bool = True
    verification_timeout_seconds: float = 6.0
    #: Probes run in a bounded pool; the database is touched only afterwards.
    verification_max_concurrency: int = 8
    #: Minimum gap between probes to the same host, so verifying many matches
    #: on one appliance does not look like a scan.
    verification_per_host_delay_seconds: float = 0.5
    #: Permit loopback/private targets.  Off by default: §6.1 asks whether a
    #: service is reachable *from the internet*.
    verification_allow_private_targets: bool = False
    #: How long a verification stays fresh before it is re-run.
    verification_ttl_hours: int = 24
    #: Sent on HTTP banner reads; never carries client identity.
    verification_user_agent: str = "aegis-exposure-check/0.1"

    # --- SSO / OIDC (spec §11) ----------------------------------------------
    #: The identity provider's issuer URL.  Discovery and JWKS are read from
    #: it; unset means token verification is unconfigured and the API will
    #: refuse every request rather than fall open.
    oidc_issuer: str | None = None
    #: The audience this deployment's tokens must carry.
    oidc_audience: str | None = None
    #: Claim holding tenant -> roles, e.g. {"acme": ["analyst"]}.
    oidc_roles_claim: str = "aegis_roles"
    #: Claim holding platform-wide roles, as a list.
    oidc_platform_roles_claim: str = "aegis_platform_roles"
    #: How long a fetched JWKS is reused before it is refetched.
    oidc_jwks_ttl_seconds: int = 3600
    oidc_leeway_seconds: int = 30

    # --- Secrets (spec §11) ---------------------------------------------------
    #: "env" reads from the process environment, "file" from a directory of
    #: files (the shape a mounted Kubernetes/Vault secret takes).
    secret_backend: str = "env"
    secret_file_dir: str | None = None
    secret_env_prefix: str = "AEGIS_SECRET_"
    #: Secrets older than this are reported stale by `aegis secret status`.
    secret_max_age_days: int = 90

    # --- Delivery (spec §12) --------------------------------------------------
    delivery_enabled: bool = True
    delivery_timeout_seconds: float = 10.0
    delivery_max_retries: int = 3

    # --- API (spec §12) -------------------------------------------------------
    api_title: str = "Aegis tenant API"
    #: Allowed CORS origins for the portal; empty means none.
    api_cors_origins: list[str] = Field(default_factory=list)
    #: Refuse to start against a database reached without TLS unless the
    #: deployment says it is local (spec §11: encryption in transit).
    require_database_tls: bool = False

    # --- LLM (spec §4.2, §8) -------------------------------------------------
    #: The LLM handles unstructured text and drafting only, and never
    #: receives client-identifying data (spec §1, §8.1).
    llm_enabled: bool = True
    #: "anthropic" for the hosted API, "self_hosted" for a model served
    #: behind an Anthropic-compatible endpoint (spec §8.3).
    llm_provider: str = "anthropic"
    llm_model: str = "claude-opus-5-5"
    llm_api_key: SecretStr | None = None
    #: Base URL for a self-hosted or proxied endpoint.
    llm_base_url: str | None = None
    #: Spec §8.3: a zero-retention endpoint is one of the two supported
    #: deployments. Refuse to run against a retaining endpoint when set.
    llm_require_zero_retention: bool = True
    llm_max_tokens: int = 4000
    llm_effort: str = "medium"
    llm_timeout_seconds: float = 120.0
    llm_max_retries: int = 2
    #: Advisory pages are fetched as public text; cap what is handed over.
    advisory_max_chars: int = 40_000
    #: How far back a PSIRT run looks for CVEs worth reading an advisory for.
    psirt_lookback_days: int = 30

    # EPSS accepts a comma-separated batch of CVE ids per call.
    epss_batch_size: int = 100

    # How far back an incremental NVD run looks when the store has no
    # watermark for it yet.
    nvd_initial_lookback_days: int = 7


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
