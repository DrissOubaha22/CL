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

    # EPSS accepts a comma-separated batch of CVE ids per call.
    epss_batch_size: int = 100

    # How far back an incremental NVD run looks when the store has no
    # watermark for it yet.
    nvd_initial_lookback_days: int = 7


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
