"""The API application (spec §12).

Constructed by a factory so tests can supply their own token verifier
without an identity provider, and so a deployment can fail fast on a
configuration that would serve requests insecurely.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Engine

from aegis import __version__
from aegis.api.routes import router
from aegis.auth.oidc import TokenVerifier
from aegis.config import Settings, get_settings
from aegis.logging import configure_logging

log = structlog.get_logger(__name__)

__all__ = ["create_app"]


def create_app(
    *,
    settings: Settings | None = None,
    token_verifier: TokenVerifier | None = None,
    engine: Engine | None = None,
) -> FastAPI:
    """Build the API.

    Args:
        settings: Override configuration.
        token_verifier: Override the SSO verifier.
        engine: Bind the app to a specific database engine instead of the
            configured one.  A deployment serving two databases - a
            read replica for the portal, say - uses this; so do the tests.

    Raises:
        RuntimeError: when SSO is unconfigured and no verifier was supplied.
            A tenant API that cannot authenticate must not start: every
            request would be rejected, and an operator would discover that
            from user reports rather than from startup.
    """
    config = settings or get_settings()
    configure_logging()

    verifier = token_verifier or TokenVerifier(settings=config)
    if not verifier.configured:
        raise RuntimeError(
            "the API cannot start without SSO: set AEGIS_OIDC_ISSUER "
            "(and AEGIS_OIDC_AUDIENCE) for your identity provider"
        )

    app = FastAPI(
        title=config.api_title,
        version=__version__,
        description=(
            "Tenant-scoped access to inventory, cases and bulletins. "
            "Every request is authenticated, authorised against the tenant "
            "in the path, and recorded in the audit log."
        ),
    )
    app.state.token_verifier = verifier
    app.state.settings = config
    app.state.engine = engine

    if config.api_cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(config.api_cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-Request-Id"],
        )

    app.include_router(router)
    log.info(
        "api.started",
        title=config.api_title,
        cors_origins=len(config.api_cors_origins),
    )
    return app
