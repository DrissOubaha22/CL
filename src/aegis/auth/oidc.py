"""Verifying SSO tokens (spec §11).

Spec §11 asks for "SSO + RBAC".  This is the SSO half: an OIDC access token
arrives, its signature is checked against the provider's published keys, and
the roles it carries become a :class:`~aegis.auth.rbac.Principal`.

Three properties worth stating, because getting any of them wrong turns
authentication into decoration:

* **Unconfigured means closed.** With no issuer configured, every token is
  rejected.  A verifier that falls open when misconfigured is worse than no
  verifier, because it looks like one.
* **The signature is checked against the provider's keys**, fetched from its
  JWKS endpoint and cached for a configured TTL.  Nothing is trusted from
  the token itself except the key id used to select a key.
* **Roles come from the token, scoped to tenants.** A claim maps tenant slug
  to roles.  An unknown role name is dropped rather than guessed at, so an
  identity provider that invents a role grants nothing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
import structlog
from jwt import PyJWKClient

from aegis.auth.rbac import Principal, Role
from aegis.config import Settings, get_settings

log = structlog.get_logger(__name__)

__all__ = ["InvalidToken", "TokenVerifier", "principal_from_claims"]


class InvalidToken(ValueError):
    """The token is absent, malformed, expired, or not for us."""


@dataclass(slots=True)
class _CachedJwks:
    client: PyJWKClient
    fetched_at: float


class TokenVerifier:
    """Verifies OIDC access tokens and turns them into principals."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        jwk_client: PyJWKClient | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._cached: _CachedJwks | None = (
            _CachedJwks(client=jwk_client, fetched_at=time.monotonic())
            if jwk_client is not None
            else None
        )
        self._injected = jwk_client is not None

    @property
    def configured(self) -> bool:
        return bool(self.settings.oidc_issuer) or self._injected

    def verify(self, token: str) -> Principal:
        """Verify a bearer token and return the principal it names.

        Raises:
            InvalidToken: on an unconfigured verifier, a bad signature, a
                wrong issuer or audience, or an expired token.
        """
        if not self.configured:
            # Closed by default: a deployment without an issuer has not
            # configured SSO, and must not be treated as having allowed
            # everyone.
            raise InvalidToken(
                "SSO is not configured: set AEGIS_OIDC_ISSUER before serving the API"
            )

        if not token or not token.strip():
            raise InvalidToken("no token supplied")

        try:
            signing_key = self._signing_key_for(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
                audience=self.settings.oidc_audience,
                issuer=self.settings.oidc_issuer,
                leeway=self.settings.oidc_leeway_seconds,
                options={
                    "require": ["exp", "sub"],
                    "verify_aud": bool(self.settings.oidc_audience),
                    "verify_iss": bool(self.settings.oidc_issuer),
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidToken("token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise InvalidToken("token is not for this audience") from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidToken("token is from an unexpected issuer") from exc
        except jwt.PyJWTError as exc:
            raise InvalidToken(f"token rejected: {exc}") from exc

        return principal_from_claims(claims, settings=self.settings)

    def _signing_key_for(self, token: str) -> Any:
        """Select the provider key that signed this token."""
        client = self._jwk_client()
        try:
            return client.get_signing_key_from_jwt(token).key
        except jwt.PyJWKClientError as exc:
            raise InvalidToken(f"no provider key matches this token: {exc}") from exc
        except httpx.HTTPError as exc:  # pragma: no cover - network path
            raise InvalidToken(f"cannot reach the identity provider: {exc}") from exc

    def _jwk_client(self) -> PyJWKClient:
        ttl = self.settings.oidc_jwks_ttl_seconds
        now = time.monotonic()

        if self._cached is not None and (self._injected or now - self._cached.fetched_at < ttl):
            return self._cached.client

        issuer = (self.settings.oidc_issuer or "").rstrip("/")
        jwks_uri = f"{issuer}/.well-known/jwks.json"
        log.info("oidc.jwks_refresh", jwks_uri=jwks_uri)
        client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=ttl)
        self._cached = _CachedJwks(client=client, fetched_at=now)
        return client


def principal_from_claims(claims: dict[str, Any], *, settings: Settings | None = None) -> Principal:
    """Build a principal from verified token claims.

    Unknown role names are dropped with a warning: an identity provider
    that invents a role should grant nothing, not something.
    """
    config = settings or get_settings()

    subject = str(claims.get("sub") or "").strip()
    if not subject:
        raise InvalidToken("token carries no subject")

    tenant_roles: dict[str, frozenset[Role]] = {}
    raw_roles = claims.get(config.oidc_roles_claim) or {}
    if isinstance(raw_roles, dict):
        for slug, names in raw_roles.items():
            roles = _parse_roles(names, where=f"tenant {slug!r}")
            if roles:
                tenant_roles[str(slug).strip().lower()] = roles
    elif raw_roles:
        log.warning("oidc.roles_claim_not_a_mapping", claim=config.oidc_roles_claim)

    platform_roles = _parse_roles(
        claims.get(config.oidc_platform_roles_claim) or [], where="platform"
    )

    return Principal(
        subject=subject,
        tenant_roles=tenant_roles,
        platform_roles=platform_roles,
        display_name=_display_name(claims),
        issuer="oidc",
    )


def _parse_roles(value: Any, *, where: str) -> frozenset[Role]:
    names = value if isinstance(value, list | tuple | set) else [value]
    parsed: set[Role] = set()
    for name in names:
        try:
            parsed.add(Role(str(name).strip().lower()))
        except ValueError:
            log.warning("oidc.unknown_role", role=str(name)[:40], where=where)
    return frozenset(parsed)


def _display_name(claims: dict[str, Any]) -> str | None:
    for key in ("name", "preferred_username", "email"):
        value = claims.get(key)
        if value:
            return str(value)[:200]
    return None
