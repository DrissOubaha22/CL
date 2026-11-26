"""SSO token verification and secret storage - spec §11."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK

from aegis.auth.oidc import InvalidToken, TokenVerifier, principal_from_claims
from aegis.auth.rbac import Permission, Role
from aegis.auth.secrets import (
    EnvSecretStore,
    FileSecretStore,
    SecretNotFound,
    build_secret_store,
)
from aegis.config import Settings

ISSUER = "https://idp.example.test"
AUDIENCE = "aegis-api"


@pytest.fixture(scope="module")
def signing_key() -> Any:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def public_jwk(signing_key: Any) -> dict[str, Any]:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    return jwk


@pytest.fixture
def verifier(public_jwk: dict[str, Any]) -> TokenVerifier:
    class FakeJwks:
        def get_signing_key_from_jwt(self, token: str) -> PyJWK:
            return PyJWK(public_jwk)

    return TokenVerifier(
        settings=Settings(oidc_issuer=ISSUER, oidc_audience=AUDIENCE),
        jwk_client=FakeJwks(),
    )


def make_token(signing_key: Any, **overrides: Any) -> str:
    claims: dict[str, Any] = {
        "sub": "jo@example.test",
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": int(time.time()) + 600,
        "name": "Jo Martin",
        "aegis_roles": {"acme": ["analyst"]},
    }
    claims.update(overrides)
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": "k1"})


class TestVerification:
    def test_a_valid_token_becomes_a_principal(
        self, verifier: TokenVerifier, signing_key: Any
    ) -> None:
        principal = verifier.verify(make_token(signing_key))

        assert principal.subject == "jo@example.test"
        assert principal.display_name == "Jo Martin"
        assert principal.issuer == "oidc"
        assert principal.may(Permission.REVIEW_BULLETIN, tenant_slug="acme")

    def test_an_unconfigured_verifier_rejects_everything(self, signing_key: Any) -> None:
        """Falling open when misconfigured is worse than having no verifier."""
        with pytest.raises(InvalidToken, match="not configured"):
            TokenVerifier(settings=Settings()).verify(make_token(signing_key))

    def test_an_expired_token_is_rejected(self, verifier: TokenVerifier, signing_key: Any) -> None:
        token = make_token(signing_key, exp=int(time.time()) - 600)
        with pytest.raises(InvalidToken, match="expired"):
            verifier.verify(token)

    def test_clock_skew_is_tolerated(self, verifier: TokenVerifier, signing_key: Any) -> None:
        """A token seconds past expiry is a clock difference, not an attack."""
        verifier.verify(make_token(signing_key, exp=int(time.time()) - 5))

    def test_a_wrong_audience_is_rejected(self, verifier: TokenVerifier, signing_key: Any) -> None:
        """A token minted for another service must not work here."""
        with pytest.raises(InvalidToken, match="audience"):
            verifier.verify(make_token(signing_key, aud="some-other-api"))

    def test_a_wrong_issuer_is_rejected(self, verifier: TokenVerifier, signing_key: Any) -> None:
        with pytest.raises(InvalidToken, match="issuer"):
            verifier.verify(make_token(signing_key, iss="https://evil.test"))

    def test_a_foreign_signature_is_rejected(self, verifier: TokenVerifier) -> None:
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = make_token(other)
        with pytest.raises(InvalidToken):
            verifier.verify(token)

    def test_an_unsigned_token_is_rejected(self, verifier: TokenVerifier) -> None:
        """The `alg: none` attack."""
        token = jwt.encode(
            {"sub": "attacker", "iss": ISSUER, "aud": AUDIENCE, "exp": 9999999999},
            key="",
            algorithm="none",
        )
        with pytest.raises(InvalidToken):
            verifier.verify(token)

    @pytest.mark.parametrize("token", ["", "   ", "not-a-jwt"])
    def test_malformed_tokens_are_rejected(self, verifier: TokenVerifier, token: str) -> None:
        with pytest.raises(InvalidToken):
            verifier.verify(token)

    def test_a_token_without_a_subject_is_rejected(
        self, verifier: TokenVerifier, signing_key: Any
    ) -> None:
        with pytest.raises(InvalidToken):
            verifier.verify(make_token(signing_key, sub=""))


class TestClaims:
    def test_roles_are_scoped_per_tenant(self) -> None:
        principal = principal_from_claims(
            {
                "sub": "u",
                "aegis_roles": {"acme": ["analyst"], "globex": ["viewer"]},
            }
        )
        assert principal.roles_in("acme") == frozenset({Role.ANALYST})
        assert principal.roles_in("globex") == frozenset({Role.VIEWER})

    def test_an_unknown_role_grants_nothing(self) -> None:
        """An identity provider inventing a role must not invent access."""
        principal = principal_from_claims(
            {"sub": "u", "aegis_roles": {"acme": ["superuser", "viewer"]}}
        )
        assert principal.roles_in("acme") == frozenset({Role.VIEWER})

    def test_tenant_slugs_are_normalised(self) -> None:
        principal = principal_from_claims({"sub": "u", "aegis_roles": {"  ACME ": ["analyst"]}})
        assert principal.tenants == frozenset({"acme"})

    def test_platform_roles_come_from_their_own_claim(self) -> None:
        principal = principal_from_claims(
            {"sub": "ops", "aegis_platform_roles": ["platform_operator"]}
        )
        assert principal.may(Permission.RUN_INTEL)
        assert not principal.may(Permission.READ_CASE, tenant_slug="acme")

    def test_a_malformed_roles_claim_grants_nothing(self) -> None:
        principal = principal_from_claims({"sub": "u", "aegis_roles": ["analyst"]})
        assert principal.tenants == frozenset()

    def test_no_roles_claim_means_no_access(self) -> None:
        principal = principal_from_claims({"sub": "u"})
        assert principal.tenants == frozenset()
        assert not principal.platform_roles


class TestSecrets:
    def test_env_store_reads_a_prefixed_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_SECRET_SLACK_WEBHOOK", "https://hooks.test/a")
        store = EnvSecretStore(settings=Settings())
        assert store.get("slack_webhook") == "https://hooks.test/a"
        assert store.get("SLACK-WEBHOOK") == "https://hooks.test/a"

    def test_a_missing_secret_names_where_it_looked(self) -> None:
        store = EnvSecretStore(settings=Settings())
        with pytest.raises(SecretNotFound, match="AEGIS_SECRET_ABSENT"):
            store.get("absent")

    def test_get_optional_returns_none(self) -> None:
        assert EnvSecretStore(settings=Settings()).get_optional("absent") is None

    def test_file_store_strips_trailing_newlines(self, tmp_path: Path) -> None:
        """Mounted secrets usually arrive with one."""
        (tmp_path / "nvd_api_key").write_text("key-123\n")
        store = FileSecretStore(tmp_path)
        assert store.get("nvd_api_key") == "key-123"

    def test_file_store_dates_a_secret(self, tmp_path: Path) -> None:
        (tmp_path / "webhook").write_text("x")
        info = FileSecretStore(tmp_path).describe("webhook")
        assert info.present
        assert info.updated_at is not None
        assert not info.is_stale(90)

    def test_an_old_secret_is_reported_stale(self, tmp_path: Path) -> None:
        """Rotating is the orchestrator's job; noticing nobody did is ours."""
        path = tmp_path / "webhook"
        path.write_text("x")
        os.utime(path, (time.time() - 200 * 86400,) * 2)
        assert FileSecretStore(tmp_path).describe("webhook").is_stale(90)

    def test_an_unknown_age_is_not_reported_stale(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Reporting everything stale trains people to ignore the report."""
        monkeypatch.setenv("AEGIS_SECRET_X", "y")
        assert not EnvSecretStore(settings=Settings()).describe("x").is_stale(1)

    def test_describe_never_returns_the_value(self, tmp_path: Path) -> None:
        (tmp_path / "webhook").write_text("super-secret")
        info = FileSecretStore(tmp_path).describe("webhook")
        assert "super-secret" not in str(info)

    @pytest.mark.parametrize(
        "name", ["../../etc/passwd", "..\\..\\secrets", ".ssh", "  ", "/etc/shadow"]
    )
    def test_path_traversal_is_refused(self, tmp_path: Path, name: str) -> None:
        """get_optional promises never to raise, so an unsafe name is simply
        a secret that is not there."""
        store = FileSecretStore(tmp_path)
        assert store.get_optional(name) is None
        assert not store.describe(name).present
        with pytest.raises(SecretNotFound):
            store.get(name)

    def test_an_unknown_backend_fails_at_construction(self) -> None:
        """Discovering a misconfigured vault at the first read is worse."""
        with pytest.raises(ValueError, match="unknown secret backend"):
            build_secret_store(settings=Settings(secret_backend="vault"))

    def test_a_file_backend_without_a_directory_fails(self) -> None:
        with pytest.raises(ValueError, match="secret_file_dir"):
            build_secret_store(settings=Settings(secret_backend="file"))
