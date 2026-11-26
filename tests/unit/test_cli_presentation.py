"""`aegis config` must never print a credential."""

from __future__ import annotations

import pytest

from aegis.cli import _present, _strip_credentials


class TestPresent:
    @pytest.mark.parametrize(
        "name", ["nvd_api_key", "vulncheck_api_token", "db_password", "client_secret"]
    )
    def test_secret_settings_are_withheld(self, name: str) -> None:
        assert _present(name, "super-secret") == "***set***"

    def test_an_unset_secret_reads_as_unset(self) -> None:
        assert _present("nvd_api_key", None) == "None"

    def test_dsn_credentials_are_stripped_but_the_host_is_kept(self) -> None:
        shown = _present(
            "database_dsn", "postgresql+psycopg://aegis:hunter2@db.internal:5432/aegis"
        )
        assert "hunter2" not in shown
        assert "db.internal:5432/aegis" in shown

    def test_a_credential_free_url_is_shown_in_full(self) -> None:
        url = "https://api.first.org/data/v1/epss"
        assert _present("epss_url", url) == url

    def test_plain_settings_pass_through(self) -> None:
        assert _present("db_pool_size", 5) == "5"
        assert _present("user_agent", "aegis-intel-etl/0.1") == "aegis-intel-etl/0.1"


class TestStripCredentials:
    def test_strips_user_and_password(self) -> None:
        assert _strip_credentials("redis://user:pass@cache:6379/0") == "redis://***@cache:6379/0"

    def test_leaves_a_bare_url_untouched(self) -> None:
        assert _strip_credentials("redis://cache:6379/0") == "redis://cache:6379/0"
