"""Database-enforced isolation - spec §11.

Schema-per-tenant (phase 2) stops one tenant reading another's rows. This
covers the other half: the shared intel store must be read-only to tenant
workers, which only the database can enforce, because the tables are
deliberately in reach.

These create real PostgreSQL roles, so they need a superuser connection -
which the test DSN is.  They are skipped rather than failed where it is not.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import ProgrammingError

from aegis.config import get_settings
from aegis.db.grants import (
    ETL_ROLE,
    TENANT_ROLE,
    apply_grants,
    grant_statements,
    tenant_schema_grants,
)
from tests.conftest import TEST_DSN, requires_db

pytestmark = [pytest.mark.integration, requires_db]

WORKER_PASSWORD = "worker-test-pw"


class TestGrantStatements:
    def test_the_tenant_role_only_selects_on_intel(self) -> None:
        intel = get_settings().intel_schema
        statements = grant_statements()

        selects = [
            s
            for s in statements
            if TENANT_ROLE in s and f'"{intel}"' in s and s.startswith("GRANT")
        ]
        assert selects, "the tenant role must be granted something on intel"
        assert all("SELECT" in s or "USAGE" in s for s in selects), (
            "the tenant role must not be granted write access to intel"
        )
        assert not any("ALL ON ALL TABLES" in s and TENANT_ROLE in s for s in selects)

    def test_the_etl_role_writes_intel(self) -> None:
        intel = get_settings().intel_schema
        statements = grant_statements()
        assert any(
            f'GRANT ALL ON ALL TABLES IN SCHEMA "{intel}" TO "{ETL_ROLE}"' == s for s in statements
        )

    def test_future_tables_inherit_the_split(self) -> None:
        """A table a later migration adds must not become writable."""
        defaults = [s for s in grant_statements() if "DEFAULT PRIVILEGES" in s]
        assert any(TENANT_ROLE in s and "SELECT" in s for s in defaults)
        assert any(ETL_ROLE in s and "ALL" in s for s in defaults)

    def test_a_tenant_schema_grants_write_to_the_tenant_role(self) -> None:
        statements = tenant_schema_grants("tenant_acme")
        assert any(
            'GRANT ALL ON ALL TABLES IN SCHEMA "tenant_acme"' in s and TENANT_ROLE in s
            for s in statements
        )


@pytest.fixture
def worker_engine(engine: Engine) -> Engine:
    """An engine connected as the tenant worker role.

    Skips where the connection cannot create roles, since that is a
    deployment's own privilege choice rather than a product defect.
    """
    try:
        apply_grants(engine=engine, create_roles=True)
        with engine.begin() as connection:
            connection.execute(
                text(f"ALTER ROLE \"{TENANT_ROLE}\" LOGIN PASSWORD '{WORKER_PASSWORD}'")
            )
    except ProgrammingError as exc:  # pragma: no cover - privilege dependent
        pytest.skip(f"cannot create roles on this database: {exc}")

    url = make_url(TEST_DSN).set(username=TENANT_ROLE, password=WORKER_PASSWORD)
    worker = create_engine(url)
    yield worker
    worker.dispose()


class TestIntelIsReadOnly:
    def test_a_tenant_worker_can_read_the_shared_intel(self, worker_engine: Engine) -> None:
        with worker_engine.connect() as connection:
            connection.execute(text("SELECT count(*) FROM intel.intel_record"))

    def test_a_tenant_worker_cannot_write_the_shared_intel(self, worker_engine: Engine) -> None:
        """Spec §11: read-only to tenant workers."""
        with (
            worker_engine.connect() as connection,
            pytest.raises(ProgrammingError, match="permission denied"),
        ):
            connection.exec_driver_sql(
                "INSERT INTO intel.intel_record "
                "(cve_id, exploit_status, cwe, as_of) "
                "VALUES ('CVE-2099-00001', 'active', '[]'::jsonb, now())"
            )

    def test_a_tenant_worker_cannot_delete_the_shared_intel(self, worker_engine: Engine) -> None:
        with (
            worker_engine.connect() as connection,
            pytest.raises(ProgrammingError, match="permission denied"),
        ):
            connection.exec_driver_sql("DELETE FROM intel.intel_record")

    def test_a_tenant_worker_cannot_change_the_registry(self, worker_engine: Engine) -> None:
        """Renaming itself into another tenant's schema is not available."""
        with (
            worker_engine.connect() as connection,
            pytest.raises(ProgrammingError, match="permission denied"),
        ):
            connection.exec_driver_sql("UPDATE control.tenant SET schema_name = 'tenant_other'")

    def test_a_tenant_worker_can_append_to_the_audit_log(self, worker_engine: Engine) -> None:
        """It must be able to record what it did (spec §11)."""
        with worker_engine.connect() as connection:
            connection.exec_driver_sql(
                "INSERT INTO control.audit_event "
                "(subject, action, outcome, detail) "
                "VALUES ('service:test', 'match_run', 'allowed', '{}'::jsonb)"
            )
            connection.commit()

    def test_a_tenant_worker_cannot_rewrite_the_audit_log(self, worker_engine: Engine) -> None:
        with (
            worker_engine.connect() as connection,
            pytest.raises(Exception, match=r"append-only|permission denied"),
        ):
            connection.exec_driver_sql("UPDATE control.audit_event SET subject = 'attacker'")
