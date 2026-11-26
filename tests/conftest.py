"""Shared test fixtures.

Unit tests need no database.  Integration tests need a live PostgreSQL and
are skipped unless ``AEGIS_TEST_DSN`` points at one; the intel store relies on
PostgreSQL-specific features (JSONB, partial indexes, schemas) so faking it
with SQLite would test something the product does not run on.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from aegis.config import get_settings
from aegis.core.enums import FeedSource
from aegis.db.base import Base
from aegis.intel.schemas import FeedContribution, SourceRef

TEST_DSN = os.environ.get("AEGIS_TEST_DSN")

requires_db = pytest.mark.skipif(not TEST_DSN, reason="set AEGIS_TEST_DSN to run integration tests")


@pytest.fixture(scope="session")
def engine() -> Iterator[Engine]:
    if not TEST_DSN:
        pytest.skip("AEGIS_TEST_DSN is not set")

    engine = create_engine(TEST_DSN, future=True)
    schema = get_settings().intel_schema
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield engine
    Base.metadata.drop_all(engine)
    engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    """A session whose writes are rolled back after each test."""
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    # Truncate rather than nest transactions: the code under test commits.
    schema = get_settings().intel_schema
    tables = ", ".join(
        f'"{schema}"."{table.name}"' for table in reversed(Base.metadata.sorted_tables)
    )
    session.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    session.commit()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def make_contribution(
    cve_id: str = "CVE-2026-104286",
    source: FeedSource = FeedSource.CISA_KEV,
    *,
    retrieved_at: datetime | None = None,
    **fields: object,
) -> FeedContribution:
    """Build a valid contribution with sensible provenance."""
    payload: dict[str, object] = {
        "cve_id": cve_id,
        "source": source,
        "retrieved_at": retrieved_at or datetime(2026, 11, 26, 12, 0, tzinfo=UTC),
        "sources": [SourceRef(url=f"https://example.test/{source}")],
    }
    payload.update(fields)
    return FeedContribution(**payload)  # type: ignore[arg-type]
