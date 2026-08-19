from __future__ import annotations

import os
from urllib.parse import unquote, urlsplit

import pytest

INTEGRATION_DSN = os.environ.get("ATHENA_TEST_DB_URL")

# Some code under test (notably `record_isolated`) opens its own session through the
# normal settings rather than the fixture's engine. Point those settings at the same
# database, so the tests exercise the real code path instead of a rigged one.
if INTEGRATION_DSN:
    parts = urlsplit(INTEGRATION_DSN)
    os.environ.setdefault("ATHENA_DB_HOST", parts.hostname or "localhost")
    os.environ.setdefault("ATHENA_DB_PORT", str(parts.port or 5432))
    os.environ.setdefault("ATHENA_DB_NAME", parts.path.lstrip("/") or "athena")
    os.environ.setdefault("ATHENA_DB_USER", unquote(parts.username or "athena"))
    os.environ.setdefault("ATHENA_DB_PASSWORD", unquote(parts.password or ""))


@pytest.fixture(scope="session")
def engine():
    """A real Postgres engine, or skip.

    These tests assert database-enforced behaviour — the append-only trigger, SKIP
    LOCKED semantics — so proving them on a SQLite substitute would prove nothing.
    """
    if not INTEGRATION_DSN:
        pytest.skip("ATHENA_TEST_DB_URL not set; skipping integration tests")

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", INTEGRATION_DSN)
    command.upgrade(cfg, "head")

    return create_engine(INTEGRATION_DSN, future=True)


@pytest.fixture
def session(engine):
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    s = factory()
    try:
        yield s
        s.rollback()
    finally:
        s.close()
