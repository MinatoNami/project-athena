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

    _ensure_database_exists(INTEGRATION_DSN)

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", INTEGRATION_DSN)

    # Rebuild the schema so the suite starts from a known state. Tests that exercise
    # committed behaviour — retry bookkeeping, coverage arithmetic — would otherwise
    # drift as state accumulated across runs. Truncation is not an option: audit_event
    # rejects it by design.
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")

    return create_engine(INTEGRATION_DSN, future=True)


def _ensure_database_exists(dsn: str) -> None:
    """Create the test database if it is missing.

    Losing it is easy — wiping the compose volume for a clean install takes it with
    the rest — and a missing database should not look like 17 broken tests.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import OperationalError

    target = urlsplit(dsn).path.lstrip("/")
    try:
        create_engine(dsn).connect().close()
        return
    except OperationalError as exc:
        if "does not exist" not in str(exc):
            raise

    admin = create_engine(
        dsn.rsplit("/", 1)[0] + "/postgres", isolation_level="AUTOCOMMIT", future=True
    )
    with admin.connect() as conn:
        # Identifier, so it cannot be bound as a parameter. The name comes from the
        # operator's own DSN, never from user input.
        conn.execute(text(f'CREATE DATABASE "{target}"'))
    admin.dispose()


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
