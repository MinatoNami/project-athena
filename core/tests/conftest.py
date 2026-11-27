from __future__ import annotations

import os
from urllib.parse import unquote, urlsplit

import pytest

INTEGRATION_DSN = os.environ.get("ATHENA_TEST_DB_URL")

if INTEGRATION_DSN:
    parts = urlsplit(INTEGRATION_DSN)
    os.environ.setdefault("ATHENA_DB_HOST", parts.hostname or "localhost")
    os.environ.setdefault("ATHENA_DB_PORT", str(parts.port or 5432))
    os.environ.setdefault("ATHENA_DB_NAME", parts.path.lstrip("/") or "athena")
    os.environ.setdefault("ATHENA_DB_USER", unquote(parts.username or "athena"))
    os.environ.setdefault("ATHENA_DB_PASSWORD", unquote(parts.password or ""))


@pytest.fixture(scope="session")
def engine():
    if not INTEGRATION_DSN:
        pytest.skip("ATHENA_TEST_DB_URL not set; skipping integration tests")

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine

    _ensure_database_exists(INTEGRATION_DSN)

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", INTEGRATION_DSN)

    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")

    return create_engine(INTEGRATION_DSN, future=True)


def _ensure_database_exists(dsn: str) -> None:
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
