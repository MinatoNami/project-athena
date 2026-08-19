from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from athena.config import get_settings

_engine: Engine | None = None
_factory: sessionmaker[Session] | None = None


class Base(DeclarativeBase):
    pass


def get_engine() -> Engine:
    global _engine, _factory
    if _engine is None:
        s = get_settings()
        _engine = create_engine(
            s.database_url,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            future=True,
        )
        _factory = sessionmaker(bind=_engine, expire_on_commit=False, future=True)
    return _engine


def _get_factory() -> sessionmaker[Session]:
    get_engine()
    assert _factory is not None
    return _factory


def new_session() -> Session:
    """An unmanaged session. The caller owns commit, rollback, and close."""
    return _get_factory()()


@contextmanager
def session_scope() -> Iterator[Session]:
    session = _get_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
