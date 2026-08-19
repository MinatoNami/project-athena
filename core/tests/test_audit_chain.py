"""Audit trail integrity.

These require a real Postgres: the append-only guarantee is a database trigger, and
proving it on any other engine would prove nothing.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from athena.audit import record, verify_chain


def test_chain_verifies_after_appends(session):
    for i in range(5):
        record(session, actor="test", action="PROBE", subject=f"s:{i}", detail={"i": i})
    session.commit()

    result = verify_chain(session)
    assert result["intact"] is True
    assert result["checked"] >= 5


def test_update_is_rejected_by_the_database(session):
    event = record(session, actor="test", action="PROBE", subject="s", detail={})
    session.commit()

    with pytest.raises(DatabaseError):
        session.execute(
            text("UPDATE audit_event SET action = 'TAMPERED' WHERE seq = :s"), {"s": event.seq}
        )
        session.commit()
    session.rollback()


def test_delete_is_rejected_by_the_database(session):
    event = record(session, actor="test", action="PROBE", subject="s", detail={})
    session.commit()

    with pytest.raises(DatabaseError):
        session.execute(text("DELETE FROM audit_event WHERE seq = :s"), {"s": event.seq})
        session.commit()
    session.rollback()


def test_each_event_commits_to_its_predecessor(session):
    a = record(session, actor="test", action="A", subject="s", detail={})
    session.flush()
    b = record(session, actor="test", action="B", subject="s", detail={})
    session.commit()
    assert bytes(b.prev_hash) == bytes(a.hash)


def test_rejected_attempts_survive_the_rollback_that_follows_them(session, monkeypatch):
    """A failed login rolls back its request transaction. The audit record must not
    roll back with it — failures are the events most worth keeping."""
    from athena.audit import record_isolated

    before = verify_chain(session)["checked"]

    try:
        record_isolated(actor="anonymous", action="LOGIN_FAILED", subject="email:x@y.z", detail={})
        raise RuntimeError("the rejection that follows the audit write")
    except RuntimeError:
        pass

    session.rollback()
    after = verify_chain(session)
    assert after["checked"] == before + 1
    assert after["intact"] is True
