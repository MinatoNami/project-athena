"""AI spend limits.

A local model has no invoice, but an unbounded sweep can occupy the machine
indefinitely. The limit exists so unattended work has a ceiling.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from athena.config import get_settings
from athena.db.models import EgressLog
from athena.llm.budget import current


def _call(session, *, hours_ago: float = 0, blocked: bool = False) -> None:
    session.add(
        EgressLog(
            at=datetime.now(UTC) - timedelta(hours=hours_ago),
            purpose="investigation", endpoint="http://127.0.0.1:1234",
            model="test", local=True, data_classes=["package_metadata"],
            blocked=blocked, payload_hash="x", bytes_out=1,
        )
    )


def test_an_empty_window_has_the_full_budget(session):
    budget = current(session)
    assert budget.remaining == budget.limit
    assert budget.exhausted is False


def test_calls_inside_the_window_are_counted(session):
    before = current(session).spent
    for _ in range(3):
        _call(session)
    session.flush()
    assert current(session).spent == before + 3


def test_calls_outside_the_window_are_not_counted(session):
    before = current(session).spent
    _call(session, hours_ago=get_settings().ai_budget_window_hours + 1)
    session.flush()
    assert current(session).spent == before


def test_blocked_calls_do_not_consume_budget(session):
    """A refused payload never reached the model, so it cost nothing."""
    before = current(session).spent
    _call(session, blocked=True)
    session.flush()
    assert current(session).spent == before


def test_exhaustion_is_reported_not_inferred(session, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "ai_budget_calls", 1, raising=False)
    for _ in range(2):
        _call(session)
    session.flush()

    budget = current(session)
    assert budget.exhausted is True
    assert budget.remaining == 0
    # The sweep logs this rather than stopping quietly: "we stopped looking" and
    # "there was nothing to find" must not look the same.
    assert budget.as_dict()["exhausted"] is True
