"""AI spend limits.

A local model has no invoice, but an unbounded sweep can occupy the machine
indefinitely. The limit exists so unattended work has a ceiling.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

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


# ── enforcement at the gateway ───────────────────────────────────────────────


def _spend(session, n: int, *, blocked: bool = False, purpose: str = "investigation"):
    """Record n egress rows in the window."""
    from athena.db.models import EgressLog

    for _ in range(n):
        session.add(EgressLog(
            purpose=purpose, endpoint="http://local:1234", model="m", local=True,
            data_classes=[], blocked=blocked, payload_hash="h", bytes_out=1,
            prompt_tokens=1, completion_tokens=1, duration_ms=1,
        ))
    session.flush()


def test_check_passes_while_there_is_room(session, monkeypatch):
    from athena.config import get_settings
    from athena.llm.budget import check

    monkeypatch.setattr(get_settings(), "ai_budget_calls", 500, raising=False)
    _spend(session, 3)
    assert check(session, purpose="investigation").remaining > 0


def test_check_refuses_once_the_window_is_spent(session, monkeypatch):
    from athena.config import get_settings
    from athena.llm.budget import BudgetExhausted, check

    monkeypatch.setattr(get_settings(), "ai_budget_calls", 5, raising=False)
    _spend(session, 6)
    with pytest.raises(BudgetExhausted, match="queued, not dropped"):
        check(session, purpose="investigation")


def test_a_refusal_is_not_an_outage(session, monkeypatch):
    """BudgetExhausted must not be a ModelUnavailable: the endpoint is healthy and
    we declined to use it. Reporting a self-imposed limit as an outage sends
    somebody to debug something that is working."""
    from athena.llm import BudgetExhausted, ModelUnavailable

    assert not issubclass(BudgetExhausted, ModelUnavailable)


def test_refusals_cannot_inflate_the_window_they_enforce(session, monkeypatch):
    """A refused call is logged as blocked, and blocked rows are not counted.

    Were they counted, the first refusal would push the window further past the
    limit, and the budget would never recover no matter how long you waited.
    """
    from athena.config import get_settings
    from athena.llm.budget import current

    monkeypatch.setattr(get_settings(), "ai_budget_calls", 5, raising=False)
    _spend(session, 4)
    before = current(session).spent
    _spend(session, 50, blocked=True)
    assert current(session).spent == before


def test_triage_is_gated_by_the_same_budget(session, monkeypatch):
    """Triage is a model call like any other, and an ungated cheap call is still a
    call that occupies the machine."""
    from athena.config import get_settings
    from athena.llm.budget import BudgetExhausted, check

    monkeypatch.setattr(get_settings(), "ai_budget_calls", 2, raising=False)
    _spend(session, 3, purpose="triage")
    with pytest.raises(BudgetExhausted):
        check(session, purpose="triage")
