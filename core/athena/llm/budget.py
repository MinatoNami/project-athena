"""Spend limits for the AI layer.

A local model has no invoice, but it does have wall-clock: an unbounded sweep can
occupy the machine indefinitely and starve everything else. The limit is on model
calls rather than tokens, because that is what the operator can reason about.

On exhaustion work is *queued*, never silently dropped. "We stopped looking" and
"there was nothing to find" must never be the same state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.config import get_settings
from athena.db.models import EgressLog

log = structlog.get_logger(__name__)


class BudgetExhausted(RuntimeError):
    """The call was refused to protect the machine, not because anything failed.

    Deliberately not ModelUnavailable: the model is fine and we chose not to ask it.
    Reporting a self-imposed limit as an outage would send somebody to debug a
    healthy endpoint.
    """


@dataclass
class Budget:
    spent: int
    limit: int
    window_hours: int

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.spent)

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0

    def as_dict(self) -> dict:
        return {
            "spent": self.spent,
            "limit": self.limit,
            "remaining": self.remaining,
            "window_hours": self.window_hours,
            "exhausted": self.exhausted,
        }


def current(session: Session) -> Budget:
    """Model calls made in the rolling window."""
    settings = get_settings()
    window = settings.ai_budget_window_hours
    since = datetime.now(UTC) - timedelta(hours=window)

    spent = session.execute(
        select(func.count())
        .select_from(EgressLog)
        .where(EgressLog.at >= since, EgressLog.blocked.is_(False))
    ).scalar_one()

    return Budget(spent=spent, limit=settings.ai_budget_calls, window_hours=window)


def check(session: Session, *, purpose: str) -> Budget:
    """Raise if the window is spent.

    Called on every model call rather than once per sweep. A limit enforced only
    where work is scheduled binds only the scheduler: anything calling the gateway
    directly — a script, a harness, a future feature — spends freely past it, which
    is how a 2,000-call ceiling came to sit under 6,500 calls.
    """
    budget = current(session)
    if budget.exhausted:
        log.warning("llm.budget_exhausted", purpose=purpose, **budget.as_dict())
        raise BudgetExhausted(
            f"{budget.spent} model calls in the last {budget.window_hours}h exceeds "
            f"the {budget.limit} allowed. Work is queued, not dropped; it resumes as "
            "the window rolls forward."
        )
    return budget
