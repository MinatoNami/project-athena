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
    pass


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
    budget = current(session)
    if budget.exhausted:
        log.warning("llm.budget_exhausted", purpose=purpose, **budget.as_dict())
        raise BudgetExhausted(
            f"{budget.spent} model calls in the last {budget.window_hours}h exceeds "
            f"the {budget.limit} allowed. Work is queued, not dropped; it resumes as "
            "the window rolls forward."
        )
    return budget
