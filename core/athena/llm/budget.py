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
