from __future__ import annotations

from typing import Any

import structlog

from athena.db.base import session_scope
from athena.queue.registry import handler
from athena.suppression import review_suppressions

log = structlog.get_logger(__name__)


@handler("suppression.review")
def review(payload: dict[str, Any]) -> dict[str, Any]:
    with session_scope() as session:
        outcome = review_suppressions(session)
    log.info("suppression.reviewed", **outcome)
    return outcome
