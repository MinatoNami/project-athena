"""Re-check live suppressions against the world as it is now.

Expiry needs no sweep — it is evaluated in the query, so an expired suppression
stops applying the moment it expires. Premise invalidation does need one, because it
is an event worth recording: the operator should be able to see that a decision was
overturned and why, rather than merely notice a finding reappearing and wonder
whether they imagined dismissing it.
"""

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
