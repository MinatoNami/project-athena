"""Send what should go now, hold the rest for the digest.

A job rather than a call at emit time: whether something sends depends on what else
has already gone out this hour, which is a question about the whole queue and not
about the event that just happened.
"""

from __future__ import annotations

from typing import Any

import structlog

from athena.db.base import session_scope
from athena.notify import dispatch
from athena.queue.registry import handler

log = structlog.get_logger(__name__)


@handler("notify.dispatch")
def dispatch_notifications(payload: dict[str, Any]) -> dict[str, Any]:
    with session_scope() as session:
        return dispatch(session)
