"""Built-in job handlers.

M0 ships only what the foundations checkpoint exercises. Real handlers arrive with
their milestones (scan.* in M1, correlate.* in M2, investigate.* in M3).
"""

from __future__ import annotations

import time
from typing import Any

from athena.queue.registry import handler


@handler("system.echo")
def echo(payload: dict[str, Any]) -> dict[str, Any]:
    """Round-trip probe used by the M0 checkpoint and by `athena doctor`."""
    return {"echo": payload}


@handler("system.sleep")
def sleep(payload: dict[str, Any]) -> dict[str, Any]:
    seconds = min(float(payload.get("seconds", 0.1)), 30.0)
    time.sleep(seconds)
    return {"slept": seconds}


@handler("system.fail")
def fail(payload: dict[str, Any]) -> dict[str, Any]:
    """Deliberate failure, for exercising retry and backoff."""
    raise RuntimeError(payload.get("message", "deliberate failure"))
