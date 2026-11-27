from __future__ import annotations

import time
from typing import Any

from athena.queue.registry import handler


@handler("system.echo")
def echo(payload: dict[str, Any]) -> dict[str, Any]:
    return {"echo": payload}


@handler("system.sleep")
def sleep(payload: dict[str, Any]) -> dict[str, Any]:
    seconds = min(float(payload.get("seconds", 0.1)), 30.0)
    time.sleep(seconds)
    return {"slept": seconds}


@handler("system.fail")
def fail(payload: dict[str, Any]) -> dict[str, Any]:
    raise RuntimeError(payload.get("message", "deliberate failure"))
