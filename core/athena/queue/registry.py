"""Job handler registry.

A job kind with no registered handler is a hard error, not a silent no-op.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Handler = Callable[[dict[str, Any]], dict[str, Any] | None]

_HANDLERS: dict[str, Handler] = {}


def handler(kind: str) -> Callable[[Handler], Handler]:
    def register(fn: Handler) -> Handler:
        if kind in _HANDLERS:
            raise RuntimeError(f"Duplicate handler for job kind {kind!r}")
        _HANDLERS[kind] = fn
        return fn

    return register


def get_handler(kind: str) -> Handler:
    try:
        return _HANDLERS[kind]
    except KeyError:
        raise LookupError(f"No handler registered for job kind {kind!r}") from None


def known_kinds() -> list[str]:
    return sorted(_HANDLERS)
