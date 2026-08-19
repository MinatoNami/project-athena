from __future__ import annotations

import logging
import sys

import structlog

REDACT_KEYS = {"password", "token", "secret", "key", "authorization", "cookie"}


def _redact(_logger, _method, event_dict: dict) -> dict:
    """Defence in depth: a secret must never reach the log even if one is passed."""
    for k in list(event_dict):
        if any(marker in k.lower() for marker in REDACT_KEYS):
            event_dict[k] = "<redacted>"
    return event_dict


def configure(level: str = "INFO") -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _redact,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )
