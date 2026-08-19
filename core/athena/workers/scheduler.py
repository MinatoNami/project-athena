"""Periodic work.

Leader-elected through a Postgres advisory lock, so running two scheduler containers
is safe — the second waits rather than double-scheduling.
"""

from __future__ import annotations

import signal
import threading
import time
from datetime import UTC, datetime

import structlog
from sqlalchemy import text

from athena.db.base import session_scope

log = structlog.get_logger(__name__)
_stop = threading.Event()

LOCK_ID = 0x4154_4845  # "ATHE"

# (name, interval seconds, job kind, payload) — real patrol cadence arrives in M1.
SCHEDULE: list[tuple[str, int, str, dict]] = [
    ("session-sweep", 300, "system.echo", {"task": "session-sweep"}),
]


def _acquire_leadership(session) -> bool:
    return bool(session.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": LOCK_ID}).scalar())


def run() -> None:
    def handle(signum, _frame):
        log.info("shutdown.signal", signal=signum)
        _stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)

    log.info("scheduler.start")
    last_run: dict[str, float] = {}

    while not _stop.is_set():
        try:
            with session_scope() as session:
                if not _acquire_leadership(session):
                    log.debug("scheduler.not_leader")
                    _stop.wait(10)
                    continue

                from athena.queue import enqueue

                now = time.monotonic()
                for name, interval, kind, payload in SCHEDULE:
                    if now - last_run.get(name, 0) < interval:
                        continue
                    last_run[name] = now
                    bucket = int(datetime.now(UTC).timestamp() // interval)
                    enqueue(session, kind=kind, key=f"{name}:{bucket}", payload=payload)
                    log.info("scheduler.enqueued", task=name)
        except Exception as exc:  # noqa: BLE001
            log.error("scheduler.error", error=str(exc))
        _stop.wait(5)

    log.info("scheduler.stopped")
