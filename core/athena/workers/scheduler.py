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

# (name, interval seconds, job kind, payload)
SCHEDULE: list[tuple[str, int, str, dict]] = []

# Periodic work done directly by the scheduler rather than through the queue,
# because it is cheap and must not compete with scans for worker slots.
NODE_SWEEP_INTERVAL = 60
NONCE_SWEEP_INTERVAL = 300


def _acquire_leadership(session) -> bool:
    return bool(session.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": LOCK_ID}).scalar())


def _sweep_nodes(session, last_run: dict[str, float], now: float) -> None:
    """Issue collection work to nodes that are due for it."""
    if now - last_run.get("node-sweep", 0) < NODE_SWEEP_INTERVAL:
        return
    last_run["node-sweep"] = now

    from athena.nodes.dispatch import enqueue_collection, nodes_due

    for node in nodes_due(session):
        created = enqueue_collection(session, node)
        if created:
            log.info("scheduler.node_collection", node=str(node.id), tasks=created)


def _sweep_nonces(session, last_run: dict[str, float], now: float) -> None:
    """Drop replay nonces that can no longer be replayed."""
    if now - last_run.get("nonce-sweep", 0) < NONCE_SWEEP_INTERVAL:
        return
    last_run["nonce-sweep"] = now

    from athena.api.routers.nodes import sweep_nonces

    removed = sweep_nonces(session)
    if removed:
        log.info("scheduler.nonces_swept", removed=removed)


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
                _sweep_nodes(session, last_run, now)
                _sweep_nonces(session, last_run, now)
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
