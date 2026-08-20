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
#
# Cadence follows PRD §42. Intelligence is hourly because a newly published advisory
# should reach correlation in minutes, not on the next full patrol; EPSS is refreshed
# daily upstream so polling it more often is wasted traffic.
HOUR = 3600
DAY = 24 * HOUR

SCHEDULE: list[tuple[str, int, str, dict]] = [
    *[
        (f"intel-osv-{eco.lower()}", HOUR, "intel.poll.osv", {"ecosystem": eco})
        for eco in ("PyPI", "npm", "Go", "Debian", "Ubuntu", "Alpine")
    ],
    ("intel-kev", HOUR, "intel.poll.kev", {}),
    ("intel-epss", DAY, "intel.poll.epss", {}),
    # Re-correlate findings whose advisory has been revised since they were
    # evaluated, including ones previously closed: a corrected range can make a
    # dismissed finding real again.
    ("correlate-stale", HOUR, "correlate.stale", {}),
]

# Periodic work done directly by the scheduler rather than through the queue,
# because it is cheap and must not compete with scans for worker slots.
NODE_SWEEP_INTERVAL = 60
NONCE_SWEEP_INTERVAL = 300
CORRELATION_SWEEP_INTERVAL = 300
# Images change only when something is rebuilt or pulled, and each scan pulls the
# image, so this is deliberately unhurried.
IMAGE_SWEEP_INTERVAL = 600


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


def _sweep_correlation(session, last_run: dict[str, float], now: float) -> None:
    """Correlate assets whose inventory changed since they were last correlated.

    Without this, a freshly scanned host would carry no findings until the next
    advisory happened to arrive for one of its packages.
    """
    if now - last_run.get("correlate-assets", 0) < CORRELATION_SWEEP_INTERVAL:
        return
    last_run["correlate-assets"] = now

    from sqlalchemy import text

    from athena.queue import enqueue

    # Only assets that actually carry components are worth correlating. A host with
    # thousands of packages was being crowded out of the batch by hundreds of service
    # assets that have none, so the one asset with anything to match never ran.
    rows = session.execute(
        text(
            "SELECT a.id::text, extract(epoch FROM a.last_inventoried_at)::bigint AS stamp "
            "  FROM asset a "
            " WHERE a.tombstoned_at IS NULL "
            "   AND a.last_inventoried_at IS NOT NULL "
            "   AND EXISTS (SELECT 1 FROM asset_component ac WHERE ac.asset_id = a.id) "
            " ORDER BY a.last_inventoried_at DESC LIMIT 200"
        )
    ).all()
    for asset_id, stamp in rows:
        # Keyed on the inventory timestamp, so an unchanged asset is not re-correlated
        # on every sweep but a rescanned one always is.
        enqueue(
            session,
            kind="correlate.asset",
            key=f"{asset_id}:{stamp}",
            payload={"asset_id": asset_id},
            priority=5,
        )


def _sweep_images(session, last_run: dict[str, float], now: float) -> None:
    """Queue image scans for images not yet inventoried, or stale.

    Images are registered by the node's Docker inventory but carry no components
    until something scans them — until then they are correctly reported as unknown,
    which is honest but not useful.
    """
    if now - last_run.get("image-sweep", 0) < IMAGE_SWEEP_INTERVAL:
        return
    last_run["image-sweep"] = now

    from sqlalchemy import text

    from athena.queue import enqueue

    rows = session.execute(
        text(
            "SELECT id::text FROM asset "
            " WHERE kind = 'image' AND tombstoned_at IS NULL "
            "   AND (last_inventoried_at IS NULL "
            "        OR last_inventoried_at < now() - interval '7 days') "
            " ORDER BY last_inventoried_at NULLS FIRST LIMIT 20"
        )
    ).all()
    for (asset_id,) in rows:
        enqueue(
            session,
            kind="scan.image",
            key=asset_id,
            payload={"asset_id": asset_id},
            priority=6,
        )
    if rows:
        log.info("scheduler.image_scans", queued=len(rows))


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
                _sweep_correlation(session, last_run, now)
                _sweep_images(session, last_run, now)
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
