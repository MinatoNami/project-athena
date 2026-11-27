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

LOCK_ID = 0x4154_4845

HOUR = 3600
DAY = 24 * HOUR

SCHEDULE: list[tuple[str, int, str, dict]] = [
    *[
        (f"intel-osv-{eco.lower()}", HOUR, "intel.poll.osv", {"ecosystem": eco})
        for eco in ("PyPI", "npm", "Go", "Debian", "Ubuntu", "Alpine")
    ],
    ("intel-kev", HOUR, "intel.poll.kev", {}),
    ("intel-epss", DAY, "intel.poll.epss", {}),
    ("intel-vulnrichment", HOUR, "intel.enrich.vulnrichment", {}),
    ("correlate-stale", HOUR, "correlate.stale", {}),
    ("suppression-review", HOUR, "suppression.review", {}),
    ("notify-dispatch", 5 * 60, "notify.dispatch", {}),
]

NODE_SWEEP_INTERVAL = 60
NONCE_SWEEP_INTERVAL = 300
CORRELATION_SWEEP_INTERVAL = 300
IMAGE_SWEEP_INTERVAL = 600
TRIAGE_SWEEP_INTERVAL = 120


def _acquire_leadership(session) -> bool:
    return bool(session.execute(text("SELECT pg_try_advisory_lock(:id)"), {"id": LOCK_ID}).scalar())


def _sweep_nodes(session, last_run: dict[str, float], now: float) -> None:
    if now - last_run.get("node-sweep", 0) < NODE_SWEEP_INTERVAL:
        return
    last_run["node-sweep"] = now

    from athena.nodes.dispatch import enqueue_collection, nodes_due

    for node in nodes_due(session):
        created = enqueue_collection(session, node)
        if created:
            log.info("scheduler.node_collection", node=str(node.id), tasks=created)


def _sweep_correlation(session, last_run: dict[str, float], now: float) -> None:
    if now - last_run.get("correlate-assets", 0) < CORRELATION_SWEEP_INTERVAL:
        return
    last_run["correlate-assets"] = now

    from sqlalchemy import text

    from athena.queue import enqueue

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
        enqueue(
            session,
            kind="correlate.asset",
            key=f"{asset_id}:{stamp}",
            payload={"asset_id": asset_id},
            priority=5,
        )


def _sweep_triage(session, last_run: dict[str, float], now: float) -> None:
    if now - last_run.get("triage-sweep", 0) < TRIAGE_SWEEP_INTERVAL:
        return
    last_run["triage-sweep"] = now

    from sqlalchemy import text

    from athena.config import get_settings
    from athena.investigation.priority import decide
    from athena.llm.budget import current
    from athena.queue import enqueue

    budget = current(session)
    if budget.exhausted:
        log.warning("scheduler.ai_budget_exhausted", **budget.as_dict())
        return

    floor = get_settings().investigation_floor
    batch = min(get_settings().triage_batch, budget.remaining)

    rows = session.execute(
        text(
            """
            SELECT f.id::text, f.triage_disposition, v.severity, v.cvss_score,
                   v.epss_score, v.kev, v.malicious, a.tier, a.exposure
              FROM finding f
              JOIN vulnerability v ON v.id = f.vulnerability_id
              JOIN asset a ON a.id = f.asset_id
             WHERE f.state = 'discovered'
               AND f.investigation_id IS NULL
               -- Retracted reports are out of the list, so they are out of the
               -- budget too: a withdrawn malware record would otherwise sort first.
               AND v.withdrawn_at IS NULL
               -- Not until correlation has re-matched it against the advisory's
               -- current revision (`investigate.match_is_current`): queued now, the
               -- worker would only set it aside, on every pass until then.
               AND f.advisory_revision >= v.revision
               AND (f.triage_disposition IS NULL OR f.triage_disposition = 'investigate')
             ORDER BY v.malicious DESC,
                      v.kev DESC,
                      COALESCE(v.cvss_score, 0) DESC,
                      COALESCE(v.epss_score, 0) DESC,
                      f.first_seen
             LIMIT :scan
            """
        ),
        {"scan": max(batch * 20, 500)},
    ).all()

    queued = deferred = 0
    for row in rows:
        if queued >= batch:
            break
        facts = {
            "advisory": {
                "severity": row.severity, "cvss": row.cvss_score,
                "epss": row.epss_score, "known_exploited": row.kev,
                "malicious": row.malicious,
            },
            "asset": {"tier": row.tier, "exposure": row.exposure},
        }
        if not decide(facts, floor=floor).investigate:
            deferred += 1
            continue
        kind = "triage.finding" if row.triage_disposition is None else "investigate.finding"
        enqueue(
            session, kind=kind, key=row[0],
            payload={"finding_id": row[0]}, priority=6 if kind == "triage.finding" else 5,
        )
        queued += 1

    if queued or deferred:
        log.info(
            "scheduler.triage_queued", count=queued, deferred_below_floor=deferred,
            floor=floor, budget_remaining=budget.remaining,
        )


def _sweep_images(session, last_run: dict[str, float], now: float) -> None:
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
                _sweep_triage(session, last_run, now)
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
