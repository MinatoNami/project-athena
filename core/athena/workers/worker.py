from __future__ import annotations

import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import structlog

from athena.audit import record
from athena.config import get_settings
from athena.db.base import session_scope
from athena.queue import (
    claim,
    finish,
    get_handler,
    handlers,  # noqa: F401
    publish,
)
from athena.workers import (
    image,  # noqa: F401
    intel_jobs,  # noqa: F401
    investigate,  # noqa: F401
    node_ingest,  # noqa: F401
    notify_jobs,  # noqa: F401
    repository,  # noqa: F401
    rescore,  # noqa: F401
    suppression_jobs,  # noqa: F401
)

log = structlog.get_logger(__name__)
_stop = threading.Event()


def _install_signal_handlers() -> None:
    def handle(signum, _frame):
        log.info("shutdown.signal", signal=signum)
        _stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)


def _run_one() -> bool:
    from athena.db.models import Job

    with session_scope() as session:
        job = claim(session)
        if job is None:
            return False
        job_id, kind, payload = job.id, job.kind, dict(job.payload)

    log.info("job.start", job_id=job_id, kind=kind)
    started = time.monotonic()

    try:
        result = get_handler(kind)(payload)
    except Exception as exc:  # noqa: BLE001
        with session_scope() as session:
            j = session.get(Job, job_id)
            if j is not None:
                finish(session, j, succeeded=False, error=f"{type(exc).__name__}: {exc}")
                record(
                    session,
                    actor="system:worker",
                    action="JOB_FAILED",
                    subject=f"job:{job_id}",
                    detail={"kind": kind, "error": str(exc), "attempt": j.attempts},
                )
                publish(session, topic="jobs", subject_id=str(job_id))
        log.warning("job.failed", job_id=job_id, kind=kind, error=str(exc))
        return True

    with session_scope() as session:
        j = session.get(Job, job_id)
        if j is not None:
            finish(session, j, succeeded=True, result=result)
            publish(session, topic="jobs", subject_id=str(job_id))
    log.info("job.done", job_id=job_id, kind=kind, ms=round((time.monotonic() - started) * 1000))
    return True


def run() -> None:
    settings = get_settings()
    _install_signal_handlers()
    log.info("worker.start", concurrency=settings.worker_concurrency)

    def loop() -> None:
        while not _stop.is_set():
            try:
                if not _run_one():
                    _stop.wait(settings.poll_interval_seconds)
            except Exception as exc:  # noqa: BLE001
                log.error("worker.loop_error", error=str(exc))
                _stop.wait(settings.poll_interval_seconds)

    with ThreadPoolExecutor(max_workers=settings.worker_concurrency) as pool:
        for _ in range(settings.worker_concurrency):
            pool.submit(loop)
        while not _stop.is_set():
            time.sleep(0.2)
    log.info("worker.stopped")
