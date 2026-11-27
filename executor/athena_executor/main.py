from __future__ import annotations

import signal
import threading

import structlog

from athena_executor.config import ExecutorSettings
from athena_executor.grants import GrantVerifier

log = structlog.get_logger(__name__)
_stop = threading.Event()


def main() -> int:
    settings = ExecutorSettings()
    verifier = GrantVerifier(settings.grant_public_key)

    def handle(signum, _frame):
        log.info("executor.shutdown", signal=signum)
        _stop.set()

    signal.signal(signal.SIGTERM, handle)
    signal.signal(signal.SIGINT, handle)

    log.info(
        "executor.start",
        verifier_ready=verifier.ready,
        note="no execution capabilities registered until M5",
    )

    while not _stop.is_set():
        _stop.wait(5)

    log.info("executor.stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
